// write.go — Mach-O MH_OBJECT serialisation.
//
// Symbol table ordering required by the static linker:
//   [0]          mandatory null symbol
//   [1..nSec]    one anonymous N_SECT (local) section-symbol per section
//   [nSec+1..]   BindingLocal symbols from s.Symbols, in section order
//   [..]         BindingGlobal / BindingWeak symbols from s.Symbols
//   [last..]     N_UNDF/N_EXT undefined-external symbols for unresolved reloc targets
//
// r_extern / r_symbolnum encoding:
//   BindingLocal target         → r_extern=0, r_symbolnum = 1-based section index
//   BindingGlobal/Weak target   → r_extern=1, r_symbolnum = nlist index
//   undefined target            → r_extern=1, r_symbolnum = nlist index
//
// Implicit-addend convention:
//   Reloc.Addend is written into Code[r.Offset:] (little-endian, 4 or 8 bytes)
//   before the section bytes are emitted.  The relocation record carries zero.
package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/vertex-language/objectfile/object"
)

// ── Structure sizes ───────────────────────────────────────────────────────────

const (
	mhSize64        = 32 // sizeof(mach_header_64)
	segCmdSize64    = 72 // sizeof(segment_command_64)
	sectionSize64   = 80 // sizeof(section_64)
	symtabCmdSize   = 24 // sizeof(symtab_command)
	buildVerCmdSize = 24 // sizeof(build_version_command) with ntools=0
	nlistSize64     = 16 // sizeof(nlist_64)
	relocSize       = 8  // sizeof(relocation_info)
)

// ── Load command identifiers ──────────────────────────────────────────────────

const (
	lcSegment64    uint32 = 0x19 // LC_SEGMENT_64
	lcSymtab       uint32 = 0x2  // LC_SYMTAB
	lcBuildVersion uint32 = 0x32 // LC_BUILD_VERSION
)

// ── VM protection ─────────────────────────────────────────────────────────────

const (
	vmProtNone    int32 = 0x0
	vmProtRead    int32 = 0x1
	vmProtWrite   int32 = 0x2
	vmProtExecute int32 = 0x4
)

// ── Section flags ─────────────────────────────────────────────────────────────

const (
	sAttrPureInstructions uint32 = 0x80000000
	sAttrSomeInstructions uint32 = 0x00000400
	sTypeRegular          uint32 = 0x0
	sTypeZerofill         uint32 = 0x1
)

// ── nlist_64 type / binding bits ──────────────────────────────────────────────

const (
	nUndf uint8 = 0x00 // N_UNDF: undefined
	nSect uint8 = 0x0E // N_SECT: defined in a section
	nExt  uint8 = 0x01 // N_EXT: external (global) bit
)

// nlist_64 n_desc flags
const (
	nWeakDef uint16 = 0x0080 // N_WEAK_DEF: weak definition (FlagLinkOnce / BindingWeak)
)

const noSect uint8 = 0 // NO_SECT

// ── Binary structures ─────────────────────────────────────────────────────────

type machHeader64 struct {
	Magic      uint32
	CPUType    int32
	CPUSubtype int32
	FileType   uint32
	NCmds      uint32
	SizeOfCmds uint32
	Flags      uint32
	Reserved   uint32
}

type segmentCommand64 struct {
	Cmd      uint32
	CmdSize  uint32
	SegName  [16]byte
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  int32
	InitProt int32
	NSects   uint32
	Flags    uint32
}

type section64 struct {
	SectName  [16]byte
	SegName   [16]byte
	Addr      uint64
	Size      uint64
	Offset    uint32 // file offset; 0 for zerofill
	Align     uint32 // log2 of byte alignment
	RelOff    uint32 // file offset of relocation entries; 0 if none
	NReloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

type symtabCommand struct {
	Cmd     uint32
	CmdSize uint32
	SymOff  uint32
	NSyms   uint32
	StrOff  uint32
	StrSize uint32
}

type buildVersionCommand struct {
	Cmd      uint32
	CmdSize  uint32
	Platform uint32
	MinOS    uint32
	SDK      uint32
	NTools   uint32
}

type nlist64 struct {
	NStrx  uint32
	NType  uint8
	NSect  uint8
	NDesc  uint16
	NValue uint64
}

// relocInfo mirrors relocation_info.  The r_symbolnum/r_pcrel/r_length/
// r_extern/r_type bitfields are packed into RInfo (little-endian).
type relocInfo struct {
	RAddress uint32
	RInfo    uint32
}

// ── relocInfo packing ─────────────────────────────────────────────────────────

func packRelocInfo(symbolNum uint32, pcrel bool, length uint8, extern bool, rtype uint8) uint32 {
	var v uint32
	v |= symbolNum & 0x00FFFFFF
	if pcrel {
		v |= 1 << 24
	}
	v |= uint32(length&0x3) << 25
	if extern {
		v |= 1 << 27
	}
	v |= uint32(rtype&0xF) << 28
	return v
}

// ── Relocation type constants ─────────────────────────────────────────────────

// x86-64 Mach-O relocation types (r_type, 4 bits).
const (
	x86_64RelocUnsigned uint8 = 0 // X86_64_RELOC_UNSIGNED  — absolute 64-bit
	x86_64RelocSigned   uint8 = 1 // X86_64_RELOC_SIGNED    — 32-bit PC-relative (generic)
	x86_64RelocBranch   uint8 = 2 // X86_64_RELOC_BRANCH    — 32-bit PC-relative CALL/JMP
	x86_64RelocGOTLoad  uint8 = 3 // X86_64_RELOC_GOT_LOAD  — MOVQ load of GOT entry
	x86_64RelocGOT      uint8 = 4 // X86_64_RELOC_GOT       — other GOT reference
	x86_64RelocTLV      uint8 = 9 // X86_64_RELOC_TLV       — TLV descriptor access
)

// ARM64 Mach-O relocation types.
const (
	arm64RelocUnsigned          uint8 = 0 // ARM64_RELOC_UNSIGNED
	arm64RelocSubtractor        uint8 = 1 // ARM64_RELOC_SUBTRACTOR
	arm64RelocBranch26          uint8 = 2 // ARM64_RELOC_BRANCH26        — BL/B
	arm64RelocPage21            uint8 = 3 // ARM64_RELOC_PAGE21          — ADRP
	arm64RelocPageoff12         uint8 = 4 // ARM64_RELOC_PAGEOFF12       — ADD/LDR page offset
	arm64RelocGOTLoadPage21     uint8 = 5 // ARM64_RELOC_GOT_LOAD_PAGE21
	arm64RelocGOTLoadPageoff12  uint8 = 6 // ARM64_RELOC_GOT_LOAD_PAGEOFF12
	arm64RelocTLVPLoadPage21    uint8 = 7 // ARM64_RELOC_TLVP_LOAD_PAGE21
	arm64RelocTLVPLoadPageoff12 uint8 = 8 // ARM64_RELOC_TLVP_LOAD_PAGEOFF12
)

// r_length: log2 of the byte width of the relocated field.
//
//	0 → 1 byte, 1 → 2 bytes, 2 → 4 bytes, 3 → 8 bytes
const (
	rLength1 uint8 = 0
	rLength2 uint8 = 1
	rLength4 uint8 = 2
	rLength8 uint8 = 3
)

// ── Alignment helpers ─────────────────────────────────────────────────────────

func alignUp(v, a uint32) uint32 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func padTo(buf *bytes.Buffer, target uint32) {
	for uint32(buf.Len()) < target {
		buf.WriteByte(0)
	}
}

// ── Relocation kind → Mach-O descriptor ──────────────────────────────────────

type relocDesc struct {
	rtype  uint8
	length uint8 // r_length (log2 of byte width)
	pcrel  bool
}

func (f *File) relocDesc(k object.RelocKind) (relocDesc, error) {
	switch f.cpuType {
	case cpuTypeX86_64:
		switch k {
		case object.RelocAbs64:
			return relocDesc{x86_64RelocUnsigned, rLength8, false}, nil
		case object.RelocPCRel32:
			return relocDesc{x86_64RelocBranch, rLength4, true}, nil
		case object.RelocGOTLoad:
			return relocDesc{x86_64RelocGOTLoad, rLength4, true}, nil
		case object.RelocTLSGD:
			return relocDesc{x86_64RelocTLV, rLength4, true}, nil
		}
	case cpuTypeARM64:
		switch k {
		case object.RelocAbs64:
			return relocDesc{arm64RelocUnsigned, rLength8, false}, nil
		case object.RelocPCRel26:
			return relocDesc{arm64RelocBranch26, rLength4, true}, nil
		case object.RelocADRPage21:
			return relocDesc{arm64RelocPage21, rLength4, true}, nil
		case object.RelocAddOff12:
			return relocDesc{arm64RelocPageoff12, rLength4, false}, nil
		case object.RelocGOTPage21:
			return relocDesc{arm64RelocGOTLoadPage21, rLength4, true}, nil
		case object.RelocGOTOff12:
			return relocDesc{arm64RelocGOTLoadPageoff12, rLength4, false}, nil
		case object.RelocTLSGD:
			return relocDesc{arm64RelocTLVPLoadPage21, rLength4, true}, nil
		}
	}
	return relocDesc{}, fmt.Errorf("macho: unsupported relocation kind %v for cpu_type 0x%08X",
		k, uint32(f.cpuType))
}

// ── Implicit-addend patching ──────────────────────────────────────────────────

// addendSize returns the byte width of the implicit addend field.
func addendSize(rd relocDesc) int {
	if rd.length == rLength8 {
		return 8
	}
	return 4
}

// applyImplicitAddends returns a copy of code with each relocation's addend
// written into the appropriate bytes at r.Offset (little-endian).
func applyImplicitAddends(code []byte, relocs []object.Reloc, descs []relocDesc) []byte {
    if len(relocs) == 0 {
        return code
    }
    patched := make([]byte, len(code))
    copy(patched, code)
    le := binary.LittleEndian
    for i, r := range relocs {
        if r.Addend == 0 {
            continue // instruction bytes are already the correct placeholder
        }
        sz := addendSize(descs[i])
        end := int(r.Offset) + sz
        if end > len(patched) {
            continue
        }
        switch sz {
        case 8:
            le.PutUint64(patched[r.Offset:], uint64(r.Addend))
        default:
            le.PutUint32(patched[r.Offset:], uint32(int32(r.Addend)))
        }
    }
    return patched
}

// ── External symbol discovery ─────────────────────────────────────────────────

// externalSymbols returns a sorted list of symbol names that are referenced
// by relocations but not defined in any section's Symbols slice.
func externalSymbols(sections []object.Section) []string {
	defined := make(map[string]bool)
	for _, s := range sections {
		for _, sym := range s.Symbols {
			if sym.Name != "" {
				defined[sym.Name] = true
			}
		}
	}
	seen := make(map[string]bool)
	for _, s := range sections {
		for _, r := range s.Relocs {
			if r.Symbol != "" && !defined[r.Symbol] {
				seen[r.Symbol] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ── Section metadata ──────────────────────────────────────────────────────────

type secMeta struct {
	segName    string
	sectName   string
	flags      uint32
	align      uint32 // alignment in bytes (value, not log2)
	rawSize    uint32 // bytes of content in the file (0 for zerofill)
	bssSize    uint64 // virtual zero-fill byte count (zerofill sections only)
	isZerofill bool
}

// sectionMeta computes the Mach-O section descriptor for section i.
func sectionMeta(i int, s object.Section) (secMeta, error) {
	// ea returns s.Align when set, otherwise the format default.
	ea := func(dflt uint32) uint32 {
		if s.Align > 0 {
			return s.Align
		}
		return dflt
	}

	// zerofillSize picks VSize when non-zero, else falls back to len(Code).
	zerofillSize := func() uint64 {
		if s.VSize > 0 {
			return s.VSize
		}
		return uint64(len(s.Code))
	}

	switch s.Kind {
	case object.SectionText:
		return secMeta{
			segName:  "__TEXT",
			sectName: "__text",
			flags:    sAttrPureInstructions | sAttrSomeInstructions,
			align:    ea(16),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionData:
		return secMeta{
			segName:  "__DATA",
			sectName: "__data",
			flags:    sTypeRegular,
			align:    ea(8),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionROData:
		return secMeta{
			segName:  "__TEXT",
			sectName: "__const",
			flags:    sTypeRegular,
			align:    ea(8),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionBSS:
		return secMeta{
			segName:    "__DATA",
			sectName:   "__bss",
			flags:      sTypeZerofill,
			align:      ea(8),
			bssSize:    zerofillSize(),
			isZerofill: true,
		}, nil

	case object.SectionUnwind:
		// Compact unwind records.  Callers that also need __eh_frame should
		// supply a SectionCustom("__TEXT,__eh_frame") section separately.
		return secMeta{
			segName:  "__TEXT",
			sectName: "__unwind_info",
			flags:    sTypeRegular,
			align:    ea(4),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionInitArray:
		return secMeta{
			segName:  "__DATA",
			sectName: "__mod_init_func",
			flags:    sTypeRegular,
			align:    ea(8),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionFiniArray:
		return secMeta{
			segName:  "__DATA",
			sectName: "__mod_term_func",
			flags:    sTypeRegular,
			align:    ea(8),
			rawSize:  uint32(len(s.Code)),
		}, nil

	case object.SectionTLS:
		if len(s.Code) > 0 {
			return secMeta{
				segName:  "__DATA",
				sectName: "__thread_data",
				flags:    sTypeRegular,
				align:    ea(8),
				rawSize:  uint32(len(s.Code)),
			}, nil
		}
		return secMeta{
			segName:    "__DATA",
			sectName:   "__thread_bss",
			flags:      sTypeZerofill,
			align:      ea(8),
			bssSize:    zerofillSize(),
			isZerofill: true,
		}, nil

	case object.SectionCustom:
		comma := strings.IndexByte(s.Custom, ',')
		if comma < 0 {
			return secMeta{}, fmt.Errorf(
				"macho: section[%d] SectionCustom: expected \"segment,section\" format, got %q",
				i, s.Custom)
		}
		return secMeta{
			segName:  s.Custom[:comma],
			sectName: s.Custom[comma+1:],
			flags:    sTypeRegular,
			align:    ea(1),
			rawSize:  uint32(len(s.Code)),
		}, nil

	default:
		return secMeta{}, fmt.Errorf("macho: section[%d]: unknown SectionKind %d", i, s.Kind)
	}
}

// ── Main serialisation ────────────────────────────────────────────────────────

func (f *File) build() ([]byte, error) {
	le := binary.LittleEndian
	nSec := len(f.sections)

	// ── Phase 1: relocation descriptors ──────────────────────────────────

	type secRelInfo struct {
		descs   []relocDesc
		records []relocInfo
	}
	secRel := make([]secRelInfo, nSec)

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		descs := make([]relocDesc, len(s.Relocs))
		for j, r := range s.Relocs {
			rd, err := f.relocDesc(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("macho: section[%d] reloc[%d]: %w", i, j, err)
			}
			descs[j] = rd
		}
		secRel[i].descs = descs
	}

	// ── Phase 2: section metadata ─────────────────────────────────────────

	meta := make([]secMeta, nSec)
	for i, s := range f.sections {
		m, err := sectionMeta(i, s)
		if err != nil {
			return nil, err
		}
		meta[i] = m
	}

	// ── Phase 3: symbol table ─────────────────────────────────────────────
	//
	// symEntry records what we need to resolve r_extern / r_symbolnum for
	// each relocation target.
	type symEntry struct {
		nlistIdx uint32
		sectIdx  int            // 0-based section index; -1 for undefined externals
		binding  object.Binding
	}
	symDefs := make(map[string]symEntry)

	strtab := newStrTab()
	var syms []nlist64

	// [0] mandatory null symbol
	syms = append(syms, nlist64{})

	// [1..nSec] one anonymous local section-symbol per section (strx=0).
	// Used as the r_symbolnum target for section-relative (r_extern=0) relocs.
	for i := range f.sections {
		syms = append(syms, nlist64{
			NStrx:  0,
			NType:  nSect,
			NSect:  uint8(1 + i),
			NDesc:  0,
			NValue: 0,
		})
	}

	// Local symbols (BindingLocal) — must precede globals in the nlist.
	for i, s := range f.sections {
		for _, sym := range s.Symbols {
			if sym.Name == "" || sym.Binding != object.BindingLocal {
				continue
			}
			idx := uint32(len(syms))
			syms = append(syms, nlist64{
				NStrx:  strtab.intern("_" + sym.Name),
				NType:  nSect,
				NSect:  uint8(1 + i),
				NDesc:  0,
				NValue: uint64(sym.Offset),
			})
			symDefs[sym.Name] = symEntry{idx, i, object.BindingLocal}
		}
	}

	// Global and weak defined symbols (BindingGlobal / BindingWeak).
	// FlagLinkOnce marks all globals in the section as N_WEAK_DEF so the
	// linker can dead-strip duplicate copies.
	for i, s := range f.sections {
		linkOnce := s.Flags&object.FlagLinkOnce != 0
		for _, sym := range s.Symbols {
			if sym.Name == "" {
				continue
			}
			if sym.Binding != object.BindingGlobal && sym.Binding != object.BindingWeak {
				continue
			}
			idx := uint32(len(syms))
			desc := uint16(0)
			if sym.Binding == object.BindingWeak || linkOnce {
				desc |= nWeakDef
			}
			syms = append(syms, nlist64{
				NStrx:  strtab.intern("_" + sym.Name),
				NType:  nSect | nExt,
				NSect:  uint8(1 + i),
				NDesc:  desc,
				NValue: uint64(sym.Offset),
			})
			symDefs[sym.Name] = symEntry{idx, i, sym.Binding}
		}
	}

	// Undefined external (N_UNDF | N_EXT) symbols for each reloc target not
	// defined in this object.
	for _, name := range externalSymbols(f.sections) {
		idx := uint32(len(syms))
		syms = append(syms, nlist64{
			NStrx:  strtab.intern("_" + name),
			NType:  nUndf | nExt,
			NSect:  noSect,
			NDesc:  0,
			NValue: 0,
		})
		symDefs[name] = symEntry{idx, -1, object.BindingGlobal}
	}

	// ── Phase 4: fill relocation records ─────────────────────────────────

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		records := make([]relocInfo, len(s.Relocs))
		for j, r := range s.Relocs {
			rd := secRel[i].descs[j]

			def, ok := symDefs[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("macho: section[%d] reloc[%d]: symbol %q not in symbol table",
					i, j, r.Symbol)
			}

			var isExternal bool
			var rSymNum uint32

			if def.binding == object.BindingLocal && def.sectIdx >= 0 {
				// Local defined symbol: section-relative relocation (r_extern=0).
				isExternal = false
				rSymNum = uint32(1 + def.sectIdx)
			} else {
				// Global, weak, or undefined: symbol-table relocation (r_extern=1).
				isExternal = true
				rSymNum = def.nlistIdx
			}

			records[j] = relocInfo{
				RAddress: r.Offset,
				RInfo:    packRelocInfo(rSymNum, rd.pcrel, rd.length, isExternal, rd.rtype),
			}
		}
		secRel[i].records = records
	}

	// ── Phase 5: load command block size ──────────────────────────────────

	lcSegSize := uint32(segCmdSize64 + nSec*sectionSize64)
	lcBvSize := uint32(0)
	if f.buildVersion {
		lcBvSize = buildVerCmdSize
	}
	totalLCSize := lcSegSize + lcBvSize + uint32(symtabCmdSize)

	dataStart := uint32(mhSize64) + totalLCSize

	// ── Phase 6: file-offset layout for section data & relocs ────────────

	type secLayout struct {
		dataOff  uint32 // file offset of raw bytes (0 for zerofill)
		relocOff uint32 // file offset of reloc array (0 if none)
		nReloc   uint32
	}
	layout := make([]secLayout, nSec)

	pos := dataStart
	for i := range f.sections {
		if meta[i].isZerofill {
			continue
		}
		pos = alignUp(pos, meta[i].align)
		layout[i].dataOff = pos
		pos += meta[i].rawSize

		if nr := uint32(len(secRel[i].records)); nr > 0 {
			layout[i].relocOff = pos
			layout[i].nReloc = nr
			pos += nr * relocSize
		}
	}

	symOff := pos
	strOff := symOff + uint32(len(syms))*nlistSize64
	strSize := uint32(len(strtab.bytes()))

	// ── Phase 7: segment vmsize and file size ─────────────────────────────

	var segVMSize, segFileSize uint64
	for i := range f.sections {
		if meta[i].isZerofill {
			segVMSize += meta[i].bssSize
		} else {
			segVMSize += uint64(meta[i].rawSize)
			segFileSize += uint64(meta[i].rawSize)
		}
	}

	// ── Phase 8: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)

	nCmds := uint32(2) // LC_SEGMENT_64 + LC_SYMTAB
	if f.buildVersion {
		nCmds++
	}

	// mach_header_64
	hdr := machHeader64{
		Magic:      mhMagic64,
		CPUType:    f.cpuType,
		CPUSubtype: f.cpuSubtype,
		FileType:   mhObject,
		NCmds:      nCmds,
		SizeOfCmds: totalLCSize,
		Flags:      mhSubsectionsViaSymbols,
	}
	if err := binary.Write(out, le, hdr); err != nil {
		return nil, fmt.Errorf("macho: write header: %w", err)
	}

	// LC_SEGMENT_64 — single unnamed segment for MH_OBJECT.
	var seg segmentCommand64
	seg.Cmd = lcSegment64
	seg.CmdSize = lcSegSize
	// SegName[16] stays zeroed — the unnamed segment.
	seg.VMAddr = 0
	seg.VMSize = segVMSize
	seg.FileOff = uint64(dataStart)
	seg.FileSize = segFileSize
	seg.MaxProt = vmProtRead | vmProtWrite | vmProtExecute
	seg.InitProt = vmProtRead | vmProtWrite | vmProtExecute
	seg.NSects = uint32(nSec)
	if err := binary.Write(out, le, seg); err != nil {
		return nil, fmt.Errorf("macho: write LC_SEGMENT_64: %w", err)
	}

	// section_64 entries — one per input section.
	for i := range f.sections {
		var sh section64
		copyPaddedName(sh.SectName[:], meta[i].sectName)
		copyPaddedName(sh.SegName[:], meta[i].segName)
		sh.Addr = 0
		sh.Flags = meta[i].flags
		sh.Align = log2(meta[i].align)

		if meta[i].isZerofill {
			sh.Size = meta[i].bssSize
			// Offset, RelOff, NReloc remain 0 for zerofill.
		} else {
			sh.Size = uint64(meta[i].rawSize)
			sh.Offset = layout[i].dataOff
			sh.RelOff = layout[i].relocOff
			sh.NReloc = layout[i].nReloc
		}
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("macho: write section_64[%d]: %w", i, err)
		}
	}

	// LC_BUILD_VERSION (optional)
	if f.buildVersion {
		bv := buildVersionCommand{
			Cmd:      lcBuildVersion,
			CmdSize:  buildVerCmdSize,
			Platform: uint32(f.bvPlatform),
			MinOS:    f.bvMinOS,
			SDK:      f.bvSDK,
			NTools:   0,
		}
		if err := binary.Write(out, le, bv); err != nil {
			return nil, fmt.Errorf("macho: write LC_BUILD_VERSION: %w", err)
		}
	}

	// LC_SYMTAB
	if err := binary.Write(out, le, symtabCommand{
		Cmd:     lcSymtab,
		CmdSize: symtabCmdSize,
		SymOff:  symOff,
		NSyms:   uint32(len(syms)),
		StrOff:  strOff,
		StrSize: strSize,
	}); err != nil {
		return nil, fmt.Errorf("macho: write LC_SYMTAB: %w", err)
	}

	// Section data + inline relocation tables.
	for i, s := range f.sections {
		if meta[i].isZerofill {
			continue
		}
		padTo(out, layout[i].dataOff)
		out.Write(applyImplicitAddends(s.Code, s.Relocs, secRel[i].descs))
		for _, r := range secRel[i].records {
			if err := binary.Write(out, le, r); err != nil {
				return nil, fmt.Errorf("macho: write reloc for section[%d]: %w", i, err)
			}
		}
	}

	// nlist_64 symbol table.
	padTo(out, symOff)
	for _, sym := range syms {
		if err := binary.Write(out, le, sym); err != nil {
			return nil, fmt.Errorf("macho: write nlist_64: %w", err)
		}
	}

	// String table.
	padTo(out, strOff)
	out.Write(strtab.bytes())

	return out.Bytes(), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// copyPaddedName copies up to 16 bytes of name into dst, zero-padding the rest.
func copyPaddedName(dst []byte, name string) {
	copy(dst, name)
	for i := len(name); i < len(dst); i++ {
		dst[i] = 0
	}
}

// log2 returns the base-2 logarithm of a power-of-two value v.
// Returns 0 for v == 0 or v == 1.
func log2(v uint32) uint32 {
	if v <= 1 {
		return 0
	}
	n := uint32(0)
	for v >>= 1; v > 0; v >>= 1 {
		n++
	}
	return n
}