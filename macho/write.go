// write.go — Mach-O MH_OBJECT serialisation.
//
// File layout (all offsets from start of file):
//
//   mach_header_64                                    32 bytes
//   LC_SEGMENT_64  (+ N × section_64)                72 + N×80 bytes
//   LC_BUILD_VERSION (if configured)                 24 bytes
//   LC_SYMTAB                                        24 bytes
//   ── section data region ──
//   section[0] raw bytes  (aligned)
//   section[0] reloc_info[]   (8 bytes each)
//   section[1] raw bytes
//   section[1] reloc_info[]
//   …
//   ── symbol & string tables ──
//   nlist_64[]            (16 bytes each)
//   string table          (null-terminated strings)
//
// Addend convention (implicit addends, like COFF):
//   Mach-O stores no addend in the relocation record.  Instead the linker
//   reads the addend from the instruction bytes at r_address.  Serialize
//   therefore writes RelocEntry.Addend into Code[r.Offset:] before emitting
//   each section's raw bytes.
//
// Symbol table ordering required by the static linker:
//   [0]        mandatory null / empty symbol
//   [1..nSec]  one N_SECT/N_EXT=0 (local) section-symbol per section
//   [nSec+1..] N_SECT/N_EXT=1 (external/global) symbols for exported sections
//   [last..]   N_UNDF/N_EXT=1 (undefined external) symbols for reloc targets
//
// r_symbolnum:
//   r_extern=1 → index into the nlist_64 symbol table (0-based)
//   r_extern=0 → 1-based section index (for local symbols)
package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
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

// ── nlist_64 type / binding nibbles ──────────────────────────────────────────

const (
	nUndf uint8 = 0x00 // N_UNDF: undefined
	nSect uint8 = 0x0E // N_SECT: defined in a section
	nExt  uint8 = 0x01 // N_EXT: external (global) bit
	nPExt uint8 = 0x10 // N_PEXT: private external (not used here)
)

const noSect uint8 = 0 // NO_SECT

// ── Binary structures ─────────────────────────────────────────────────────────

// machHeader64 mirrors mach_header_64 from <mach-o/loader.h>.
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

// segmentCommand64 mirrors segment_command_64.
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

// section64 mirrors section_64.
type section64 struct {
	SectName  [16]byte
	SegName   [16]byte
	Addr      uint64
	Size      uint64
	Offset    uint32 // file offset; 0 for zerofill
	Align     uint32 // power of 2
	RelOff    uint32 // file offset of relocation entries; 0 if none
	NReloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

// symtabCommand mirrors symtab_command.
type symtabCommand struct {
	Cmd     uint32
	CmdSize uint32
	SymOff  uint32 // file offset of nlist_64 array
	NSyms   uint32
	StrOff  uint32 // file offset of string table
	StrSize uint32
}

// buildVersionCommand mirrors build_version_command (ntools=0 variant).
type buildVersionCommand struct {
	Cmd      uint32
	CmdSize  uint32
	Platform uint32
	MinOS    uint32 // X.Y.Z packed as (X<<16)|(Y<<8)|Z
	SDK      uint32 // same packing
	NTools   uint32 // 0 — no tool version entries follow
}

// nlist64 mirrors nlist_64 from <mach-o/nlist.h>.
type nlist64 struct {
	NStrx  uint32 // index into string table
	NType  uint8  // type flags (N_TYPE + N_EXT etc.)
	NSect  uint8  // section number (1-based) or NO_SECT
	NDesc  uint16 // reference / stab flags
	NValue uint64 // symbol value (address or 0 for undef)
}

// relocInfo mirrors relocation_info from <mach-o/reloc.h>.
// The r_symbolnum, r_pcrel, r_length, r_extern, r_type bitfields are packed
// into a single uint32 in little-endian order.
type relocInfo struct {
	RAddress uint32 // byte offset within section
	RInfo    uint32 // packed: symbolnum[23:0] | pcrel[24] | length[26:25] | extern[27] | type[31:28]
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

// x86-64 Mach-O relocation types (r_type field, 4 bits).
const (
	x86_64RelocUnsigned uint8 = 0 // absolute 64-bit address
	x86_64RelocSigned   uint8 = 1 // 32-bit signed PC-relative displacement (generic)
	x86_64RelocBranch   uint8 = 2 // 32-bit PC-relative (CALL/JMP)
	x86_64RelocGOTLoad  uint8 = 3 // MOVQ load of a GOT entry
	x86_64RelocGOT      uint8 = 4 // other GOT reference
)

// ARM64 Mach-O relocation types.
const (
	arm64RelocUnsigned         uint8 = 0 // absolute (pointer-sized)
	arm64RelocSubtractor       uint8 = 1 // must be followed by ARM64_RELOC_UNSIGNED
	arm64RelocBranch26         uint8 = 2 // BL/B  26-bit PC-relative
	arm64RelocPage21           uint8 = 3 // ADR page21
	arm64RelocPageoff12        uint8 = 4 // page offset12
	arm64RelocGOTLoadPage21    uint8 = 5 // ADR GOT page21
	arm64RelocGOTLoadPageoff12 uint8 = 6 // GOT page offset12
)

// ── r_length encoding ─────────────────────────────────────────────────────────
// r_length encodes the byte width of the relocated field as log2:
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

// ── Relocation kind → Mach-O type ────────────────────────────────────────────

type relocDesc struct {
	rtype  uint8
	length uint8 // r_length (log2 of byte width)
	pcrel  bool
}

// FIX 1: enc.RelocKind → mir.RelocKind; the kind lives in the mir package.
func (f *File) relocDesc(k mir.RelocKind) (relocDesc, error) {
	switch f.cpuType {
	case cpuTypeX86_64:
		switch k {
		case mir.RelocPCRel32:
			return relocDesc{x86_64RelocBranch, rLength4, true}, nil
		case mir.RelocAbs64:
			return relocDesc{x86_64RelocUnsigned, rLength8, false}, nil
		case mir.RelocGOT:
			return relocDesc{x86_64RelocGOTLoad, rLength4, true}, nil
		}
	case cpuTypeARM64:
		switch k {
		case mir.RelocPCRel26:
			return relocDesc{arm64RelocBranch26, rLength4, true}, nil
		case mir.RelocAbs64:
			return relocDesc{arm64RelocUnsigned, rLength8, false}, nil
		case mir.RelocGOT:
			// First half of the GOT pair (GOT_LOAD_PAGE21); the encoder is
			// expected to emit a companion entry immediately after this one
			// (GOT_LOAD_PAGEOFF12) as required by the ARM64 ABI.
			return relocDesc{arm64RelocGOTLoadPage21, rLength4, true}, nil
		}
	}
	return relocDesc{}, fmt.Errorf("macho: unsupported relocation kind %v for cpu_type 0x%08X",
		k, uint32(f.cpuType))
}

// ── Implicit-addend patching ──────────────────────────────────────────────────

// addendSize returns the byte width of the implicit addend field for a given
// relocation descriptor.  All PCrel/32-bit types use 4 bytes; abs64 uses 8.
func addendSize(rd relocDesc) int {
	if rd.length == rLength8 {
		return 8
	}
	return 4
}

// applyImplicitAddends returns a copy of code with each relocation's addend
// baked into the appropriate bytes at r.Offset (little-endian).
func applyImplicitAddends(code []byte, relocs []enc.RelocEntry, descs []relocDesc) []byte {
	if len(relocs) == 0 {
		return code
	}
	patched := make([]byte, len(code))
	copy(patched, code)
	le := binary.LittleEndian
	for i, r := range relocs {
		sz := addendSize(descs[i])
		end := int(r.Offset) + sz
		if end > len(patched) {
			continue // malformed; relocDesc lookup already caught the kind error
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

func externalSymbols(sections []enc.Section) []string {
	defined := make(map[string]bool, len(sections))
	for _, s := range sections {
		defined[s.Name] = true
	}
	seen := make(map[string]bool)
	for _, s := range sections {
		for _, r := range s.Relocs {
			if !defined[r.Symbol] {
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
		// symbol index map is not yet built; we fill r_symbolnum in Phase 3.
		descs := make([]relocDesc, len(s.Relocs))
		for j, r := range s.Relocs {
			rd, err := f.relocDesc(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("macho: section %q reloc[%d]: %w", s.Name, j, err)
			}
			descs[j] = rd
		}
		secRel[i].descs = descs
	}

	// ── Phase 2: symbol table ─────────────────────────────────────────────

	strtab := newStrTab()
	symIdx := make(map[string]uint32)
	var syms []nlist64

	// [0] mandatory null symbol
	syms = append(syms, nlist64{})

	// [1..nSec] one local (N_SECT, !N_EXT) section symbol per section.
	// These are used by local (r_extern=0) relocations when the relocation
	// target is within the same object.
	for i, s := range f.sections {
		idx := uint32(len(syms))
		// Section symbols get the name "_<sectname>" stripped — they are
		// anonymous in Mach-O; n_strx=0 (empty) is conventional.
		syms = append(syms, nlist64{
			NStrx:  0,
			NType:  nSect,        // local, defined in section
			NSect:  uint8(1 + i), // 1-based section index
			NDesc:  0,
			NValue: 0,
		})
		symIdx[s.Name] = idx // default: section symbol; may be overridden below
	}

	// Exported (N_SECT | N_EXT) symbols for sections marked Exported=true.
	for i, s := range f.sections {
		if !s.Exported {
			continue
		}
		idx := uint32(len(syms))
		sym := nlist64{
			NStrx:  strtab.intern("_" + s.Name), // Mach-O convention: leading underscore
			NType:  nSect | nExt,
			NSect:  uint8(1 + i),
			NDesc:  0,
			NValue: 0,
		}
		syms = append(syms, sym)
		symIdx[s.Name] = idx // global overrides section symbol
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
		symIdx[name] = idx
	}

	// ── Phase 3: fill relocation records ─────────────────────────────────

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		records := make([]relocInfo, len(s.Relocs))
		for j, r := range s.Relocs {
			rd := secRel[i].descs[j]

			si, ok := symIdx[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("macho: section %q: relocation symbol %q not in symbol table",
					s.Name, r.Symbol)
			}

			// Determine whether target is external (r_extern=1) or local
			// (r_extern=0, r_symbolnum = 1-based section index).
			isExternal := true
			var rSymNum uint32

			// Check if target is a section symbol (defined in this object) but
			// not exported — then use section-relative reloc (r_extern=0).
			targetSecIdx := -1
			for k, sec := range f.sections {
				if sec.Name == r.Symbol {
					targetSecIdx = k
					break
				}
			}
			if targetSecIdx >= 0 && !f.sections[targetSecIdx].Exported {
				isExternal = false
				rSymNum = uint32(1 + targetSecIdx) // 1-based section ordinal
			} else {
				rSymNum = si
			}

			// FIX 2: r.Offset is int32; cast to uint32 for the RAddress field.
			records[j] = relocInfo{
				RAddress: uint32(r.Offset),
				RInfo:    packRelocInfo(rSymNum, rd.pcrel, rd.length, isExternal, rd.rtype),
			}
		}
		secRel[i].records = records
	}

	// ── Phase 4: section metadata ─────────────────────────────────────────

	type secMeta struct {
		segName  string // destination segment for section_64.segname
		sectName string // section_64.sectname
		flags    uint32
		align    uint32 // power-of-2 alignment (value, not log2)
		rawSize  uint32 // bytes of content (0 for zerofill/BSS)
		bssSize  uint64 // zerofill byte count
	}
	meta := make([]secMeta, nSec)

	for i, s := range f.sections {
		switch s.Kind {
		case enc.SectionText:
			meta[i] = secMeta{
				segName:  "__TEXT",
				sectName: "__text",
				flags:    sAttrPureInstructions | sAttrSomeInstructions,
				align:    16,
				rawSize:  uint32(len(s.Code)),
			}
		case enc.SectionData:
			meta[i] = secMeta{
				segName:  "__DATA",
				sectName: "__data",
				flags:    sTypeRegular,
				align:    8,
				rawSize:  uint32(len(s.Code)),
			}
		case enc.SectionROData:
			meta[i] = secMeta{
				segName:  "__TEXT",
				sectName: "__const",
				flags:    sTypeRegular,
				align:    8,
				rawSize:  uint32(len(s.Code)),
			}
		case enc.SectionBSS:
			// FIX 3: Section.Size field was removed; BSS size is now len(s.Code),
			// which the encoder sets to the required zero-fill byte count.
			meta[i] = secMeta{
				segName:  "__DATA",
				sectName: "__bss",
				flags:    sTypeZerofill,
				align:    8,
				bssSize:  uint64(len(s.Code)),
			}
		}
	}

	// ── Phase 5: compute load command block size ──────────────────────────

	// The load command block begins immediately after the Mach-O header.
	// It contains:
	//   LC_SEGMENT_64:  72 + nSec×80 bytes
	//   LC_BUILD_VERSION (optional): 24 bytes
	//   LC_SYMTAB:  24 bytes
	lcSegSize := uint32(segCmdSize64 + nSec*sectionSize64)
	lcBvSize := uint32(0)
	if f.buildVersion {
		lcBvSize = buildVerCmdSize
	}
	lcSymSize := uint32(symtabCmdSize)
	totalLCSize := lcSegSize + lcBvSize + lcSymSize

	// Data region starts right after header + load commands.
	dataStart := uint32(mhSize64) + totalLCSize

	// ── Phase 6: file-offset layout for section data & relocs ────────────

	type secLayout struct {
		dataOff  uint32 // file offset of raw bytes (0 for zerofill)
		relocOff uint32 // file offset of reloc array (0 if none)
		nReloc   uint32
	}
	layout := make([]secLayout, nSec)

	pos := dataStart
	for i, s := range f.sections {
		if s.Kind == enc.SectionBSS {
			continue
		}
		pos = alignUp(pos, meta[i].align)
		layout[i].dataOff = pos
		pos += meta[i].rawSize

		nr := uint32(len(secRel[i].records))
		if nr > 0 {
			// relocation_info entries need no special alignment (8 bytes, and
			// pos should already be at least 4-byte aligned after raw data).
			layout[i].relocOff = pos
			layout[i].nReloc = nr
			pos += nr * relocSize
		}
	}

	// Symbol table and string table come after all section data+relocs.
	symOff := pos
	strOff := symOff + uint32(len(syms))*nlistSize64
	strSize := uint32(len(strtab.bytes()))

	// ── Phase 7: compute segment vmsize (sum of all section sizes) ────────

	var segVMSize uint64
	for i, s := range f.sections {
		if s.Kind == enc.SectionBSS {
			segVMSize += meta[i].bssSize
		} else {
			segVMSize += uint64(meta[i].rawSize)
		}
	}

	// Total file bytes occupied by the segment's section content (excluding BSS).
	var segFileSize uint64
	for i, s := range f.sections {
		if s.Kind != enc.SectionBSS {
			segFileSize += uint64(meta[i].rawSize)
		}
	}

	// ── Phase 8: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)

	// Count load commands.
	nCmds := uint32(2) // LC_SEGMENT_64 + LC_SYMTAB
	if f.buildVersion {
		nCmds++
	}

	// Mach-O header
	hdr := machHeader64{
		Magic:      mhMagic64,
		CPUType:    f.cpuType,
		CPUSubtype: f.cpuSubtype,
		FileType:   mhObject,
		NCmds:      nCmds,
		SizeOfCmds: totalLCSize,
		Flags:      mhSubsectionsViaSymbols,
		Reserved:   0,
	}
	if err := binary.Write(out, le, hdr); err != nil {
		return nil, fmt.Errorf("macho: write header: %w", err)
	}

	// LC_SEGMENT_64
	var seg segmentCommand64
	seg.Cmd = lcSegment64
	seg.CmdSize = lcSegSize
	// MH_OBJECT: segment name is empty (the single unnamed segment).
	// segname[16] is already zeroed.
	seg.VMAddr = 0
	seg.VMSize = segVMSize
	seg.FileOff = uint64(dataStart)
	seg.FileSize = segFileSize
	seg.MaxProt = vmProtRead | vmProtWrite | vmProtExecute
	seg.InitProt = vmProtRead | vmProtWrite | vmProtExecute
	seg.NSects = uint32(nSec)
	seg.Flags = 0
	if err := binary.Write(out, le, seg); err != nil {
		return nil, fmt.Errorf("macho: write LC_SEGMENT_64: %w", err)
	}

	// section_64 entries — one per input section.
	for i, s := range f.sections {
		var sh section64
		copyPaddedName(sh.SectName[:], meta[i].sectName)
		copyPaddedName(sh.SegName[:], meta[i].segName)
		sh.Addr = 0
		sh.Flags = meta[i].flags

		// log2 of alignment
		sh.Align = log2(meta[i].align)

		if s.Kind == enc.SectionBSS {
			sh.Size = meta[i].bssSize
			sh.Offset = 0 // zerofill: no file bytes
			sh.RelOff = 0
			sh.NReloc = 0
		} else {
			sh.Size = uint64(meta[i].rawSize)
			sh.Offset = layout[i].dataOff
			sh.RelOff = layout[i].relocOff
			sh.NReloc = layout[i].nReloc
		}
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("macho: write section_64[%d] (%s): %w", i, s.Name, err)
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
	symCmd := symtabCommand{
		Cmd:     lcSymtab,
		CmdSize: symtabCmdSize,
		SymOff:  symOff,
		NSyms:   uint32(len(syms)),
		StrOff:  strOff,
		StrSize: strSize,
	}
	if err := binary.Write(out, le, symCmd); err != nil {
		return nil, fmt.Errorf("macho: write LC_SYMTAB: %w", err)
	}

	// Section data + inline relocation tables
	for i, s := range f.sections {
		if s.Kind == enc.SectionBSS {
			continue
		}
		padTo(out, layout[i].dataOff)

		code := applyImplicitAddends(s.Code, s.Relocs, secRel[i].descs)
		out.Write(code)

		for _, r := range secRel[i].records {
			if err := binary.Write(out, le, r); err != nil {
				return nil, fmt.Errorf("macho: write reloc for section %s: %w", s.Name, err)
			}
		}
	}

	// Symbol table
	padTo(out, symOff)
	for _, sym := range syms {
		if err := binary.Write(out, le, sym); err != nil {
			return nil, fmt.Errorf("macho: write nlist_64: %w", err)
		}
	}

	// String table
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
// Returns 0 for v==0 or v==1.
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