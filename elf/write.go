// write.go — ELF object-file serialisation for 64-bit and 32-bit targets.
//
// File layout produced (ET_REL, no program header table):
//
//	┌────────────────────────────────┐
//	│ ELF header (64 or 52 bytes)   │
//	├────────────────────────────────┤
//	│ content sections               │
//	│ (.bss / .tbss: no file bytes)  │
//	├────────────────────────────────┤
//	│ .rela<name> …                  │
//	├────────────────────────────────┤
//	│ .group …   (COMDAT only)       │
//	├────────────────────────────────┤
//	│ .note.GNU-stack  (if enabled)  │
//	├────────────────────────────────┤
//	│ .symtab                        │
//	├────────────────────────────────┤
//	│ .strtab                        │
//	├────────────────────────────────┤
//	│ .shstrtab                      │
//	├────────────────────────────────┤
//	│ Section header table           │
//	└────────────────────────────────┘
//
// Symbol table ordering: STB_LOCAL symbols first (null + section symbols +
// local named), then STB_GLOBAL / STB_WEAK. sh_info of .symtab holds the
// index of the first non-local symbol.
package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/vertex-language/objectfile/object"
)

// ── ELF binary structures ─────────────────────────────────────────────────────

type elf64Ehdr struct {
	Ident     [16]uint8
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type elf64Shdr struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type elf64Sym struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

type elf64Rela struct {
	Offset uint64
	Info   uint64
	Addend int64
}

type elf32Ehdr struct {
	Ident     [16]uint8
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint32
	Phoff     uint32
	Shoff     uint32
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type elf32Shdr struct {
	Name      uint32
	Type      uint32
	Flags     uint32
	Addr      uint32
	Offset    uint32
	Size      uint32
	Link      uint32
	Info      uint32
	Addralign uint32
	Entsize   uint32
}

// elf32Sym: ELF32 places Value and Size before Info/Other/Shndx.
type elf32Sym struct {
	Name  uint32
	Value uint32
	Size  uint32
	Info  uint8
	Other uint8
	Shndx uint16
}

type elf32Rela struct {
	Offset uint32
	Info   uint32
	Addend int32
}

// ── Section-header type constants ─────────────────────────────────────────────

const (
	shtNull      uint32 = 0
	shtProgBits  uint32 = 1
	shtSymTab    uint32 = 2
	shtStrTab    uint32 = 3
	shtRela      uint32 = 4
	shtNoBits    uint32 = 8
	shtInitArray uint32 = 14
	shtFiniArray uint32 = 15
	shtGroup     uint32 = 17
)

// Section-header flag constants.
const (
	shfWrite     uint64 = 0x1
	shfAlloc     uint64 = 0x2
	shfExecInstr uint64 = 0x4
	shfInfoLink  uint64 = 0x40  // sh_info holds a section index
	shfTLS       uint64 = 0x400
)

const (
	shnUndef uint16 = 0
	shnABS   uint16 = 0xFFF1
)

// ── Symbol constants ──────────────────────────────────────────────────────────

const (
	stbLocal  uint8 = 0
	stbGlobal uint8 = 1
	stbWeak   uint8 = 2
)

const (
	sttNotype  uint8 = 0
	sttObject  uint8 = 1
	sttFunc    uint8 = 2
	sttSection uint8 = 3
)

func stInfo(bind, typ uint8) uint8 { return (bind << 4) | (typ & 0xF) }

// ── Relocation type numbers ───────────────────────────────────────────────────

// AMD64 (R_X86_64_*)
const (
	rX86_64_64       uint32 = 1
	rX86_64_PC32     uint32 = 2
	rX86_64_PLT32    uint32 = 4
	rX86_64_GOTPCREL uint32 = 9
	rX86_64_32       uint32 = 10
	rX86_64_TLSGD    uint32 = 19
	rX86_64_GOTTPOFF uint32 = 22
	rX86_64_TPOFF32  uint32 = 23
)

// AArch64 (R_AARCH64_*)
const (
	rAARCH64_ABS64                      uint32 = 257
	rAARCH64_ABS32                      uint32 = 258
	rAARCH64_ADR_PREL_PG_HI21          uint32 = 275
	rAARCH64_ADD_ABS_LO12_NC           uint32 = 277
	rAARCH64_CALL26                     uint32 = 283
	rAARCH64_ADR_GOT_PAGE              uint32 = 311
	rAARCH64_LD64_GOT_LO12_NC         uint32 = 312
	rAARCH64_TLSGD_ADR_PAGE21          uint32 = 513
	rAARCH64_TLSIE_ADR_GOTTPREL_PAGE21 uint32 = 541
	rAARCH64_TLSLE_ADD_TPREL_LO12_NC  uint32 = 554
)

// i386 (R_386_*)
const (
	r386_32    uint32 = 1
	r386_PC32  uint32 = 2
	r386_GOT32 uint32 = 3
)

// RISC-V 64 (R_RISCV_*)
const (
	rRISCV_32           uint32 = 1
	rRISCV_64           uint32 = 2
	rRISCV_CALL_PLT     uint32 = 19
	rRISCV_TLS_GOT_HI20 uint32 = 21
	rRISCV_TLS_GD_HI20  uint32 = 22
	rRISCV_HI20         uint32 = 26
	rRISCV_LO12_I       uint32 = 27
	rRISCV_LO12_S       uint32 = 28
	rRISCV_TPREL_HI20   uint32 = 29
)

// ── Structure sizes (bytes) ───────────────────────────────────────────────────

const (
	ehdrSize64 = 64
	shdrSize64 = 64
	symSize64  = 24
	relaSize64 = 24

	ehdrSize32 = 52
	shdrSize32 = 40
	symSize32  = 16
	relaSize32 = 12
)

// ── Alignment helpers ─────────────────────────────────────────────────────────

func alignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func padTo(buf *bytes.Buffer, target uint64) {
	for uint64(buf.Len()) < target {
		buf.WriteByte(0)
	}
}

// ── r_info constructors ───────────────────────────────────────────────────────

func rinfo64(sym, typ uint32) uint64 { return (uint64(sym) << 32) | uint64(typ) }
func rinfo32(sym, typ uint32) uint32 { return (sym << 8) | (typ & 0xFF) }

// ── Internal section descriptor ───────────────────────────────────────────────

type secDesc struct {
	name    string
	shType  uint32
	flags   uint64 // cast to uint32 for 32-bit output
	link    uint32
	info    uint32
	align   uint64
	entSize uint64
	data    []byte
	noSize  uint64 // sh_size for SHT_NOBITS sections
	fileOff uint64 // assigned during layout
}

// ── Section / symbol helpers ──────────────────────────────────────────────────

// elfSectionName returns the canonical ELF section name for a Section.
func elfSectionName(s object.Section) string {
	switch s.Kind {
	case object.SectionText:
		return ".text"
	case object.SectionData:
		return ".data"
	case object.SectionROData:
		return ".rodata"
	case object.SectionBSS:
		return ".bss"
	case object.SectionUnwind:
		return ".eh_frame"
	case object.SectionInitArray:
		return ".init_array"
	case object.SectionFiniArray:
		return ".fini_array"
	case object.SectionTLS:
		if len(s.Code) > 0 {
			return ".tdata"
		}
		return ".tbss"
	case object.SectionCustom:
		return s.Custom
	}
	return ".unknown"
}

// elfSymType maps an object.SymbolKind to an ELF st_type nibble.
func elfSymType(k object.SymbolKind) uint8 {
	switch k {
	case object.SymFunc:
		return sttFunc
	case object.SymData:
		return sttObject
	case object.SymSection:
		return sttSection
	}
	return sttNotype
}

// sectionVSize returns the virtual size for BSS / zero-fill sections.
func sectionVSize(s object.Section) uint64 {
	if s.VSize > 0 {
		return s.VSize
	}
	return uint64(len(s.Code))
}

// comdatSig returns the symbol-table index of the first global or weak
// symbol in s, used as the COMDAT group signature.
func comdatSig(s object.Section, symIndex map[string]uint32, sectionI int) (uint32, error) {
	for _, sym := range s.Symbols {
		if sym.Binding == object.BindingGlobal || sym.Binding == object.BindingWeak {
			if si, ok := symIndex[sym.Name]; ok {
				return si, nil
			}
		}
	}
	return 0, fmt.Errorf("elf: FlagLinkOnce section %d has no global symbol for COMDAT signature", sectionI)
}

// buildGroupData assembles the GRP_COMDAT flag word followed by ELF section
// indices for the content section and its RELA section (if any).
func buildGroupData(contentELFIdx uint32, relaIdxFor map[int]int, sectionI int, nContent uint32) []byte {
	members := []uint32{contentELFIdx}
	if j, ok := relaIdxFor[sectionI]; ok {
		members = append(members, 1+nContent+uint32(j))
	}
	data := make([]byte, 4*(1+len(members)))
	binary.LittleEndian.PutUint32(data[0:], 1) // GRP_COMDAT
	for k, m := range members {
		binary.LittleEndian.PutUint32(data[4+k*4:], m)
	}
	return data
}

// ── 64-bit ELF serialisation ──────────────────────────────────────────────────

func (f *File) build64() ([]byte, error) {
	le := binary.LittleEndian

	// ── Phase 1: symbol table ─────────────────────────────────────────────

	strtab := newStrTab()
	symIndex := make(map[string]uint32)
	var syms []elf64Sym

	// [0] Mandatory null symbol — all fields zero.
	syms = append(syms, elf64Sym{})

	// [1..N] One anonymous STT_SECTION/STB_LOCAL symbol per content section.
	for i := range f.sections {
		syms = append(syms, elf64Sym{
			Info:  stInfo(stbLocal, sttSection),
			Shndx: uint16(1 + i),
		})
	}

	// Local named symbols (non-section kind).
	for i, s := range f.sections {
		for _, sym := range s.Symbols {
			if sym.Binding != object.BindingLocal || sym.Kind == object.SymSection {
				continue
			}
			idx := uint32(len(syms))
			syms = append(syms, elf64Sym{
				Name:  strtab.intern(sym.Name),
				Info:  stInfo(stbLocal, elfSymType(sym.Kind)),
				Shndx: uint16(1 + i),
				Value: uint64(sym.Offset),
				Size:  uint64(sym.Size),
			})
			symIndex[sym.Name] = idx
		}
	}

	firstGlobal := uint32(len(syms))

	// Global and weak named symbols.
	for i, s := range f.sections {
		for _, sym := range s.Symbols {
			if sym.Binding == object.BindingLocal {
				continue
			}
			bind := stbGlobal
			if sym.Binding == object.BindingWeak {
				bind = stbWeak
			}
			idx := uint32(len(syms))
			syms = append(syms, elf64Sym{
				Name:  strtab.intern(sym.Name),
				Info:  stInfo(uint8(bind), elfSymType(sym.Kind)),
				Shndx: uint16(1 + i),
				Value: uint64(sym.Offset),
				Size:  uint64(sym.Size),
			})
			symIndex[sym.Name] = idx
		}
	}

	// SHN_UNDEF entries for external relocation targets.
	for _, name := range externalSymbols(f.sections) {
		idx := uint32(len(syms))
		syms = append(syms, elf64Sym{
			Name:  strtab.intern(name),
			Info:  stInfo(stbGlobal, sttNotype),
			Shndx: shnUndef,
		})
		symIndex[name] = idx
	}

	symBuf := new(bytes.Buffer)
	for _, sym := range syms {
		if err := binary.Write(symBuf, le, sym); err != nil {
			return nil, fmt.Errorf("elf: encode symbol: %w", err)
		}
	}

	// ── Phase 2: RELA section data ────────────────────────────────────────

	type relaEntry struct {
		contentIdx int
		data       []byte
	}
	var relaWork []relaEntry

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		buf := new(bytes.Buffer)
		for _, r := range s.Relocs {
			si, ok := symIndex[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("elf: section %d (%s): relocation symbol %q not in symbol table",
					i, elfSectionName(s), r.Symbol)
			}
			rtype, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("elf: section %d (%s): %w", i, elfSectionName(s), err)
			}
			if err := binary.Write(buf, le, elf64Rela{
				Offset: uint64(r.Offset),
				Info:   rinfo64(si, rtype),
				Addend: r.Addend,
			}); err != nil {
				return nil, fmt.Errorf("elf: encode rela: %w", err)
			}
		}
		relaWork = append(relaWork, relaEntry{i, buf.Bytes()})
	}

	// ── Phase 3: section descriptor list ─────────────────────────────────

	// Section index layout:
	//   0            → NULL
	//   1..N         → content sections        (N = len(f.sections))
	//   N+1..N+M     → RELA sections           (M = len(relaWork))
	//   N+M+1..N+M+G → GROUP sections          (G = FlagLinkOnce count)
	//   N+M+G+1      → .note.GNU-stack         (if gnuStack)
	//   N+M+G+S+1    → .symtab  (S = gnuStackAdd)
	//   N+M+G+S+2    → .strtab
	//   N+M+G+S+3    → .shstrtab

	nContent := uint32(len(f.sections))
	nRela := uint32(len(relaWork))

	nGroup := uint32(0)
	for _, s := range f.sections {
		if s.Flags&object.FlagLinkOnce != 0 {
			nGroup++
		}
	}
	gnuStackAdd := uint32(0)
	if f.gnuStack {
		gnuStackAdd = 1
	}

	symtabIdx := 1 + nContent + nRela + nGroup + gnuStackAdd
	strtabIdx := symtabIdx + 1
	shstrtabIdx := strtabIdx + 1

	// Reverse map: content section index → position in relaWork.
	relaIdxFor := make(map[int]int, len(relaWork))
	for j, rw := range relaWork {
		relaIdxFor[rw.contentIdx] = j
	}

	shstrtab := newStrTab()
	shstrtab.intern("") // index 0 = empty name

	var descs []secDesc
	descs = append(descs, secDesc{shType: shtNull}) // [0] NULL

	// [1..N] Content sections.
	for _, s := range f.sections {
		name := elfSectionName(s)
		shstrtab.intern(name)
		d := secDesc{name: name}
		switch s.Kind {
		case object.SectionText:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc|shfExecInstr, 16, s.Code
		case object.SectionData:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc|shfWrite, 8, s.Code
		case object.SectionROData:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 8, s.Code
		case object.SectionBSS:
			d.shType, d.flags, d.align = shtNoBits, shfAlloc|shfWrite, 8
			d.noSize = sectionVSize(s)
		case object.SectionUnwind:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 8, s.Code
		case object.SectionInitArray:
			d.shType, d.flags, d.align, d.data = shtInitArray, shfAlloc|shfWrite, 8, s.Code
		case object.SectionFiniArray:
			d.shType, d.flags, d.align, d.data = shtFiniArray, shfAlloc|shfWrite, 8, s.Code
		case object.SectionTLS:
			d.flags, d.align = shfAlloc|shfWrite|shfTLS, 8
			if len(s.Code) > 0 {
				d.shType, d.data = shtProgBits, s.Code
			} else {
				d.shType, d.noSize = shtNoBits, sectionVSize(s)
			}
		case object.SectionCustom:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 8, s.Code
		}
		if s.Align > 0 {
			d.align = uint64(s.Align)
		}
		descs = append(descs, d)
	}

	// [N+1..N+M] RELA sections.
	for _, rw := range relaWork {
		s := f.sections[rw.contentIdx]
		nm := ".rela" + elfSectionName(s)
		shstrtab.intern(nm)
		descs = append(descs, secDesc{
			name:    nm,
			shType:  shtRela,
			flags:   shfInfoLink,
			align:   8,
			link:    symtabIdx,
			info:    uint32(1 + rw.contentIdx),
			entSize: uint64(relaSize64),
			data:    rw.data,
		})
	}

	// [N+M+1..N+M+G] GROUP (COMDAT) sections.
	for i, s := range f.sections {
		if s.Flags&object.FlagLinkOnce == 0 {
			continue
		}
		sigIdx, err := comdatSig(s, symIndex, i)
		if err != nil {
			return nil, err
		}
		shstrtab.intern(".group")
		descs = append(descs, secDesc{
			name:    ".group",
			shType:  shtGroup,
			align:   4,
			link:    symtabIdx,
			info:    sigIdx,
			entSize: 4,
			data:    buildGroupData(uint32(1+i), relaIdxFor, i, nContent),
		})
	}

	// .note.GNU-stack (if enabled) — empty SHT_PROGBITS, no flags.
	// Presence without SHF_EXECINSTR signals a non-executable stack to the linker.
	if f.gnuStack {
		shstrtab.intern(".note.GNU-stack")
		descs = append(descs, secDesc{
			name:   ".note.GNU-stack",
			shType: shtProgBits,
			align:  1,
		})
	}

	// .symtab
	shstrtab.intern(".symtab")
	descs = append(descs, secDesc{
		name:    ".symtab",
		shType:  shtSymTab,
		align:   8,
		link:    strtabIdx,
		info:    firstGlobal,
		entSize: uint64(symSize64),
		data:    symBuf.Bytes(),
	})

	// .strtab
	shstrtab.intern(".strtab")
	descs = append(descs, secDesc{
		name:   ".strtab",
		shType: shtStrTab,
		align:  1,
		data:   strtab.bytes(),
	})

	// .shstrtab — intern its own name last, then freeze.
	shstrtab.intern(".shstrtab")
	descs = append(descs, secDesc{
		name:   ".shstrtab",
		shType: shtStrTab,
		align:  1,
		data:   shstrtab.bytes(),
	})

	// ── Phase 4: file-offset layout ───────────────────────────────────────

	pos := uint64(ehdrSize64)
	for i := range descs {
		if i == 0 {
			continue // NULL: no file content
		}
		d := &descs[i]
		if d.shType == shtNoBits {
			// Assign a conceptual offset per spec; pos does NOT advance.
			pos = alignUp(pos, d.align)
			d.fileOff = pos
			continue
		}
		if len(d.data) == 0 {
			d.fileOff = pos
			continue
		}
		pos = alignUp(pos, d.align)
		d.fileOff = pos
		pos += uint64(len(d.data))
	}
	shoff := alignUp(pos, 8)

	// ── Phase 5: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)

	var hdr elf64Ehdr
	hdr.Ident[0], hdr.Ident[1], hdr.Ident[2], hdr.Ident[3] = 0x7F, 'E', 'L', 'F'
	hdr.Ident[eiClass] = elfClass64
	hdr.Ident[eiData] = elfData2LSB
	hdr.Ident[eiVersion] = evCurrent
	hdr.Ident[eiOSABI] = uint8(f.osabi)
	hdr.Type = etRel
	hdr.Machine = f.machine
	hdr.Version = evCurrent
	hdr.Shoff = shoff
	hdr.Ehsize = ehdrSize64
	hdr.Shentsize = shdrSize64
	hdr.Shnum = uint16(len(descs))
	hdr.Shstrndx = uint16(shstrtabIdx)
	if err := binary.Write(out, le, hdr); err != nil {
		return nil, fmt.Errorf("elf: write ELF64 header: %w", err)
	}

	for i := 1; i < len(descs); i++ {
		d := &descs[i]
		if d.shType == shtNoBits || len(d.data) == 0 {
			continue
		}
		padTo(out, d.fileOff)
		out.Write(d.data)
	}

	padTo(out, shoff)
	for i, d := range descs {
		var sh elf64Shdr
		if i > 0 {
			sh.Name = shstrtab.offsets[d.name]
			sh.Type = d.shType
			sh.Flags = d.flags
			sh.Offset = d.fileOff
			sh.Link = d.link
			sh.Info = d.info
			sh.Addralign = d.align
			sh.Entsize = d.entSize
			if d.shType == shtNoBits {
				sh.Size = d.noSize
			} else {
				sh.Size = uint64(len(d.data))
			}
		}
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("elf: write section header %d (%s): %w", i, d.name, err)
		}
	}

	return out.Bytes(), nil
}

// ── 32-bit ELF serialisation ──────────────────────────────────────────────────

func (f *File) build32() ([]byte, error) {
	le := binary.LittleEndian

	// ── Phase 1: symbol table ─────────────────────────────────────────────

	strtab := newStrTab()
	symIndex := make(map[string]uint32)
	var syms []elf32Sym

	syms = append(syms, elf32Sym{}) // [0] null

	for i := range f.sections {
		syms = append(syms, elf32Sym{
			Info:  stInfo(stbLocal, sttSection),
			Shndx: uint16(1 + i),
		})
	}

	for i, s := range f.sections {
		for _, sym := range s.Symbols {
			if sym.Binding != object.BindingLocal || sym.Kind == object.SymSection {
				continue
			}
			idx := uint32(len(syms))
			syms = append(syms, elf32Sym{
				Name:  strtab.intern(sym.Name),
				Info:  stInfo(stbLocal, elfSymType(sym.Kind)),
				Shndx: uint16(1 + i),
				Value: uint32(sym.Offset),
				Size:  uint32(sym.Size),
			})
			symIndex[sym.Name] = idx
		}
	}

	firstGlobal := uint32(len(syms))

	for i, s := range f.sections {
		for _, sym := range s.Symbols {
			if sym.Binding == object.BindingLocal {
				continue
			}
			bind := stbGlobal
			if sym.Binding == object.BindingWeak {
				bind = stbWeak
			}
			idx := uint32(len(syms))
			syms = append(syms, elf32Sym{
				Name:  strtab.intern(sym.Name),
				Info:  stInfo(uint8(bind), elfSymType(sym.Kind)),
				Shndx: uint16(1 + i),
				Value: uint32(sym.Offset),
				Size:  uint32(sym.Size),
			})
			symIndex[sym.Name] = idx
		}
	}

	for _, name := range externalSymbols(f.sections) {
		idx := uint32(len(syms))
		syms = append(syms, elf32Sym{
			Name:  strtab.intern(name),
			Info:  stInfo(stbGlobal, sttNotype),
			Shndx: shnUndef,
		})
		symIndex[name] = idx
	}

	symBuf := new(bytes.Buffer)
	for _, sym := range syms {
		if err := binary.Write(symBuf, le, sym); err != nil {
			return nil, fmt.Errorf("elf: encode symbol32: %w", err)
		}
	}

	// ── Phase 2: RELA sections ────────────────────────────────────────────

	type relaEntry struct {
		contentIdx int
		data       []byte
	}
	var relaWork []relaEntry

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		buf := new(bytes.Buffer)
		for _, r := range s.Relocs {
			si, ok := symIndex[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("elf: section %d (%s): relocation symbol %q not in symbol table",
					i, elfSectionName(s), r.Symbol)
			}
			rtype, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("elf: section %d (%s): %w", i, elfSectionName(s), err)
			}
			if err := binary.Write(buf, le, elf32Rela{
				Offset: uint32(r.Offset),
				Info:   rinfo32(si, rtype),
				Addend: int32(r.Addend),
			}); err != nil {
				return nil, fmt.Errorf("elf: encode rela32: %w", err)
			}
		}
		relaWork = append(relaWork, relaEntry{i, buf.Bytes()})
	}

	// ── Phase 3: section descriptor list ─────────────────────────────────

	nContent := uint32(len(f.sections))
	nRela := uint32(len(relaWork))

	nGroup := uint32(0)
	for _, s := range f.sections {
		if s.Flags&object.FlagLinkOnce != 0 {
			nGroup++
		}
	}
	gnuStackAdd := uint32(0)
	if f.gnuStack {
		gnuStackAdd = 1
	}

	symtabIdx := 1 + nContent + nRela + nGroup + gnuStackAdd
	strtabIdx := symtabIdx + 1
	shstrtabIdx := strtabIdx + 1

	relaIdxFor := make(map[int]int, len(relaWork))
	for j, rw := range relaWork {
		relaIdxFor[rw.contentIdx] = j
	}

	shstrtab := newStrTab()
	shstrtab.intern("")

	var descs []secDesc
	descs = append(descs, secDesc{shType: shtNull})

	for _, s := range f.sections {
		name := elfSectionName(s)
		shstrtab.intern(name)
		d := secDesc{name: name}
		switch s.Kind {
		case object.SectionText:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc|shfExecInstr, 16, s.Code
		case object.SectionData:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc|shfWrite, 4, s.Code
		case object.SectionROData:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 4, s.Code
		case object.SectionBSS:
			d.shType, d.flags, d.align = shtNoBits, shfAlloc|shfWrite, 4
			d.noSize = sectionVSize(s)
		case object.SectionUnwind:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 4, s.Code
		case object.SectionInitArray:
			d.shType, d.flags, d.align, d.data = shtInitArray, shfAlloc|shfWrite, 4, s.Code
		case object.SectionFiniArray:
			d.shType, d.flags, d.align, d.data = shtFiniArray, shfAlloc|shfWrite, 4, s.Code
		case object.SectionTLS:
			d.flags, d.align = shfAlloc|shfWrite|shfTLS, 4
			if len(s.Code) > 0 {
				d.shType, d.data = shtProgBits, s.Code
			} else {
				d.shType, d.noSize = shtNoBits, sectionVSize(s)
			}
		case object.SectionCustom:
			d.shType, d.flags, d.align, d.data = shtProgBits, shfAlloc, 4, s.Code
		}
		if s.Align > 0 {
			d.align = uint64(s.Align)
		}
		descs = append(descs, d)
	}

	for _, rw := range relaWork {
		s := f.sections[rw.contentIdx]
		nm := ".rela" + elfSectionName(s)
		shstrtab.intern(nm)
		descs = append(descs, secDesc{
			name:    nm,
			shType:  shtRela,
			flags:   shfInfoLink,
			align:   4,
			link:    symtabIdx,
			info:    uint32(1 + rw.contentIdx),
			entSize: uint64(relaSize32),
			data:    rw.data,
		})
	}

	for i, s := range f.sections {
		if s.Flags&object.FlagLinkOnce == 0 {
			continue
		}
		sigIdx, err := comdatSig(s, symIndex, i)
		if err != nil {
			return nil, err
		}
		shstrtab.intern(".group")
		descs = append(descs, secDesc{
			name:    ".group",
			shType:  shtGroup,
			align:   4,
			link:    symtabIdx,
			info:    sigIdx,
			entSize: 4,
			data:    buildGroupData(uint32(1+i), relaIdxFor, i, nContent),
		})
	}

	if f.gnuStack {
		shstrtab.intern(".note.GNU-stack")
		descs = append(descs, secDesc{
			name:   ".note.GNU-stack",
			shType: shtProgBits,
			align:  1,
		})
	}

	shstrtab.intern(".symtab")
	descs = append(descs, secDesc{
		name:    ".symtab",
		shType:  shtSymTab,
		align:   4,
		link:    strtabIdx,
		info:    firstGlobal,
		entSize: uint64(symSize32),
		data:    symBuf.Bytes(),
	})

	shstrtab.intern(".strtab")
	descs = append(descs, secDesc{
		name:   ".strtab",
		shType: shtStrTab,
		align:  1,
		data:   strtab.bytes(),
	})

	shstrtab.intern(".shstrtab")
	descs = append(descs, secDesc{
		name:   ".shstrtab",
		shType: shtStrTab,
		align:  1,
		data:   shstrtab.bytes(),
	})

	// ── Phase 4: file-offset layout ───────────────────────────────────────

	pos := uint64(ehdrSize32)
	for i := range descs {
		if i == 0 {
			continue
		}
		d := &descs[i]
		if d.shType == shtNoBits {
			pos = alignUp(pos, d.align)
			d.fileOff = pos
			continue
		}
		if len(d.data) == 0 {
			d.fileOff = pos
			continue
		}
		pos = alignUp(pos, d.align)
		d.fileOff = pos
		pos += uint64(len(d.data))
	}
	shoff := alignUp(pos, 4)

	// ── Phase 5: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)

	var hdr elf32Ehdr
	hdr.Ident[0], hdr.Ident[1], hdr.Ident[2], hdr.Ident[3] = 0x7F, 'E', 'L', 'F'
	hdr.Ident[eiClass] = elfClass32
	hdr.Ident[eiData] = elfData2LSB
	hdr.Ident[eiVersion] = evCurrent
	hdr.Ident[eiOSABI] = uint8(f.osabi)
	hdr.Type = etRel
	hdr.Machine = f.machine
	hdr.Version = evCurrent
	hdr.Shoff = uint32(shoff)
	hdr.Ehsize = ehdrSize32
	hdr.Shentsize = shdrSize32
	hdr.Shnum = uint16(len(descs))
	hdr.Shstrndx = uint16(shstrtabIdx)
	if err := binary.Write(out, le, hdr); err != nil {
		return nil, fmt.Errorf("elf: write ELF32 header: %w", err)
	}

	for i := 1; i < len(descs); i++ {
		d := &descs[i]
		if d.shType == shtNoBits || len(d.data) == 0 {
			continue
		}
		padTo(out, d.fileOff)
		out.Write(d.data)
	}

	padTo(out, shoff)
	for i, d := range descs {
		var sh elf32Shdr
		if i > 0 {
			sh.Name = shstrtab.offsets[d.name]
			sh.Type = d.shType
			sh.Flags = uint32(d.flags)
			sh.Offset = uint32(d.fileOff)
			sh.Link = d.link
			sh.Info = d.info
			sh.Addralign = uint32(d.align)
			sh.Entsize = uint32(d.entSize)
			if d.shType == shtNoBits {
				sh.Size = uint32(d.noSize)
			} else {
				sh.Size = uint32(len(d.data))
			}
		}
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("elf: write section header %d (%s): %w", i, d.name, err)
		}
	}

	return out.Bytes(), nil
}

// ── Shared helpers ────────────────────────────────────────────────────────────

// externalSymbols returns a sorted, deduplicated list of symbol names that
// appear in relocation records but are not defined in any section's Symbols
// slice — i.e. they require SHN_UNDEF entries.
func externalSymbols(sections []object.Section) []string {
	defined := make(map[string]bool)
	for _, s := range sections {
		for _, sym := range s.Symbols {
			defined[sym.Name] = true
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
	sort.Strings(names) // deterministic output
	return names
}