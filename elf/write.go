// write.go — ELF object-file serialisation for 64-bit and 32-bit targets.
//
// File layout produced (ET_REL, no program header table):
//
//   ┌────────────────────────────────┐
//   │ ELF header (64 or 52 bytes)   │
//   ├────────────────────────────────┤
//   │ .text / .data / .rodata        │  one section per encoder.Section
//   │ (.bss occupies no file bytes)  │
//   ├────────────────────────────────┤
//   │ .rela<name>  …                 │  one SHT_RELA per section with relocs
//   ├────────────────────────────────┤
//   │ .symtab                        │
//   ├────────────────────────────────┤
//   │ .strtab                        │  symbol name strings
//   ├────────────────────────────────┤
//   │ .shstrtab                      │  section name strings
//   ├────────────────────────────────┤
//   │ Section header table           │
//   └────────────────────────────────┘
//
// Symbol table ordering: all STB_LOCAL symbols first (null + section symbols),
// then STB_GLOBAL symbols (exported + undefined externals). sh_info of .symtab
// holds the index of the first global.
package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
)

// ── ELF binary structures ─────────────────────────────────────────────────────
//
// All fields are naturally aligned; binary.Write produces exactly the byte
// layout mandated by the ELF specification without any implicit padding.

// elf64Ehdr is the 64-byte ELF64 file header.
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

// elf64Shdr is the 64-byte ELF64 section header.
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

// elf64Sym is the 24-byte ELF64 symbol table entry.
type elf64Sym struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

// elf64Rela is the 24-byte ELF64 RELA relocation entry.
type elf64Rela struct {
	Offset uint64
	Info   uint64
	Addend int64
}

// elf32Ehdr is the 52-byte ELF32 file header.
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

// elf32Shdr is the 40-byte ELF32 section header.
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

// elf32Sym is the 16-byte ELF32 symbol table entry.
// Note: ELF32 places Value and Size before Info/Other/Shndx — the opposite
// of ELF64.
type elf32Sym struct {
	Name  uint32
	Value uint32
	Size  uint32
	Info  uint8
	Other uint8
	Shndx uint16
}

// elf32Rela is the 12-byte ELF32 RELA relocation entry.
type elf32Rela struct {
	Offset uint32
	Info   uint32
	Addend int32
}

// ── Section-header constants ──────────────────────────────────────────────────

const (
	shtNull     uint32 = 0
	shtProgBits uint32 = 1
	shtSymTab   uint32 = 2
	shtStrTab   uint32 = 3
	shtRela     uint32 = 4
	shtNoBits   uint32 = 8
)

const (
	shfWrite     uint64 = 0x1
	shfAlloc     uint64 = 0x2
	shfExecInstr uint64 = 0x4
	// shfInfoLink signals that sh_info holds a section header table index.
	// Required on SHT_RELA sections so the linker can validate cross-references.
	shfInfoLink uint64 = 0x40
)

const (
	shnUndef uint16 = 0
	shnABS   uint16 = 0xFFF1
)

// ── Symbol constants ──────────────────────────────────────────────────────────

const (
	stbLocal  uint8 = 0
	stbGlobal uint8 = 1
)

const (
	sttNotype  uint8 = 0
	sttObject  uint8 = 1
	sttFunc    uint8 = 2
	sttSection uint8 = 3
)

// stInfo packs the binding and type nibbles into st_info.
func stInfo(bind, typ uint8) uint8 { return (bind << 4) | (typ & 0xF) }

// ── Relocation type numbers ───────────────────────────────────────────────────

// AMD64 (R_X86_64_*)
const (
	rX86_64_64       uint32 = 1  // S + A              (absolute 64-bit)
	rX86_64_PC32     uint32 = 2  // S + A - P          (PC-relative 32-bit)
	rX86_64_GOTPCREL uint32 = 9  // G + GOT + A - P    (GOT-indirect)
	rX86_64_32       uint32 = 10 // S + A (zero-extend) (absolute 32-bit)
)

// AArch64 (R_AARCH64_*)
const (
	rAARCH64_ABS64            uint32 = 257 // S + A         (absolute 64-bit)
	rAARCH64_CALL26           uint32 = 283 // S + A - P     (BL / B, 26-bit)
	rAARCH64_ADR_GOT_PAGE     uint32 = 311 // GOT page (pair[0] of GOT reference)
	rAARCH64_LD64_GOT_LO12_NC uint32 = 312 // GOT offset   (pair[1] of GOT reference)
)

// i386 (R_386_*)
const (
	r386_32    uint32 = 1 // S + A    (absolute 32-bit)
	r386_PC32  uint32 = 2 // S + A - P (PC-relative 32-bit)
	r386_GOT32 uint32 = 3 // G + A    (GOT-relative)
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

// alignUp rounds v up to the next multiple of a (a must be a power of two,
// or ≤ 1 to mean "no alignment").
func alignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

// padTo writes zero bytes to buf until buf.Len() equals target.
func padTo(buf *bytes.Buffer, target uint64) {
	for uint64(buf.Len()) < target {
		buf.WriteByte(0)
	}
}

// ── r_info constructors ───────────────────────────────────────────────────────

func rinfo64(sym, typ uint32) uint64 { return (uint64(sym) << 32) | uint64(typ) }
func rinfo32(sym, typ uint32) uint32 { return (sym << 8) | (typ & 0xFF) }

// ── Relocation kind → ELF type number ────────────────────────────────────────

func (f *File) relocType(k enc.RelocKind) (uint32, error) {
	switch f.machine {
	case emX86_64:
		switch k {
		case mir.RelocPCRel32:
			return rX86_64_PC32, nil
		case mir.RelocAbs64:
			return rX86_64_64, nil
		case mir.RelocAbs32:
			return rX86_64_32, nil
		case mir.RelocGOT:
			return rX86_64_GOTPCREL, nil
		}
	case emAARCH64:
		switch k {
		case mir.RelocPCRel26:
			return rAARCH64_CALL26, nil
		case mir.RelocAbs64:
			return rAARCH64_ABS64, nil
		case mir.RelocGOT:
			// First half of the two-entry GOT pair.  The ARM64 encoder is
			// expected to emit a companion RelocEntry with Kind=RelocGOT
			// immediately after (the linker maps the pair to
			// ADR_GOT_PAGE + LD64_GOT_LO12_NC).  We handle both uniformly;
			// the alternating pattern produces the right RELA sequence.
			return rAARCH64_ADR_GOT_PAGE, nil
		}
	case emI386:
		switch k {
		case mir.RelocPCRel32:
			return r386_PC32, nil
		case mir.RelocAbs32:
			return r386_32, nil
		case mir.RelocGOT:
			return r386_GOT32, nil
		}
	}
	return 0, fmt.Errorf("unsupported relocation kind %v for e_machine %d", k, f.machine)
}

// ── Internal section descriptor ───────────────────────────────────────────────

// secDesc holds everything needed to emit one section header plus its content.
type secDesc struct {
	name    string
	shType  uint32
	flags   uint64 // cast to uint32 for 32-bit output
	link    uint32 // sh_link
	info    uint32 // sh_info
	align   uint64 // sh_addralign (0 → not applicable)
	entSize uint64 // sh_entsize
	data    []byte // section content; nil for SHT_NOBITS
	noSize  uint64 // sh_size for SHT_NOBITS sections
	fileOff uint64 // assigned during layout
}

// ── 64-bit ELF serialisation ──────────────────────────────────────────────────

func (f *File) build64() ([]byte, error) {
	le := binary.LittleEndian

	// ── Phase 1: symbol table ─────────────────────────────────────────────

	strtab := newStrTab() // symbol name string table
	symIndex := make(map[string]uint32)
	var syms []elf64Sym

	// [0] Mandatory null symbol — all fields zero.
	syms = append(syms, elf64Sym{})

	// [1..N] One STT_SECTION/STB_LOCAL symbol per input section.
	// Section content sections start at ELF section index 1.
	for i, s := range f.sections {
		idx := uint32(len(syms))
		syms = append(syms, elf64Sym{
			Name:  0, // section symbols are nameless
			Info:  stInfo(stbLocal, sttSection),
			Shndx: uint16(1 + i),
		})
		symIndex[s.Name] = idx // default: section symbol; may be overridden below
	}

	// firstGlobal is the index of the first STB_GLOBAL symbol, stored in
	// .symtab sh_info so the linker can partition the symbol table.
	firstGlobal := uint32(len(syms))

	// STB_GLOBAL symbols for exported sections.
	for i, s := range f.sections {
		if !s.Exported {
			continue
		}
		symType := sttFunc
		if s.Kind != enc.SectionText {
			symType = sttObject
		}
		idx := uint32(len(syms))
		syms = append(syms, elf64Sym{
			Name:  strtab.intern(s.Name),
			Info:  stInfo(stbGlobal, symType),
			Shndx: uint16(1 + i),
			Size:  uint64(len(s.Code)),
		})
		symIndex[s.Name] = idx // global takes priority over section symbol
	}

	// STB_GLOBAL/SHN_UNDEF symbols for each external relocation target.
	for _, name := range externalSymbols(f.sections) {
		idx := uint32(len(syms))
		syms = append(syms, elf64Sym{
			Name:  strtab.intern(name),
			Info:  stInfo(stbGlobal, sttNotype),
			Shndx: shnUndef,
		})
		symIndex[name] = idx
	}

	// Encode symbol table bytes.
	symBuf := new(bytes.Buffer)
	for _, sym := range syms {
		if err := binary.Write(symBuf, le, sym); err != nil {
			return nil, fmt.Errorf("elf: encode symbol: %w", err)
		}
	}

	// ── Phase 2: RELA section data ────────────────────────────────────────

	type relaWork struct {
		contentIdx int    // index into f.sections
		data       []byte // encoded Elf64_Rela entries
	}
	var relaWork []relaWork

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		buf := new(bytes.Buffer)
		for _, r := range s.Relocs {
			si, ok := symIndex[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("elf: section %q: relocation symbol %q not in symbol table",
					s.Name, r.Symbol)
			}
			rtype, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("elf: section %q: %w", s.Name, err)
			}
			rela := elf64Rela{
				Offset: uint64(r.Offset),
				Info:   rinfo64(si, rtype),
				Addend: r.Addend,
			}
			if err := binary.Write(buf, le, rela); err != nil {
				return nil, fmt.Errorf("elf: encode rela: %w", err)
			}
		}
		relaWork = append(relaWork, struct {
			contentIdx int
			data       []byte
		}{i, buf.Bytes()})
	}

	// ── Phase 3: section descriptor list ─────────────────────────────────

	// Section indices:
	//   0            → NULL
	//   1..N         → content sections   (N = len(f.sections))
	//   N+1..N+M     → RELA sections      (M = len(relaWork))
	//   N+M+1        → .symtab
	//   N+M+2        → .strtab
	//   N+M+3        → .shstrtab
	nContent := uint32(len(f.sections))
	nRela := uint32(len(relaWork))
	symtabIdx := 1 + nContent + nRela
	strtabIdx := symtabIdx + 1
	shstrtabIdx := strtabIdx + 1

	shstrtab := newStrTab() // section name string table
	shstrtab.intern("")     // index 0 = empty

	var descs []secDesc

	// [0] NULL section
	descs = append(descs, secDesc{name: "", shType: shtNull})

	// [1..N] Content sections
	for _, s := range f.sections {
		shstrtab.intern(s.Name)
		d := secDesc{name: s.Name}
		switch s.Kind {
		case enc.SectionText:
			d.shType = shtProgBits
			d.flags = shfAlloc | shfExecInstr
			d.align = 16
			d.data = s.Code
		case enc.SectionData:
			d.shType = shtProgBits
			d.flags = shfAlloc | shfWrite
			d.align = 8
			d.data = s.Code
		case enc.SectionROData:
			d.shType = shtProgBits
			d.flags = shfAlloc
			d.align = 8
			d.data = s.Code
		case enc.SectionBSS:
			d.shType = shtNoBits
			d.flags = shfAlloc | shfWrite
			d.align = 8
			d.noSize = uint64(s.Size)
		}
		descs = append(descs, d)
	}

	// [N+1..N+M] RELA sections
	for _, rw := range relaWork {
		s := f.sections[rw.contentIdx]
		nm := ".rela" + s.Name
		shstrtab.intern(nm)
		descs = append(descs, secDesc{
			name:    nm,
			shType:  shtRela,
			flags:   shfInfoLink,
			align:   8,
			link:    symtabIdx,
			info:    uint32(1 + rw.contentIdx), // section being relocated
			entSize: uint64(relaSize64),
			data:    rw.data,
		})
	}

	// [N+M+1] .symtab
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

	// [N+M+2] .strtab
	shstrtab.intern(".strtab")
	descs = append(descs, secDesc{
		name:   ".strtab",
		shType: shtStrTab,
		align:  1,
		data:   strtab.bytes(),
	})

	// [N+M+3] .shstrtab — intern its own name last, then freeze.
	shstrtab.intern(".shstrtab")
	descs = append(descs, secDesc{
		name:   ".shstrtab",
		shType: shtStrTab,
		align:  1,
		data:   shstrtab.bytes(), // all names already interned above
	})

	// ── Phase 4: file-offset layout ───────────────────────────────────────

	pos := uint64(ehdrSize64)
	for i := range descs {
		if i == 0 {
			continue // NULL: no file content; fileOff stays 0
		}
		d := &descs[i]
		if d.shType == shtNoBits {
			// Conceptual file offset per ELF spec; no bytes written.
			pos = alignUp(pos, d.align)
			d.fileOff = pos
			continue // pos does NOT advance for NOBITS
		}
		if len(d.data) == 0 {
			d.fileOff = pos
			continue
		}
		pos = alignUp(pos, d.align)
		d.fileOff = pos
		pos += uint64(len(d.data))
	}
	shoff := alignUp(pos, 8) // section header table: 8-byte aligned

	// ── Phase 5: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)

	// ELF64 header
	var hdr elf64Ehdr
	hdr.Ident[0] = 0x7F
	hdr.Ident[1] = 'E'
	hdr.Ident[2] = 'L'
	hdr.Ident[3] = 'F'
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

	// Section content (skip NULL and NOBITS; write the rest with alignment padding)
	for i := 1; i < len(descs); i++ {
		d := &descs[i]
		if d.shType == shtNoBits || len(d.data) == 0 {
			continue
		}
		padTo(out, d.fileOff)
		out.Write(d.data)
	}

	// Section header table
	padTo(out, shoff)
	for i, d := range descs {
		var sh elf64Shdr
		if i > 0 { // i == 0 → all-zero NULL header
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

	for i, s := range f.sections {
		idx := uint32(len(syms))
		syms = append(syms, elf32Sym{
			Info:  stInfo(stbLocal, sttSection),
			Shndx: uint16(1 + i),
		})
		symIndex[s.Name] = idx
	}
	firstGlobal := uint32(len(syms))

	for i, s := range f.sections {
		if !s.Exported {
			continue
		}
		symType := sttFunc
		if s.Kind != enc.SectionText {
			symType = sttObject
		}
		idx := uint32(len(syms))
		syms = append(syms, elf32Sym{
			Name:  strtab.intern(s.Name),
			Info:  stInfo(stbGlobal, symType),
			Shndx: uint16(1 + i),
			Size:  uint32(len(s.Code)),
		})
		symIndex[s.Name] = idx
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

	type relaWork struct {
		contentIdx int
		data       []byte
	}
	var relaWork []relaWork

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		buf := new(bytes.Buffer)
		for _, r := range s.Relocs {
			si, ok := symIndex[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("elf: section %q: relocation symbol %q not in symbol table",
					s.Name, r.Symbol)
			}
			rtype, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("elf: section %q: %w", s.Name, err)
			}
			rela := elf32Rela{
				Offset: uint32(r.Offset),
				Info:   rinfo32(si, rtype),
				Addend: int32(r.Addend),
			}
			if err := binary.Write(buf, le, rela); err != nil {
				return nil, fmt.Errorf("elf: encode rela32: %w", err)
			}
		}
		relaWork = append(relaWork, struct {
			contentIdx int
			data       []byte
		}{i, buf.Bytes()})
	}

	// ── Phase 3: section descriptor list ─────────────────────────────────

	nContent := uint32(len(f.sections))
	nRela := uint32(len(relaWork))
	symtabIdx := 1 + nContent + nRela
	strtabIdx := symtabIdx + 1
	shstrtabIdx := strtabIdx + 1

	shstrtab := newStrTab()
	shstrtab.intern("")

	var descs []secDesc
	descs = append(descs, secDesc{name: "", shType: shtNull})

	for _, s := range f.sections {
		shstrtab.intern(s.Name)
		d := secDesc{name: s.Name}
		switch s.Kind {
		case enc.SectionText:
			d.shType = shtProgBits
			d.flags = shfAlloc | shfExecInstr
			d.align = 16
			d.data = s.Code
		case enc.SectionData:
			d.shType = shtProgBits
			d.flags = shfAlloc | shfWrite
			d.align = 4
			d.data = s.Code
		case enc.SectionROData:
			d.shType = shtProgBits
			d.flags = shfAlloc
			d.align = 4
			d.data = s.Code
		case enc.SectionBSS:
			d.shType = shtNoBits
			d.flags = shfAlloc | shfWrite
			d.align = 4
			d.noSize = uint64(s.Size)
		}
		descs = append(descs, d)
	}
	for _, rw := range relaWork {
		s := f.sections[rw.contentIdx]
		nm := ".rela" + s.Name
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
	hdr.Ident[0] = 0x7F
	hdr.Ident[1] = 'E'
	hdr.Ident[2] = 'L'
	hdr.Ident[3] = 'F'
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
// appear in relocation entries across all sections but are not themselves
// the name of any input section (i.e. they require SHN_UNDEF entries).
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
	sort.Strings(names) // deterministic output
	return names
}