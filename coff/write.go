// write.go — COFF object-file serialisation.
package coff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
)

// ── Structure size constants ──────────────────────────────────────────────────

const (
	coffFileHdrSize = 20 // IMAGE_FILE_HEADER
	coffSecHdrSize  = 40 // IMAGE_SECTION_HEADER
	coffSymSize     = 18 // IMAGE_SYMBOL  (fixed; AuxiliaryCount always 0)
	coffRelocSize   = 10 // IMAGE_RELOCATION
)

// ── Binary structures ─────────────────────────────────────────────────────────

// coffFileHdr is the 20-byte COFF file header (IMAGE_FILE_HEADER).
// SizeOfOptionalHeader is always 0 for object files.
type coffFileHdr struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// coffSecHdr is the 40-byte section header (IMAGE_SECTION_HEADER).
//
// For object files VirtualSize and VirtualAddress are 0 for all section kinds
// except BSS, where VirtualSize carries the uninitialized-data byte count.
type coffSecHdr struct {
	Name                 [8]byte // inline if ≤8 chars; else "/"+decimal strtab offset
	VirtualSize          uint32  // 0 for obj (used by loader in images only)
	VirtualAddress       uint32  // 0 for obj
	SizeOfRawData        uint32  // bytes of raw data in file; 0 for BSS
	PointerToRawData     uint32  // file offset of first raw byte; 0 for BSS
	PointerToRelocations uint32  // file offset of first reloc; 0 if none
	PointerToLinenumbers uint32  // deprecated; always 0
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16 // deprecated; always 0
	Characteristics      uint32
}

// coffReloc is the 10-byte relocation record (IMAGE_RELOCATION).
// COFF uses implicit addends: no Addend field; the linker reads the addend
// from the bytes at VirtualAddress inside the section.
type coffReloc struct {
	VirtualAddress   uint32 // byte offset within section
	SymbolTableIndex uint32
	Type             uint16
}

// coffSym is the 18-byte symbol table entry (IMAGE_SYMBOL).
// NumberOfAuxiliarySymbols is always 0; we emit no auxiliary records.
type coffSym struct {
	Name                    [8]byte // inline or \0\0\0\0 + strtab offset
	Value                   uint32
	SectionNumber           int16
	Type                    uint16
	StorageClass            uint8
	NumberOfAuxiliarySymbols uint8
}

// ── Section-characteristics constants ────────────────────────────────────────

const (
	scnCntCode    uint32 = 0x00000020 // IMAGE_SCN_CNT_CODE
	scnCntInitDat uint32 = 0x00000040 // IMAGE_SCN_CNT_INITIALIZED_DATA
	scnCntUninit  uint32 = 0x00000080 // IMAGE_SCN_CNT_UNINITIALIZED_DATA
	scnAlign1     uint32 = 0x00100000 // IMAGE_SCN_ALIGN_1BYTES
	scnAlign4     uint32 = 0x00300000 // IMAGE_SCN_ALIGN_4BYTES
	scnAlign8     uint32 = 0x00400000 // IMAGE_SCN_ALIGN_8BYTES
	scnAlign16    uint32 = 0x00500000 // IMAGE_SCN_ALIGN_16BYTES
	scnMemExec    uint32 = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
	scnMemRead    uint32 = 0x40000000 // IMAGE_SCN_MEM_READ
	scnMemWrite   uint32 = 0x80000000 // IMAGE_SCN_MEM_WRITE
)

// ── Symbol constants ──────────────────────────────────────────────────────────

const (
	symClassExternal uint8 = 2 // IMAGE_SYM_CLASS_EXTERNAL
	symClassStatic   uint8 = 3 // IMAGE_SYM_CLASS_STATIC

	symTypeNull uint16 = 0x0000 // no type info
	symTypeFunc uint16 = 0x0020 // function (DT_FUNCTION<<4 | T_NULL)

	symUndefined int16 = 0 // SHN_UNDEF equivalent
)

// ── Relocation type constants ─────────────────────────────────────────────────

// AMD64 (IMAGE_REL_AMD64_*)
const (
	relAMD64Addr64   uint16 = 0x0001 // 64-bit VA; 8-byte addend field
	relAMD64Addr32   uint16 = 0x0002 // 32-bit VA
	relAMD64Addr32NB uint16 = 0x0003 // 32-bit image-relative (no ImageBase added)
	relAMD64Rel32    uint16 = 0x0004 // 32-bit PC-relative from byte after reloc field
)

// ARM64 (IMAGE_REL_ARM64_*)
const (
	relARM64Addr32   uint16 = 0x0001 // 32-bit VA
	relARM64Addr32NB uint16 = 0x0002 // 32-bit image-relative
	relARM64Branch26 uint16 = 0x0003 // 26-bit PC-relative (BL/B)
	relARM64Addr64   uint16 = 0x000E // 64-bit VA; 8-byte addend field
)

// ── Relocation kind → COFF type ───────────────────────────────────────────────

func (f *File) relocType(k enc.RelocKind) (uint16, error) {
	switch f.machine {
	case machineAMD64:
		switch k {
		case mir.RelocPCRel32:
			return relAMD64Rel32, nil
		case mir.RelocAbs64:
			return relAMD64Addr64, nil
		case mir.RelocAbs32:
			return relAMD64Addr32, nil
		case mir.RelocIAT:
			return relAMD64Addr32NB, nil
		}
	case machineARM64:
		switch k {
		case mir.RelocPCRel26:
			return relARM64Branch26, nil
		case mir.RelocAbs64:
			return relARM64Addr64, nil
		case mir.RelocAbs32:
			return relARM64Addr32, nil
		case mir.RelocIAT:
			return relARM64Addr32NB, nil
		}
	}
	return 0, fmt.Errorf("unsupported relocation kind %v for machine 0x%04X", k, f.machine)
}

// relocAddendSize returns the byte width of the implicit addend field for a
// given COFF relocation type.  All types use a 4-byte field except the 64-bit
// absolute address types, which use 8.
func relocAddendSize(t uint16) int {
	switch t {
	case relAMD64Addr64, relARM64Addr64:
		return 8
	default:
		return 4
	}
}

// ── Name-encoding helpers ─────────────────────────────────────────────────────

// setSectionName encodes a section name into the 8-byte field of a section
// header following the COFF object-file rules:
//   - names ≤ 8 bytes: stored directly, null-padded
//   - names > 8 bytes: "/" + decimal offset into the string table
//     (offset measured from the start of the table, i.e. including the 4-byte
//     size prefix)
func setSectionName(field *[8]byte, name string, strtab *strTab) {
	if len(name) <= 8 {
		copy(field[:], name)
		return
	}
	off := strtab.intern(name) + 4 // +4 for the size prefix
	s := fmt.Sprintf("/%d", off)
	// The longest possible offset string for a 32-bit offset is 11 chars
	// ("/" + 10 digits), which does not fit in 8 bytes.  In practice object
	// files contain a modest number of strings; 7-digit decimal fits in 8
	// bytes.  Overflow here would indicate an extremely large string table.
	copy(field[:], s)
}

// encodeSymName encodes a symbol name into the 8-byte IMAGE_SYMBOL Name field:
//   - names ≤ 8 bytes: stored inline, null-padded
//   - names > 8 bytes: first 4 bytes = \x00\x00\x00\x00, next 4 bytes =
//     little-endian offset from start of string table (including size prefix)
func encodeSymName(name string, strtab *strTab) [8]byte {
	var b [8]byte
	if len(name) <= 8 {
		copy(b[:], name)
		return b
	}
	off := strtab.intern(name) + 4 // +4 for the size prefix
	// b[0:4] remain zero — the "use string table" sentinel
	binary.LittleEndian.PutUint32(b[4:], off)
	return b
}

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

// ── Implicit-addend patching ──────────────────────────────────────────────────

// applyImplicitAddends returns a new copy of code with each relocation's
// Addend written into the appropriate bytes at r.Offset.  The original slice
// is never modified.  All writes are little-endian.
func applyImplicitAddends(code []byte, relocs []enc.RelocEntry, rtypes []uint16) []byte {
	if len(relocs) == 0 {
		return code
	}
	patched := make([]byte, len(code))
	copy(patched, code)
	for i, r := range relocs {
		sz := relocAddendSize(rtypes[i])
		end := int(r.Offset) + sz
		if end > len(patched) {
			// Malformed; build() will have already caught this via relocType.
			continue
		}
		switch sz {
		case 8:
			binary.LittleEndian.PutUint64(patched[r.Offset:], uint64(r.Addend))
		default:
			binary.LittleEndian.PutUint32(patched[r.Offset:], uint32(int32(r.Addend)))
		}
	}
	return patched
}

// ── External symbol discovery ─────────────────────────────────────────────────

// externalSymbols returns a sorted, deduplicated list of symbol names that
// appear in relocation entries but are not the name of any input section.
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

	// ── Phase 1: string table ─────────────────────────────────────────────
	// Intern all long names eagerly so that the table is stable before we
	// compute offsets for section/symbol headers.

	strtab := newStrTab()
	for _, s := range f.sections {
		if len(s.Name) > 8 {
			strtab.intern(s.Name)
		}
	}

	// ── Phase 2: section metadata ─────────────────────────────────────────

	type secMeta struct {
		chars   uint32 // Characteristics
		align   uint32 // raw-data file alignment (bytes, power of two)
		rawSize uint32 // bytes of raw data (0 for BSS)
		bssSize uint32 // uninitialized-data byte count (SizeOfRawData for BSS)
	}
	meta := make([]secMeta, nSec)
	for i, s := range f.sections {
		switch s.Kind {
		case enc.SectionText:
			meta[i] = secMeta{
				chars:   scnCntCode | scnMemExec | scnMemRead | scnAlign16,
				align:   16,
				rawSize: uint32(len(s.Code)),
			}
		case enc.SectionData:
			meta[i] = secMeta{
				chars:   scnCntInitDat | scnMemRead | scnMemWrite | scnAlign8,
				align:   8,
				rawSize: uint32(len(s.Code)),
			}
		case enc.SectionROData:
			meta[i] = secMeta{
				chars:   scnCntInitDat | scnMemRead | scnAlign8,
				align:   8,
				rawSize: uint32(len(s.Code)),
			}
		case enc.SectionBSS:
			meta[i] = secMeta{
				chars:   scnCntUninit | scnMemRead | scnMemWrite | scnAlign8,
				align:   8,
				rawSize: 0,
				bssSize: uint32(s.Size),
			}
		}
	}

	// ── Phase 3: symbol table ─────────────────────────────────────────────
	//
	// Symbol ordering:
	//   [0 .. nSec-1]   STB_STATIC section symbols, one per section
	//   [nSec ..]       IMAGE_SYM_CLASS_EXTERNAL for exported sections
	//   [after that]    IMAGE_SYM_CLASS_EXTERNAL / undefined for external targets

	symIdx := make(map[string]uint32, nSec*2)
	var syms []coffSym

	// Section symbols (local)
	for i, s := range f.sections {
		symIdx[s.Name] = uint32(len(syms))
		syms = append(syms, coffSym{
			Name:          encodeSymName(s.Name, strtab),
			Value:         0,
			SectionNumber: int16(i + 1), // 1-based
			Type:          symTypeNull,
			StorageClass:  symClassStatic,
		})
	}

	// Exported (global) symbols
	for i, s := range f.sections {
		if !s.Exported {
			continue
		}
		t := symTypeNull
		if s.Kind == enc.SectionText {
			t = symTypeFunc
		}
		symIdx[s.Name] = uint32(len(syms)) // global overrides section symbol
		syms = append(syms, coffSym{
			Name:          encodeSymName(s.Name, strtab),
			Value:         0,
			SectionNumber: int16(i + 1),
			Type:          t,
			StorageClass:  symClassExternal,
		})
	}

	// Undefined external symbols (relocation targets not defined locally)
	for _, name := range externalSymbols(f.sections) {
		symIdx[name] = uint32(len(syms))
		syms = append(syms, coffSym{
			Name:          encodeSymName(name, strtab),
			Value:         0,
			SectionNumber: symUndefined,
			Type:          symTypeNull,
			StorageClass:  symClassExternal,
		})
	}

	// ── Phase 4: build relocation records and validate types ──────────────

	type secRelocs struct {
		records []coffReloc
		rtypes  []uint16 // parallel to records; needed for addend-size lookup
	}
	secRel := make([]secRelocs, nSec)

	for i, s := range f.sections {
		if len(s.Relocs) == 0 {
			continue
		}
		recs := make([]coffReloc, 0, len(s.Relocs))
		rtyps := make([]uint16, 0, len(s.Relocs))
		for _, r := range s.Relocs {
			si, ok := symIdx[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("coff: section %q: relocation symbol %q not in symbol table",
					s.Name, r.Symbol)
			}
			rt, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("coff: section %q: %w", s.Name, err)
			}
			recs = append(recs, coffReloc{
				VirtualAddress:   r.Offset,
				SymbolTableIndex: si,
				Type:             rt,
			})
			rtyps = append(rtyps, rt)
		}
		secRel[i] = secRelocs{records: recs, rtypes: rtyps}
	}

	// ── Phase 5: file-offset layout ───────────────────────────────────────
	//
	// The COFF file header (20 bytes) and all section headers (N×40 bytes)
	// are contiguous at the start of the file.  Section data follows.
	// Relocations are placed inline after each section's raw bytes.
	// The symbol table and string table come last.

	headerEnd := uint32(coffFileHdrSize + nSec*coffSecHdrSize)

	type secLayout struct {
		rawOff   uint32 // file offset of raw data (0 for BSS)
		relocOff uint32 // file offset of first reloc record (0 if none)
		nRelocs  uint16
	}
	layout := make([]secLayout, nSec)

	pos := headerEnd
	for i, s := range f.sections {
		if s.Kind == enc.SectionBSS {
			// BSS sections occupy no file bytes; both offsets stay zero.
			continue
		}
		pos = alignUp(pos, meta[i].align)
		layout[i].rawOff = pos
		pos += meta[i].rawSize

		nr := len(secRel[i].records)
		if nr > 0 {
			if nr > 0xFFFF {
				return nil, fmt.Errorf("coff: section %q: too many relocations (%d > 65535)",
					s.Name, nr)
			}
			layout[i].relocOff = pos
			layout[i].nRelocs = uint16(nr)
			pos += uint32(nr) * coffRelocSize
		}
	}

	symTabOff := pos // symbol table immediately after last section+relocs
	strTabOff := symTabOff + uint32(len(syms))*coffSymSize
	_ = strTabOff // implicit; the writer appends strtab.bytes() at the end

	// ── Phase 6: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)
	out.Grow(int(symTabOff) + len(syms)*coffSymSize + 64) // pre-allocate

	// COFF File Header
	fhdr := coffFileHdr{
		Machine:              f.machine,
		NumberOfSections:     uint16(nSec),
		TimeDateStamp:        0, // zero for reproducible output
		PointerToSymbolTable: symTabOff,
		NumberOfSymbols:      uint32(len(syms)),
		SizeOfOptionalHeader: 0,
		Characteristics:      0,
	}
	if err := binary.Write(out, le, fhdr); err != nil {
		return nil, fmt.Errorf("coff: write file header: %w", err)
	}

	// Section headers
	for i, s := range f.sections {
		var sh coffSecHdr
		setSectionName(&sh.Name, s.Name, strtab)
		sh.Characteristics = meta[i].chars
		if s.Kind == enc.SectionBSS {
			// BSS: SizeOfRawData = uninitialized size, PointerToRawData = 0
			sh.SizeOfRawData = meta[i].bssSize
		} else {
			sh.SizeOfRawData = meta[i].rawSize
			sh.PointerToRawData = layout[i].rawOff
		}
		sh.PointerToRelocations = layout[i].relocOff
		sh.NumberOfRelocations = layout[i].nRelocs
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("coff: write section header %d (%s): %w", i, s.Name, err)
		}
	}

	// Section data + inline relocation tables
	for i, s := range f.sections {
		if s.Kind == enc.SectionBSS {
			continue
		}
		padTo(out, layout[i].rawOff)

		// Bake implicit addends into a scratch copy of Code.
		code := applyImplicitAddends(s.Code, s.Relocs, secRel[i].rtypes)
		out.Write(code)

		for _, r := range secRel[i].records {
			if err := binary.Write(out, le, r); err != nil {
				return nil, fmt.Errorf("coff: write reloc for section %s: %w", s.Name, err)
			}
		}
	}

	// Symbol table
	padTo(out, symTabOff)
	for _, sym := range syms {
		if err := binary.Write(out, le, sym); err != nil {
			return nil, fmt.Errorf("coff: write symbol %q: %w",
				string(bytes.TrimRight(sym.Name[:], "\x00")), err)
		}
	}

	// String table (always present; minimum is 4-byte size-only block)
	out.Write(strtab.bytes())

	return out.Bytes(), nil
}