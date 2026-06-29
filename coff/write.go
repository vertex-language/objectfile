// write.go — COFF object-file serialisation.
package coff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/vertex-language/objectfile/object"
)

// ── Structure size constants ──────────────────────────────────────────────────

const (
	coffFileHdrSize = 20 // IMAGE_FILE_HEADER
	coffSecHdrSize  = 40 // IMAGE_SECTION_HEADER
	coffSymSize     = 18 // IMAGE_SYMBOL / auxiliary record (same fixed size)
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
// VirtualSize and VirtualAddress are 0 for all object-file sections.
// For BSS and zero-TLS, SizeOfRawData carries the virtual reserve size and
// PointerToRawData is 0.
type coffSecHdr struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16 // deprecated; always 0
	Characteristics      uint32
}

// coffReloc is the 10-byte relocation record (IMAGE_RELOCATION).
// COFF uses implicit addends: the linker reads the addend from the bytes at
// VirtualAddress inside the section.
type coffReloc struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// coffSym is the 18-byte symbol table entry (IMAGE_SYMBOL).
type coffSym struct {
	Name                     [8]byte
	Value                    uint32
	SectionNumber            int16
	Type                     uint16
	StorageClass             uint8
	NumberOfAuxiliarySymbols uint8
}

// ── Section-characteristics constants ────────────────────────────────────────

const (
	scnCntCode    uint32 = 0x00000020 // IMAGE_SCN_CNT_CODE
	scnCntInitDat uint32 = 0x00000040 // IMAGE_SCN_CNT_INITIALIZED_DATA
	scnCntUninit  uint32 = 0x00000080 // IMAGE_SCN_CNT_UNINITIALIZED_DATA
	scnLnkInfo    uint32 = 0x00000200 // IMAGE_SCN_LNK_INFO  (for .drectve)
	scnLnkRemove  uint32 = 0x00000800 // IMAGE_SCN_LNK_REMOVE (for .drectve)
	scnLnkCOMDAT  uint32 = 0x00001000 // IMAGE_SCN_LNK_COMDAT
	scnMemExec    uint32 = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
	scnMemRead    uint32 = 0x40000000 // IMAGE_SCN_MEM_READ
	scnMemWrite   uint32 = 0x80000000 // IMAGE_SCN_MEM_WRITE
)

// ── Symbol constants ──────────────────────────────────────────────────────────

const (
	symClassExternal uint8 = 2 // IMAGE_SYM_CLASS_EXTERNAL
	symClassStatic   uint8 = 3 // IMAGE_SYM_CLASS_STATIC

	symTypeNull uint16 = 0x0000 // no type info
	symTypeFunc uint16 = 0x0020 // DT_FUNCTION<<4 | T_NULL

	symSectionUndef int16 = 0 // undefined / external
)

// COMDAT selection: IMAGE_COMDAT_SELECT_ANY — linker keeps any one definition.
const comdatSelectAny uint8 = 2

// ── Relocation type constants ─────────────────────────────────────────────────

// AMD64 (IMAGE_REL_AMD64_*)
const (
	relAMD64Addr64   uint16 = 0x0001 // 64-bit VA
	relAMD64Addr32   uint16 = 0x0002 // 32-bit VA
	relAMD64Addr32NB uint16 = 0x0003 // 32-bit image-relative (IAT)
	relAMD64Rel32    uint16 = 0x0004 // 32-bit PC-relative
	relAMD64Secrel   uint16 = 0x000B // 32-bit section-relative (TLS IE)
)

// ARM64 (IMAGE_REL_ARM64_*)
const (
	relARM64Addr32   uint16 = 0x0001 // 32-bit VA
	relARM64Addr32NB uint16 = 0x0002 // 32-bit image-relative (IAT)
	relARM64Branch26 uint16 = 0x0003 // 26-bit PC-relative B/BL
	relARM64Secrel   uint16 = 0x0008 // 32-bit section-relative (TLS IE)
	relARM64Addr64   uint16 = 0x000E // 64-bit VA
)

// ── Relocation-kind translation ───────────────────────────────────────────────

func (f *File) relocType(k object.RelocKind) (uint16, error) {
	switch f.machine {
	case machineAMD64:
		switch k {
		case object.RelocAbs64:
			return relAMD64Addr64, nil
		case object.RelocAbs32:
			return relAMD64Addr32, nil
		case object.RelocPCRel32, object.RelocPLT32:
			return relAMD64Rel32, nil
		case object.RelocIAT:
			return relAMD64Addr32NB, nil
		case object.RelocAddr32NB:
			return relAMD64Addr32NB, nil
		case object.RelocTLSIE:
			return relAMD64Secrel, nil
		}
	case machineARM64:
		switch k {
		case object.RelocAbs64:
			return relARM64Addr64, nil
		case object.RelocAbs32:
			return relARM64Addr32, nil
		case object.RelocPCRel26, object.RelocPLT32:
			return relARM64Branch26, nil
		case object.RelocIAT:
			return relARM64Addr32NB, nil
		case object.RelocAddr32NB:
			return relARM64Addr32NB, nil
		case object.RelocTLSIE:
			return relARM64Secrel, nil
		}
	}
	return 0, fmt.Errorf("relocation kind %v is not supported for machine 0x%04X", k, f.machine)
}

// relocAddendSize returns the byte width of the implicit-addend field.
// Only 64-bit absolute relocations use an 8-byte field; everything else uses 4.
func relocAddendSize(t uint16) int {
	if t == relAMD64Addr64 || t == relARM64Addr64 {
		return 8
	}
	return 4
}

// ── Section naming ────────────────────────────────────────────────────────────

// sectionCOFFName returns the COFF section header name for s.
//
// For COMDAT sections (FlagLinkOnce) the first BindingGlobal symbol's name is
// used directly as the section name so the linker can match definitions across
// translation units by name (the standard MSVC COMDAT convention).
func sectionCOFFName(s object.Section) string {
	if s.Flags&object.FlagLinkOnce != 0 {
		if key := firstGlobalName(s); key != "" {
			return key
		}
	}
	return sectionBaseName(s)
}

func sectionBaseName(s object.Section) string {
	switch s.Kind {
	case object.SectionText:
		return ".text"
	case object.SectionData:
		return ".data"
	case object.SectionROData:
		return ".rdata"
	case object.SectionBSS:
		return ".bss"
	case object.SectionUnwind:
		// SectionUnwind maps to .pdata. Callers that also need .xdata should
		// supply it as a separate SectionCustom section named ".xdata".
		return ".pdata"
	case object.SectionInitArray:
		return ".CRT$XCU"
	case object.SectionFiniArray:
		return ".CRT$XTZ"
	case object.SectionTLS:
		if len(s.Code) > 0 {
			return ".tls"
		}
		return ".tls$ZZZ"
	case object.SectionCustom:
		return s.Custom
	default:
		return ".data"
	}
}

func firstGlobalName(s object.Section) string {
	for _, sym := range s.Symbols {
		if sym.Binding == object.BindingGlobal {
			return sym.Name
		}
	}
	return ""
}

// ── Section characteristics ───────────────────────────────────────────────────

// effectiveAlign returns the alignment to use for s, applying a kind-specific
// default when s.Align is zero.
func effectiveAlign(s object.Section) uint32 {
	if s.Align > 0 {
		return s.Align
	}
	switch s.Kind {
	case object.SectionText:
		return 16
	case object.SectionUnwind:
		return 4
	case object.SectionCustom:
		return 1
	default:
		return 8
	}
}

// alignFlag encodes an alignment value as IMAGE_SCN_ALIGN_* bits (bits 20–23).
// align must be a power of two in [1, 8192]; values outside this range are
// clamped.
func alignFlag(align uint32) uint32 {
	if align == 0 {
		align = 1
	}
	if align > 8192 {
		align = 8192
	}
	shift := uint32(0)
	for a := align; a > 1; a >>= 1 {
		shift++
	}
	return (shift + 1) << 20
}

// sectionChars returns the Characteristics value for s.
func sectionChars(s object.Section, align uint32) uint32 {
	var base uint32
	switch s.Kind {
	case object.SectionText:
		base = scnCntCode | scnMemExec | scnMemRead
	case object.SectionData:
		base = scnCntInitDat | scnMemRead | scnMemWrite
	case object.SectionROData:
		base = scnCntInitDat | scnMemRead
	case object.SectionBSS:
		base = scnCntUninit | scnMemRead | scnMemWrite
	case object.SectionUnwind:
		base = scnCntInitDat | scnMemRead
	case object.SectionInitArray, object.SectionFiniArray:
		base = scnCntInitDat | scnMemRead | scnMemWrite
	case object.SectionTLS:
		if len(s.Code) > 0 {
			base = scnCntInitDat | scnMemRead | scnMemWrite
		} else {
			// Zero-fill TLS (.tls$ZZZ): uninitialized, size in SizeOfRawData.
			base = scnCntUninit | scnMemRead | scnMemWrite
		}
	default: // SectionCustom and unknown kinds
		base = scnCntInitDat | scnMemRead | scnMemWrite
	}
	if s.Flags&object.FlagLinkOnce != 0 {
		base |= scnLnkCOMDAT
	}
	base |= alignFlag(align)
	return base
}

// isBSSLike reports whether s emits no raw bytes to the file (BSS or zero TLS).
func isBSSLike(s object.Section) bool {
	return s.Kind == object.SectionBSS ||
		(s.Kind == object.SectionTLS && len(s.Code) == 0)
}

// virtualReserveSize returns the uninitialized-data size for a BSS-like
// section: s.VSize if set, otherwise len(s.Code).
func virtualReserveSize(s object.Section) uint32 {
	if s.VSize > 0 {
		return uint32(s.VSize)
	}
	return uint32(len(s.Code))
}

// ── Name-encoding helpers ─────────────────────────────────────────────────────

// setSectionName encodes a section name into the 8-byte header field.
// Names ≤ 8 bytes are stored inline (null-padded).
// Names > 8 bytes use the "/" + decimal-offset convention; the offset is from
// the start of the string table (including the 4-byte size prefix).
func setSectionName(field *[8]byte, name string, st *strTab) {
	if len(name) <= 8 {
		copy(field[:], name)
		return
	}
	off := st.intern(name) + 4 // +4 for the size prefix
	copy(field[:], fmt.Sprintf("/%d", off))
}

// encodeSymName encodes a symbol name into the 8-byte IMAGE_SYMBOL Name field.
// Names ≤ 8 bytes are stored inline (null-padded).
// Names > 8 bytes: first 4 bytes = \x00\x00\x00\x00, next 4 bytes =
// little-endian offset from the start of the string table (including prefix).
func encodeSymName(name string, st *strTab) [8]byte {
	var b [8]byte
	if len(name) <= 8 {
		copy(b[:], name)
		return b
	}
	off := st.intern(name) + 4 // +4 for the size prefix
	// b[0:4] stay zero — the "use string table" sentinel
	binary.LittleEndian.PutUint32(b[4:], off)
	return b
}

// ── Symbol-record encoding ────────────────────────────────────────────────────

// symEntry is a single 18-byte slot in the COFF symbol table.
// Both regular symbols and auxiliary records occupy one slot.
type symEntry struct {
	data [coffSymSize]byte
}

func encodeSymbol(s coffSym) [coffSymSize]byte {
	var b [coffSymSize]byte
	le := binary.LittleEndian
	copy(b[0:8], s.Name[:])
	le.PutUint32(b[8:], s.Value)
	le.PutUint16(b[12:], uint16(s.SectionNumber)) // two's-complement reinterpret
	le.PutUint16(b[14:], s.Type)
	b[16] = s.StorageClass
	b[17] = s.NumberOfAuxiliarySymbols
	return b
}

// encodeCOMDATAux builds the 18-byte auxiliary section record that must
// immediately follow the section symbol of a COMDAT section.
//
//	Offset  Size  Field
//	0       4     Length (SizeOfRawData)
//	4       2     NumberOfRelocations
//	6       2     NumberOfLinenumbers (0)
//	8       4     CheckSum (0 for SELECT_ANY)
//	12      2     Number (0 for SELECT_ANY)
//	14      1     Selection (IMAGE_COMDAT_SELECT_ANY = 2)
//	15      3     padding (0)
func encodeCOMDATAux(rawSize uint32, nRelocs uint16) [coffSymSize]byte {
	var b [coffSymSize]byte
	le := binary.LittleEndian
	le.PutUint32(b[0:], rawSize)
	le.PutUint16(b[4:], nRelocs)
	b[14] = comdatSelectAny
	return b
}

// ── Layout helpers ────────────────────────────────────────────────────────────

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
// Addend written into the appropriate bytes at r.Offset. The original slice
// is never modified. All writes are little-endian.
//
// The encoder speaks the ELF RELA convention, where the linker computes
// S + A - P, so a PC-relative site carries A = -(4 + trailing-imm-bytes).
// Conformant COFF instead defines REL32 as S + field - (P + 4): the +4 is
// intrinsic to the relocation type. To make a standards-compliant linker
// arrive at the same displacement, the implicit addend baked into the bytes
// for an AMD64 REL32 site must be A + 4. Without this the -4 is applied twice
// (once here, once by REL32's definition) and every call/RIP reference lands
// 4 bytes short.
//
// The bump is gated on machine because relAMD64Rel32 and relARM64PagebaseRel21
// share the value 0x0004; the ARM64 path uses addend 0 with an S+A-P patcher
// and must not be adjusted.
func applyImplicitAddends(code []byte, relocs []object.Reloc, rtypes []uint16, machine uint16) []byte {
	if len(relocs) == 0 {
		return code
	}
	patched := make([]byte, len(code))
	copy(patched, code)
	for i, r := range relocs {
		sz := relocAddendSize(rtypes[i])
		end := int(r.Offset) + sz
		if end > len(patched) {
			// Malformed offset; relocType validation in build() catches this first.
			continue
		}

		addend := r.Addend
		if machine == machineAMD64 && rtypes[i] == relAMD64Rel32 {
			addend += 4
		}

		switch sz {
		case 8:
			binary.LittleEndian.PutUint64(patched[r.Offset:], uint64(addend))
		default:
			binary.LittleEndian.PutUint32(patched[r.Offset:], uint32(int32(addend)))
		}
	}
	return patched
}

// ── External symbol discovery ─────────────────────────────────────────────────

// definedSymbolNames returns the set of all symbol names defined across all
// sections' Symbols slices.
func definedSymbolNames(sections []object.Section) map[string]bool {
	m := make(map[string]bool)
	for _, s := range sections {
		for _, sym := range s.Symbols {
			m[sym.Name] = true
		}
	}
	return m
}

// externalRefs returns a sorted, deduplicated list of symbol names referenced
// in any section's Relocs but not defined in any section's Symbols.
func externalRefs(sections []object.Section, defined map[string]bool) []string {
	seen := make(map[string]bool)
	for _, s := range sections {
		for _, r := range s.Relocs {
			if !defined[r.Symbol] {
				seen[r.Symbol] = true
			}
		}
	}
	refs := make([]string, 0, len(seen))
	for name := range seen {
		refs = append(refs, name)
	}
	sort.Strings(refs)
	return refs
}

// ── .drectve synthesis (DLLExport) ───────────────────────────────────────────

// drectveCharacteristics are the COFF section characteristics for .drectve.
// IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_ALIGN_1BYTES
const drectveCharacteristics uint32 = scnLnkInfo | scnLnkRemove | (1 << 20)

// buildDrectve returns a synthetic .drectve section for any DLLExport symbols
// found in sections, or nil if there are none.
func buildDrectve(sections []object.Section) *object.Section {
	var exports []string
	for _, s := range sections {
		for _, sym := range s.Symbols {
			if sym.DLLExport {
				exports = append(exports, sym.Name)
			}
		}
	}
	if len(exports) == 0 {
		return nil
	}
	var sb strings.Builder
	for _, name := range exports {
		sb.WriteString(" /EXPORT:")
		sb.WriteString(name)
	}
	return &object.Section{
		Kind:   object.SectionCustom,
		Custom: ".drectve",
		Align:  1,
		Code:   []byte(sb.String()),
	}
}

// ── Main serialisation ────────────────────────────────────────────────────────

func (f *File) build() ([]byte, error) {
	le := binary.LittleEndian

	// ── Phase 1: assemble section list ────────────────────────────────────
	// Append a synthetic .drectve section when DLLExport symbols are present.

	sections := f.sections
	if drec := buildDrectve(sections); drec != nil {
		sections = append(sections, *drec)
	}
	nSec := len(sections)
	if nSec > 0xFFFF {
		return nil, fmt.Errorf("coff: too many sections (%d > 65535)", nSec)
	}

	// Validate SectionCustom names.
	for i, s := range sections {
		if s.Kind == object.SectionCustom && s.Custom == "" {
			return nil, fmt.Errorf("coff: section %d: SectionCustom has empty Custom name", i)
		}
	}

	// ── Phase 2: per-section metadata ────────────────────────────────────

	type secMeta struct {
		name    string
		chars   uint32
		align   uint32
		rawSize uint32 // bytes written to file (0 for BSS-like sections)
		resSize uint32 // virtual reservation for BSS-like sections
		isBSS   bool   // true → no raw bytes; resSize goes in SizeOfRawData
		isDrv   bool   // true → .drectve; suppress section symbol
	}
	meta := make([]secMeta, nSec)
	for i, s := range sections {
		align := effectiveAlign(s)
		isBSS := isBSSLike(s)
		isDrv := s.Kind == object.SectionCustom && s.Custom == ".drectve"

		var chars uint32
		if isDrv {
			chars = drectveCharacteristics
		} else {
			chars = sectionChars(s, align)
		}

		var rawSize, resSize uint32
		if isBSS {
			resSize = virtualReserveSize(s)
		} else {
			rawSize = uint32(len(s.Code))
		}

		meta[i] = secMeta{
			name:    sectionCOFFName(s),
			chars:   chars,
			align:   align,
			rawSize: rawSize,
			resSize: resSize,
			isBSS:   isBSS,
			isDrv:   isDrv,
		}
	}

	// ── Phase 3: string table ─────────────────────────────────────────────
	// Pre-intern all long names so that every offset is stable before any
	// serialisation touches the table.

	st := newStrTab()
	defined := definedSymbolNames(sections)
	extRefs := externalRefs(sections, defined)

	for i, s := range sections {
		if len(meta[i].name) > 8 {
			st.intern(meta[i].name)
		}
		for _, sym := range s.Symbols {
			if len(sym.Name) > 8 {
				st.intern(sym.Name)
			}
		}
	}
	for _, name := range extRefs {
		if len(name) > 8 {
			st.intern(name)
		}
	}

	// ── Phase 4: symbol table ─────────────────────────────────────────────
	//
	// Slot layout (each slot = 18 bytes, auxiliary records count as slots):
	//
	//   [section symbols]
	//     For each section i:
	//       slot A: section symbol (IMAGE_SYM_CLASS_STATIC, Value=0)
	//       slot B: COMDAT aux record (only if FlagLinkOnce)
	//
	//   [defined symbols]
	//     For each section i, for each sym in s.Symbols:
	//       slot: IMAGE_SYM_CLASS_EXTERNAL (Global/Weak) or STATIC (Local)
	//
	//   [undefined externals] — sorted for determinism
	//     For each name in extRefs not already in symIdx:
	//       slot: IMAGE_SYM_CLASS_EXTERNAL, SectionNumber=0

	var symTable []symEntry
	symIdx := make(map[string]uint32) // name → slot index in symTable

	// 4a. Section symbols (one per section, + optional COMDAT aux slot).
	for i, s := range sections {
		isComdat := s.Flags&object.FlagLinkOnce != 0
		nAux := uint8(0)
		if isComdat {
			nAux = 1
		}
		secSym := coffSym{
			Name:                     encodeSymName(meta[i].name, st),
			Value:                    0,
			SectionNumber:            int16(i + 1),
			Type:                     symTypeNull,
			StorageClass:             symClassStatic,
			NumberOfAuxiliarySymbols: nAux,
		}
		symTable = append(symTable, symEntry{data: encodeSymbol(secSym)})
		if isComdat {
			nRelocs := uint16(len(s.Relocs))
			symTable = append(symTable, symEntry{
				data: encodeCOMDATAux(meta[i].rawSize, nRelocs),
			})
		}
	}

	// 4b. Defined symbols from each section's Symbols slice.
	for i, s := range sections {
		for _, sym := range s.Symbols {
			idx := uint32(len(symTable))
			symIdx[sym.Name] = idx

			sc := symClassStatic
			if sym.Binding == object.BindingGlobal || sym.Binding == object.BindingWeak {
				sc = symClassExternal
			}
			typ := symTypeNull
			if sym.Kind == object.SymFunc {
				typ = symTypeFunc
			}
			cs := coffSym{
				Name:          encodeSymName(sym.Name, st),
				Value:         sym.Offset,
				SectionNumber: int16(i + 1),
				Type:          typ,
				StorageClass:  sc,
			}
			symTable = append(symTable, symEntry{data: encodeSymbol(cs)})
		}
	}

	// 4c. Undefined externals.
	for _, name := range extRefs {
		if _, ok := symIdx[name]; ok {
			continue // already emitted as a defined symbol
		}
		idx := uint32(len(symTable))
		symIdx[name] = idx
		cs := coffSym{
			Name:          encodeSymName(name, st),
			Value:         0,
			SectionNumber: symSectionUndef,
			Type:          symTypeNull,
			StorageClass:  symClassExternal,
		}
		symTable = append(symTable, symEntry{data: encodeSymbol(cs)})
	}

	// ── Phase 5: relocation records ───────────────────────────────────────

	type secRelocs struct {
		records []coffReloc
		rtypes  []uint16 // parallel to records; drives addend-field size in phase 7
	}
	secRel := make([]secRelocs, nSec)

	for i, s := range sections {
		if len(s.Relocs) == 0 {
			continue
		}
		recs := make([]coffReloc, 0, len(s.Relocs))
		rtyps := make([]uint16, 0, len(s.Relocs))
		for _, r := range s.Relocs {
			si, ok := symIdx[r.Symbol]
			if !ok {
				return nil, fmt.Errorf("coff: section %q: relocation target %q has no symbol table entry",
					meta[i].name, r.Symbol)
			}
			rt, err := f.relocType(r.Kind)
			if err != nil {
				return nil, fmt.Errorf("coff: section %q: %w", meta[i].name, err)
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

	// ── Phase 6: file-offset layout ───────────────────────────────────────
	//
	// [ file header ][ section headers ][ raw data + relocs ... ][ sym table ][ strtab ]

	headerEnd := uint32(coffFileHdrSize + nSec*coffSecHdrSize)

	type secLayout struct {
		rawOff   uint32 // file offset of raw bytes (0 for BSS-like)
		relocOff uint32 // file offset of first reloc record (0 if none)
		nRelocs  uint16
	}
	layout := make([]secLayout, nSec)

	pos := headerEnd
	for i := range sections {
		if meta[i].isBSS {
			continue // BSS-like sections occupy no file bytes
		}
		pos = alignUp(pos, meta[i].align)
		layout[i].rawOff = pos
		pos += meta[i].rawSize

		nr := len(secRel[i].records)
		if nr > 0xFFFF {
			return nil, fmt.Errorf("coff: section %q: too many relocations (%d > 65535)",
				meta[i].name, nr)
		}
		if nr > 0 {
			layout[i].relocOff = pos
			layout[i].nRelocs = uint16(nr)
			pos += uint32(nr) * coffRelocSize
		}
	}

	symTabOff := pos

	// ── Phase 7: serialise ────────────────────────────────────────────────

	out := new(bytes.Buffer)
	out.Grow(int(symTabOff) + len(symTable)*coffSymSize + 64)

	// COFF file header
	if err := binary.Write(out, le, coffFileHdr{
		Machine:              f.machine,
		NumberOfSections:     uint16(nSec),
		TimeDateStamp:        0, // zero for reproducible output
		PointerToSymbolTable: symTabOff,
		NumberOfSymbols:      uint32(len(symTable)),
		SizeOfOptionalHeader: 0,
		Characteristics:      0,
	}); err != nil {
		return nil, fmt.Errorf("coff: write file header: %w", err)
	}

	// Section headers
	for i := range sections {
		var sh coffSecHdr
		setSectionName(&sh.Name, meta[i].name, st)
		sh.Characteristics = meta[i].chars
		if meta[i].isBSS {
			// SizeOfRawData carries the virtual reservation size; no raw bytes.
			sh.SizeOfRawData = meta[i].resSize
			sh.PointerToRawData = 0
		} else {
			sh.SizeOfRawData = meta[i].rawSize
			sh.PointerToRawData = layout[i].rawOff
		}
		sh.PointerToRelocations = layout[i].relocOff
		sh.NumberOfRelocations = layout[i].nRelocs
		if err := binary.Write(out, le, sh); err != nil {
			return nil, fmt.Errorf("coff: write section header %d (%s): %w",
				i, meta[i].name, err)
		}
	}

	// Section raw data + inline relocation tables
	for i, s := range sections {
		if meta[i].isBSS {
			continue
		}
		padTo(out, layout[i].rawOff)

		// Bake implicit addends into a scratch copy of Code before writing.
		code := applyImplicitAddends(s.Code, s.Relocs, secRel[i].rtypes, f.machine)
		out.Write(code)

		for _, r := range secRel[i].records {
			if err := binary.Write(out, le, r); err != nil {
				return nil, fmt.Errorf("coff: write reloc for section %s: %w",
					meta[i].name, err)
			}
		}
	}

	// Symbol table
	padTo(out, symTabOff)
	for _, entry := range symTable {
		out.Write(entry.data[:])
	}

	// String table (always present; minimum is 4-byte size-only block)
	out.Write(st.bytes())

	return out.Bytes(), nil
}