package object

// SectionKind describes a section's role. Each format package maps these
// to its own section names and flags.
type SectionKind uint8

const (
	SectionText      SectionKind = iota // executable code
	SectionData                         // mutable initialized data
	SectionROData                       // read-only data
	SectionBSS                          // zero-initialized; no file bytes emitted
	SectionUnwind                       // unwind tables
	SectionInitArray                    // constructor pointer array
	SectionFiniArray                    // destructor pointer array
	SectionTLS                          // thread-local data
	SectionCustom                       // platform-specific; name in Section.Custom
)

// SectionFlags carries linkage attributes that apply across all formats.
type SectionFlags uint32

const (
	// FlagLinkOnce emits a COMDAT (ELF/COFF) or weak-def (Mach-O) group
	// keyed on the section's first global symbol.
	FlagLinkOnce SectionFlags = 1 << iota

	// FlagNoDeadStrip inhibits linker dead-stripping. Silently ignored on
	// ELF and COFF targets.
	FlagNoDeadStrip
)

// Section is a single, finished unit of content.
type Section struct {
	Kind    SectionKind
	Custom  string  // non-empty only when Kind == SectionCustom
	Align   uint32  // alignment in bytes; 0 = format default for Kind
	Code    []byte  // raw bytes; nil or empty for BSS and zero-fill sections
	VSize   uint64  // virtual size; for BSS may exceed len(Code); 0 = len(Code)
	Symbols []Symbol
	Relocs  []Reloc
	Flags   SectionFlags
}