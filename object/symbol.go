package object

// Binding controls symbol visibility in the output object's symbol table.
type Binding uint8

const (
	BindingLocal  Binding = iota // file-scoped; not exported to the linker
	BindingGlobal                // exported; linker resolves cross-object references
	BindingWeak                  // exported with weak precedence
)

// SymbolKind distinguishes code from data symbols.
type SymbolKind uint8

const (
	SymFunc    SymbolKind = iota // function entry point
	SymData                      // data object
	SymSection                   // anonymous section-relative label; Binding must be Local
)

// Symbol defines a named point within a Section.
type Symbol struct {
	Name      string
	Offset    uint32
	Size      uint32
	Binding   Binding
	Kind      SymbolKind
	DLLExport bool // COFF only; silently ignored on ELF and Mach-O
}