package object

import "io"

// Builder is the interface every format File implements.
// Format-specific options live on the concrete File type and must be
// configured before the first AddSection call.
type Builder interface {
	// AddSection appends one section in declaration order.
	AddSection(s Section)

	// Serialize assembles all accumulated sections into a complete relocatable
	// object file. Safe to call more than once.
	Serialize() ([]byte, error)

	// WriteTo is the io.WriterTo form of Serialize.
	WriteTo(w io.Writer) (int64, error)
}