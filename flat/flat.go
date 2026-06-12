// Package flat produces raw binary images by concatenating sections in
// declaration order with no header, symbol table, or relocation records.
//
// All symbol references must be pre-resolved before sections are added;
// Serialize returns an error if any section's Relocs slice is non-empty.
//
// Symbols are accepted by AddSection but silently discarded — no symbol
// table is emitted.
//
// SectionBSS sections emit VSize zero bytes into the output. Unlike ELF,
// COFF, and Mach-O, flat binary must be fully self-contained, so BSS cannot
// be represented as a header-only reservation.
//
// Each section's byte output is tail-padded with zeros to the next
// Section.Align boundary before the following section begins.
package flat

import (
	"bytes"
	"fmt"
	"io"

	"github.com/vertex-language/objectfile/object"
)

// File accumulates object.Section values and serialises them into a raw
// binary image. It implements object.Builder.
//
// Typical usage:
//
//	f := flat.NewFile()
//	f.SetBaseAddress(0x7C00)
//	f.AddSection(sec)
//	b, err := f.Serialize()
type File struct {
	base     uint64
	sections []object.Section
}

// NewFile returns a flat File with a base address of 0x0000.
func NewFile() *File { return &File{} }

// SetBaseAddress records the load address of the first output byte.
// Default is 0x0000. This is informational metadata — it does not alter the
// byte layout of the output, since all references must already be resolved in
// Code before AddSection is called.
func (f *File) SetBaseAddress(addr uint64) { f.base = addr }

// AddSection ingests one object.Section in declaration order.
// Symbols are accepted and silently discarded.
// Implements object.Builder.
func (f *File) AddSection(s object.Section) { f.sections = append(f.sections, s) }

// Serialize concatenates all accumulated sections into a raw binary blob and
// returns the raw bytes. Safe to call more than once; each call re-serialises
// from scratch. Returns an error if any section contains unresolved
// relocations.
// Implements object.Builder.
func (f *File) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteTo is the io.WriterTo form of Serialize.
// Implements object.Builder.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	// Validate upfront: relocations are not supported in flat binary.
	for i, s := range f.sections {
		if len(s.Relocs) > 0 {
			return 0, fmt.Errorf("flat: section %d: %d relocation(s) present; "+
				"all references must be pre-resolved in Code before adding sections",
				i, len(s.Relocs))
		}
	}

	var total int64
	for _, s := range f.sections {
		chunk := sectionChunk(s)
		if len(chunk) == 0 {
			continue
		}
		n, err := w.Write(chunk)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sectionChunk returns the complete byte representation of s for flat binary
// output, including alignment tail-padding.
//
// SectionBSS emits VSize zero bytes (self-contained; no header-only
// reservation). All other section kinds emit Code directly.
// The result is tail-padded with zeros to the next s.Align boundary.
func sectionChunk(s object.Section) []byte {
	var raw []byte
	if s.Kind == object.SectionBSS {
		if s.VSize == 0 {
			return nil
		}
		raw = make([]byte, s.VSize) // zero-initialised by Go runtime
	} else {
		if len(s.Code) == 0 {
			return nil
		}
		raw = s.Code
	}

	// Tail-pad to the alignment boundary.
	align := uint64(s.Align)
	if align <= 1 {
		return raw
	}
	size := uint64(len(raw))
	rem := size % align
	if rem == 0 {
		return raw
	}
	padded := make([]byte, size+align-rem) // zero-initialised by Go runtime
	copy(padded, raw)
	return padded
}