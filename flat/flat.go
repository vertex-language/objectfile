// Package flat produces raw binary images by concatenating text and data
// sections in declaration order with no header, symbol table, or relocation
// records.
//
// All relocations must be resolved before sections are added, as this
// format does not support external symbol references or link-time
// resolution.
package flat

import (
	"bytes"
	"io"

	enc "github.com/vertex-language/encoder"
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates encoder.Section values and serialises them into a raw
// binary image.
//
// Typical usage:
//
//	f := flat.NewObjectFile()
//	for _, s := range sections {
//	    f.AddSection(s)
//	}
//	b, err := f.Serialize() // raw bytes, no header
type File struct {
	sections []enc.Section
}

// NewObjectFile returns a flat File. It takes no target argument since there 
// is nothing to dispatch on for a raw binary dump.
func NewObjectFile() *File {
	return &File{}
}

// AddSection ingests one encoder.Section in declaration order.
func (f *File) AddSection(s enc.Section) {
	f.sections = append(f.sections, s)
}

// Serialize concatenates the accumulated sections into a raw binary blob
// and returns the raw bytes. Safe to call more than once; each call
// re-serialises from the accumulated state.
func (f *File) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteTo is the io.WriterTo form of Serialize. It only writes SectionText
// and SectionData sections, as the flat format expects no BSS allocation 
// bytes and ignores read-only data blocks typical of linked formats.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, s := range f.sections {
		// Only text and data sections are concatenated into the raw binary.
		if s.Kind == enc.SectionText || s.Kind == enc.SectionData {
			n, err := w.Write(s.Code)
			total += int64(n)
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}