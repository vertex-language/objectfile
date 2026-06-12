// strtab.go — COFF string table builder.
//
// The COFF string table sits immediately after the symbol table. Its first
// four bytes are a little-endian uint32 giving the total byte count of the
// table *including* those four bytes. Entries are null-terminated strings
// concatenated directly.
//
// Symbol records: short names (≤ 8 bytes) are stored inline, null-padded, in
// the 8-byte Name field. Long names store \x00\x00\x00\x00 in the first four
// bytes followed by a uint32 byte offset measured from the start of the
// string table (i.e. including the 4-byte size prefix).
//
// Section headers: long section names use the "/" + decimal-offset convention
// defined by the COFF spec for object files.
package coff

import "encoding/binary"

type strTab struct {
	data    []byte
	offsets map[string]uint32
}

func newStrTab() *strTab {
	return &strTab{offsets: make(map[string]uint32)}
}

// intern adds s to the table if absent and returns its byte offset within the
// payload slice (not counting the 4-byte size prefix). Callers that need the
// spec-defined offset (from the start of the string table, which includes the
// prefix) must add 4 to the returned value.
func (t *strTab) intern(s string) uint32 {
	if off, ok := t.offsets[s]; ok {
		return off
	}
	off := uint32(len(t.data))
	t.data = append(t.data, s...)
	t.data = append(t.data, 0) // null terminator
	t.offsets[s] = off
	return off
}

// bytes returns the complete, serialised string table including the 4-byte
// size prefix. Do not call intern after capturing this slice.
func (t *strTab) bytes() []byte {
	size := uint32(4 + len(t.data))
	out := make([]byte, 4, size)
	binary.LittleEndian.PutUint32(out, size)
	return append(out, t.data...)
}