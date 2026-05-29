// strtab.go — Mach-O string table builder.
//
// The Mach-O string table is a flat sequence of null-terminated strings.
// Index 0 is always a single null byte (the empty / no-name sentinel).
// nlist_64.n_strx holds a byte offset from the start of the table.
package macho

// strTab accumulates null-terminated strings for the LC_SYMTAB string table.
type strTab struct {
	data    []byte
	offsets map[string]uint32
}

func newStrTab() *strTab {
	return &strTab{
		data:    []byte{0}, // byte 0 = null sentinel
		offsets: map[string]uint32{"": 0},
	}
}

// intern returns the byte offset of s within the table, adding it if absent.
func (t *strTab) intern(s string) uint32 {
	if off, ok := t.offsets[s]; ok {
		return off
	}
	off := uint32(len(t.data))
	t.data = append(t.data, s...)
	t.data = append(t.data, 0)
	t.offsets[s] = off
	return off
}

// bytes returns the underlying slice (not a copy).
func (t *strTab) bytes() []byte { return t.data }