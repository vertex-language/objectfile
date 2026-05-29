// strtab.go — ELF null-terminated string table builder.
package elf

// strTab accumulates null-terminated strings for an ELF SHT_STRTAB section.
//
// Index 0 is always a null byte, so the empty string always maps to offset 0
// and the first byte of the table is the standard null-name sentinel.
type strTab struct {
	data    []byte
	offsets map[string]uint32
}

func newStrTab() *strTab {
	return &strTab{
		data:    []byte{0},
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
	t.data = append(t.data, 0) // null terminator
	t.offsets[s] = off
	return off
}

// bytes returns the underlying slice (not a copy).
// The caller must not intern further strings after capturing this reference.
func (t *strTab) bytes() []byte { return t.data }