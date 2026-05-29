// Package elf produces ELF relocatable object files (ET_REL) from
// encoder.Section values.
//
// 64-bit ELFCLASS64 little-endian output is used for AMD64 (EM_X86_64 = 62)
// and AArch64 (EM_AARCH64 = 183). 32-bit ELFCLASS32 little-endian output
// is used for x86 (EM_386 = 3).
//
// All output uses Elf64_Rela / Elf32_Rela relocation sections (SHT_RELA)
// with explicit addends; the AMD64 ABI mandates this form.
package elf

import (
	"bytes"
	"io"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
)

// ── ELF identification constants ──────────────────────────────────────────────

// e_ident byte indices
const (
	eiClass   = 4
	eiData    = 5
	eiVersion = 6
	eiOSABI   = 7
)

// EI_CLASS values
const (
	elfClass32 = 1
	elfClass64 = 2
)

// EI_DATA: little-endian encoding (all supported targets are LE)
const elfData2LSB = 1

// EV_CURRENT
const evCurrent = 1

// e_type
const etRel = 1 // relocatable object

// e_machine
const (
	emI386    uint16 = 3
	emX86_64  uint16 = 62
	emAARCH64 uint16 = 183
)

// ── OSABI ─────────────────────────────────────────────────────────────────────

// OSABI identifies the operating system / ABI for which the object is
// prepared. It is written to e_ident[EI_OSABI].
type OSABI uint8

const (
	OSABI_None    OSABI = 0  // System V / unspecified (default)
	OSABI_Linux   OSABI = 3  // GNU / Linux
	OSABI_FreeBSD OSABI = 9  // FreeBSD
	OSABI_OpenBSD OSABI = 12 // OpenBSD
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates encoder.Section values and serialises them into a
// complete ELF relocatable object file (ET_REL).
//
// Typical usage:
//
//	f := elf.NewObjectFile(mir.TargetLinuxAMD64)
//	for _, s := range sections {
//	    f.AddSection(s)
//	}
//	b, err := f.Serialize()
type File struct {
	machine  uint16
	is64     bool
	osabi    OSABI
	dwarf    bool
	sections []enc.Section
}

// NewObjectFile returns an ELF File configured for the given compilation target.
//
// Supported targets:
//   - TargetLinuxAMD64  → EM_X86_64,  ELFCLASS64
//   - TargetLinuxARM64  → EM_AARCH64, ELFCLASS64
//   - TargetLinuxX86    → EM_386,     ELFCLASS32
func NewObjectFile(target mir.Target) *File {
	f := &File{osabi: OSABI_None}
	switch target {
	case mir.TargetLinuxAMD64:
		f.machine, f.is64 = emX86_64, true
	case mir.TargetLinuxARM64:
		f.machine, f.is64 = emAARCH64, true
	case mir.TargetLinuxX86:
		f.machine, f.is64 = emI386, false
	default:
		f.machine, f.is64 = emX86_64, true
	}
	return f
}

// SetOS overrides the EI_OSABI byte in the file header.
// The default is OSABI_None (System V / unspecified).
func (f *File) SetOS(o OSABI) { f.osabi = o }

// EnableDWARF controls emission of skeleton .debug_info / .debug_abbrev
// sections (default: false). When true, minimal placeholder sections are
// appended so downstream tooling can attach DWARF without re-linking.
// Full DWARF generation is a future extension.
func (f *File) EnableDWARF(on bool) { f.dwarf = on }

// AddSection ingests one encoder.Section in declaration order.
func (f *File) AddSection(s enc.Section) { f.sections = append(f.sections, s) }

// Serialize assembles all accumulated sections into a complete ELF object
// file and returns the raw bytes. Safe to call more than once; each call
// re-serialises the current state.
func (f *File) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteTo is the io.WriterTo form of Serialize.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	var (
		b   []byte
		err error
	)
	if f.is64 {
		b, err = f.build64()
	} else {
		b, err = f.build32()
	}
	if err != nil {
		return 0, err
	}
	n, werr := w.Write(b)
	return int64(n), werr
}