// Package coff produces COFF relocatable object files (raw .obj, no MS-DOS
// stub) from encoder.Section values.
//
// Supported targets:
//   - TargetWindowsAMD64 → IMAGE_FILE_MACHINE_AMD64 (0x8664)
//   - TargetWindowsARM64 → IMAGE_FILE_MACHINE_ARM64 (0xAA64)
//
// File layout
//
//	┌────────────────────────────────────┐
//	│ COFF File Header      (20 bytes)   │
//	├────────────────────────────────────┤
//	│ Section Headers   (N × 40 bytes)   │
//	├────────────────────────────────────┤
//	│ .text  raw bytes  (4-byte aligned) │
//	│ .text  relocs     (10 bytes each)  │
//	│ .data  raw bytes                   │
//	│ .data  relocs                      │
//	│  …                                 │
//	│ (.bss occupies no file bytes)      │
//	├────────────────────────────────────┤
//	│ Symbol table  (18 bytes × nSyms)   │
//	├────────────────────────────────────┤
//	│ String table  (4-byte size + data) │
//	└────────────────────────────────────┘
//
// Implicit addends
//
// COFF stores no addend field in its relocation records. Instead the linker
// reads the addend from the bytes at the relocation site. Serialize therefore
// writes RelocEntry.Addend into Code[r.Offset:] (4 bytes for 32-bit kinds, 8
// bytes for RelocAbs64) before emitting the section, and records zero in the
// relocation entry.
package coff

import (
	"bytes"
	"io"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
)

// ── Machine identifiers ───────────────────────────────────────────────────────

const (
	machineAMD64 uint16 = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	machineARM64 uint16 = 0xAA64 // IMAGE_FILE_MACHINE_ARM64
)

// ── Subsystem ─────────────────────────────────────────────────────────────────

// Subsystem identifies the intended Windows subsystem. It is informational on
// a COFF object file (object files have no Optional Header) but is recorded so
// callers that later produce an image can query it.
type Subsystem uint16

const (
	SubsystemUnknown Subsystem = 0  // IMAGE_SUBSYSTEM_UNKNOWN
	SubsystemNative  Subsystem = 1  // IMAGE_SUBSYSTEM_NATIVE
	SubsystemWindows Subsystem = 2  // IMAGE_SUBSYSTEM_WINDOWS_GUI
	SubsystemConsole Subsystem = 3  // IMAGE_SUBSYSTEM_WINDOWS_CUI (default)
	SubsystemEFI     Subsystem = 10 // IMAGE_SUBSYSTEM_EFI_APPLICATION
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates encoder.Section values and serialises them into a
// complete COFF relocatable object file.
//
// Typical usage:
//
//	f := coff.NewObjectFile(mir.TargetWindowsAMD64)
//	for _, s := range sections {
//	    f.AddSection(s)
//	}
//	b, err := f.Serialize()
type File struct {
	machine   uint16
	subsystem Subsystem
	sections  []enc.Section
}

// NewObjectFile returns a COFF File configured for the given compilation target.
// Any target other than TargetWindowsARM64 defaults to AMD64.
func NewObjectFile(target mir.Target) *File {
	f := &File{subsystem: SubsystemConsole}
	switch target {
	case mir.TargetWindowsARM64:
		f.machine = machineARM64
	default:
		f.machine = machineAMD64
	}
	return f
}

// SetSubsystem records the intended Windows subsystem (informational only for
// object files; not written into the .obj output).
func (f *File) SetSubsystem(s Subsystem) { f.subsystem = s }

// AddSection ingests one encoder.Section in declaration order.
func (f *File) AddSection(s enc.Section) { f.sections = append(f.sections, s) }

// Serialize assembles all accumulated sections into a complete COFF object
// file and returns the raw bytes. Safe to call more than once.
func (f *File) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteTo is the io.WriterTo form of Serialize.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	b, err := f.build()
	if err != nil {
		return 0, err
	}
	n, werr := w.Write(b)
	return int64(n), werr
}