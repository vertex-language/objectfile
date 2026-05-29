// Package macho produces Mach-O relocatable object files (MH_OBJECT) from
// encoder.Section values.
//
// Two 64-bit architectures are supported:
//
//	TargetDarwinAMD64 → cpu_type CPU_TYPE_X86_64  (0x01000007)
//	TargetDarwinARM64 → cpu_type CPU_TYPE_ARM64   (0x0100000C)
//
// Both produce 64-bit Mach-O (MH_MAGIC_64 = 0xFEEDFACF), little-endian.
//
// MH_OBJECT layout produced:
//
//	┌──────────────────────────────────────────────┐
//	│ mach_header_64          (32 bytes)           │
//	├──────────────────────────────────────────────┤
//	│ LC_SEGMENT_64           (72 + N×80 bytes)    │  one unnamed segment;
//	│   section_64[0..N-1]                         │  one entry per input section
//	├──────────────────────────────────────────────┤
//	│ LC_BUILD_VERSION        (24 bytes, optional) │  emitted when SetMinOS called
//	├──────────────────────────────────────────────┤
//	│ LC_SYMTAB               (24 bytes)           │
//	├──────────────────────────────────────────────┤
//	│ section raw bytes  (4- or 16-byte aligned)   │
//	│ (.bss sections have no file bytes)           │
//	├──────────────────────────────────────────────┤
//	│ relocation_info[]  (8 bytes each)            │  inline after each section's
//	│                                              │  data, one block per section
//	├──────────────────────────────────────────────┤
//	│ nlist_64[]         (16 bytes each)           │  symbol table
//	├──────────────────────────────────────────────┤
//	│ string table       (null-terminated strings) │
//	└──────────────────────────────────────────────┘
//
// Relocations
//
// Mach-O uses implicit addends stored in the instruction stream.  Serialize
// writes RelocEntry.Addend into Code[r.Offset:] (4 bytes for 32-bit kinds, 8
// bytes for RelocAbs64) before emitting the section, and records zero in the
// relocation records.  r_extern is always 1 for external symbols; section
// symbols use r_extern=0 with r_symbolnum holding the 1-based section index.
package macho

import (
	"bytes"
	"io"

	enc "github.com/vertex-language/encoder"
	"github.com/vertex-language/ir/mir"
)

// ── CPU / magic constants ─────────────────────────────────────────────────────

const (
	mhMagic64 uint32 = 0xFEEDFACF // MH_MAGIC_64 (little-endian host)

	cpuTypeX86_64  int32 = 0x01000007 // CPU_TYPE_X86_64
	cpuTypeARM64   int32 = 0x0100000C // CPU_TYPE_ARM64

	cpuSubtypeAll int32 = 0x00000000 // CPU_SUBTYPE_ALL / CPU_SUBTYPE_ARM64_ALL

	mhObject uint32 = 0x1 // MH_OBJECT

	// MH_SUBSECTIONS_VIA_SYMBOLS allows the linker to dead-strip individual
	// functions.  Clang/assembler always sets this on .o files.
	mhSubsectionsViaSymbols uint32 = 0x2000
)

// ── Platform constants for LC_BUILD_VERSION ───────────────────────────────────

// Platform identifies the Darwin platform for LC_BUILD_VERSION.
type Platform uint32

const (
	MacOS   Platform = 1 // PLATFORM_MACOS
	IOS     Platform = 2 // PLATFORM_IOS
	TVOS    Platform = 3 // PLATFORM_TVOS
	WatchOS Platform = 4 // PLATFORM_WATCHOS
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates encoder.Section values and serialises them into a
// complete Mach-O relocatable object file (MH_OBJECT).
//
// Typical usage:
//
//	f := macho.NewObjectFile(mir.TargetDarwinARM64)
//	for _, s := range sections {
//	    f.AddSection(s)
//	}
//	b, err := f.Serialize()
type File struct {
	cpuType    int32
	cpuSubtype int32
	sections   []enc.Section

	// LC_BUILD_VERSION (optional)
	buildVersion    bool
	bvPlatform      Platform
	bvMinOS         uint32 // packed X.Y.Z as (X<<16)|(Y<<8)|Z
	bvSDK           uint32 // same packing; 0 = "n/a"

	// Ad-hoc code-signing stub (optional; reserves __LINKEDIT space)
	codesignReserve bool
}

// NewObjectFile returns a Mach-O File configured for the given compilation target.
//
// Supported targets:
//   - TargetDarwinAMD64 → CPU_TYPE_X86_64
//   - TargetDarwinARM64 → CPU_TYPE_ARM64
func NewObjectFile(target mir.Target) *File {
	f := &File{cpuSubtype: cpuSubtypeAll}
	switch target {
	case mir.TargetDarwinARM64:
		f.cpuType = cpuTypeARM64
	default:
		f.cpuType = cpuTypeX86_64
	}
	return f
}

// SetMinOS configures LC_BUILD_VERSION.  Call before the first AddSection.
//
//	f.SetMinOS(macho.MacOS, 14, 0)   // macOS 14.0
//
// major, minor are the minimum OS version components (patch is set to 0).
// The SDK version is set equal to the minimum OS version; the linker accepts
// this for relocatable objects.
func (f *File) SetMinOS(platform Platform, major, minor uint8) {
	f.buildVersion = true
	f.bvPlatform = platform
	f.bvMinOS = (uint32(major) << 16) | (uint32(minor) << 8)
	f.bvSDK = f.bvMinOS // SDK == minOS for .o files; ld accepts this
}

// EnableCodesignReserve reserves 8 bytes of space in an otherwise-empty
// __LINKEDIT segment so that codesign(1) can attach an ad-hoc signature
// without requiring a full re-link (default: false).  Only relevant for
// Darwin ARM64 binaries that will be codesigned immediately after link.
func (f *File) EnableCodesignReserve(on bool) { f.codesignReserve = on }

// AddSection ingests one encoder.Section in declaration order.
func (f *File) AddSection(s enc.Section) { f.sections = append(f.sections, s) }

// Serialize assembles all accumulated sections into a complete Mach-O object
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
	b, err := f.build()
	if err != nil {
		return 0, err
	}
	n, werr := w.Write(b)
	return int64(n), werr
}