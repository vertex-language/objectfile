// Package macho produces Mach-O relocatable object files (MH_OBJECT) from
// object.Section values.
//
// Two 64-bit architectures are supported:
//
//	object.TargetDarwinAMD64 → cpu_type CPU_TYPE_X86_64  (0x01000007)
//	object.TargetDarwinARM64 → cpu_type CPU_TYPE_ARM64   (0x0100000C)
//
// Both produce 64-bit Mach-O (MH_MAGIC_64 = 0xFEEDFACF), little-endian.
//
// MH_OBJECT file layout produced:
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
//	│ section raw bytes  (aligned per section)     │
//	│ (zerofill sections have no file bytes)       │
//	├──────────────────────────────────────────────┤
//	│ relocation_info[]  (8 bytes each)            │
//	├──────────────────────────────────────────────┤
//	│ nlist_64[]         (16 bytes each)           │
//	├──────────────────────────────────────────────┤
//	│ string table       (null-terminated strings) │
//	└──────────────────────────────────────────────┘
//
// Addend convention (implicit addends):
//   Mach-O stores no addend in the relocation record.  Instead the linker
//   reads the addend from the instruction bytes at r_address.  build()
//   writes Reloc.Addend into Code[r.Offset:] before emitting each section,
//   and records zero in the relocation record.
//
// r_extern convention:
//   BindingLocal target  → r_extern=0, r_symbolnum = 1-based section index.
//   BindingGlobal/Weak or undefined → r_extern=1, r_symbolnum = nlist index.
package macho

import (
	"bytes"
	"io"

	"github.com/vertex-language/objectfile/object"
)

// ── CPU / magic constants ─────────────────────────────────────────────────────

const (
	mhMagic64 uint32 = 0xFEEDFACF // MH_MAGIC_64 (little-endian host)

	cpuTypeX86_64 int32 = 0x01000007 // CPU_TYPE_X86_64
	cpuTypeARM64  int32 = 0x0100000C // CPU_TYPE_ARM64

	cpuSubtypeAll int32 = 0x00000000 // CPU_SUBTYPE_ALL / CPU_SUBTYPE_ARM64_ALL

	mhObject                uint32 = 0x1    // MH_OBJECT
	mhSubsectionsViaSymbols uint32 = 0x2000 // MH_SUBSECTIONS_VIA_SYMBOLS
)

// ── Platform constants for LC_BUILD_VERSION ───────────────────────────────────

// Platform identifies the Darwin platform for LC_BUILD_VERSION.
type Platform uint32

const (
	MacOS    Platform = 1  // PLATFORM_MACOS
	IOS      Platform = 2  // PLATFORM_IOS
	TVOS     Platform = 3  // PLATFORM_TVOS
	WatchOS  Platform = 4  // PLATFORM_WATCHOS
	VisionOS Platform = 11 // PLATFORM_VISIONOS
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates object.Section values and serialises them into a complete
// Mach-O relocatable object file (MH_OBJECT).
//
// Implements object.Builder.
//
// Typical usage:
//
//	f := macho.NewFile(object.TargetDarwinARM64)
//	f.SetMinOS(macho.MacOS, 14, 0)
//	for _, s := range sections {
//	    f.AddSection(s)
//	}
//	b, err := f.Serialize()
type File struct {
	target     object.Target
	cpuType    int32
	cpuSubtype int32
	sections   []object.Section

	// LC_BUILD_VERSION (optional)
	buildVersion bool
	bvPlatform   Platform
	bvMinOS      uint32 // packed X.Y.Z as (X<<16)|(Y<<8)|Z
	bvSDK        uint32 // same packing; set equal to bvMinOS for .o files

	codesignReserve bool
}

// compile-time Builder conformance check.
var _ object.Builder = (*File)(nil)

// NewFile returns a Mach-O File configured for the given compilation target.
//
// Supported targets: object.TargetDarwinAMD64, object.TargetDarwinARM64.
func NewFile(target object.Target) *File {
	f := &File{target: target, cpuSubtype: cpuSubtypeAll}
	switch target.Arch {
	case object.ArchARM64:
		f.cpuType = cpuTypeARM64
	default:
		f.cpuType = cpuTypeX86_64
	}
	return f
}

// SetMinOS configures LC_BUILD_VERSION.  Call before the first AddSection.
//
//	f.SetMinOS(macho.MacOS, 14, 0)   // macOS 14.0
func (f *File) SetMinOS(platform Platform, major, minor uint8) {
	f.buildVersion = true
	f.bvPlatform = platform
	f.bvMinOS = (uint32(major) << 16) | (uint32(minor) << 8)
	f.bvSDK = f.bvMinOS // SDK == minOS is accepted by ld for relocatable objects
}

// EnableCodesignReserve reserves space in __LINKEDIT for an ad-hoc codesign
// signature so that codesign(1) can attach without a full re-link (default: false).
func (f *File) EnableCodesignReserve(on bool) { f.codesignReserve = on }

// AddSection ingests one object.Section in declaration order.
func (f *File) AddSection(s object.Section) { f.sections = append(f.sections, s) }

// Serialize assembles all accumulated sections into a complete Mach-O object
// file and returns the raw bytes.  Safe to call more than once.
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