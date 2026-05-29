# macho

Package `macho` produces Mach-O relocatable object files (`MH_OBJECT`) from
[`encoder.Section`](https://github.com/vertex-language/encoder) values.

```go
import "github.com/vertex-language/objectfile/macho"
```

## Supported targets

| Constant | Architecture | `cpu_type` |
|---|---|---|
| `mir.TargetDarwinAMD64` | x86-64 | `CPU_TYPE_X86_64` |
| `mir.TargetDarwinARM64` | AArch64 | `CPU_TYPE_ARM64` |

Both produce 64-bit little-endian Mach-O (`MH_MAGIC_64`).

## Basic usage

```go
f := macho.NewObjectFile(mir.TargetDarwinARM64)

for _, s := range sections {
    f.AddSection(s)
}

b, err := f.Serialize()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("out.o", b, 0o644)
```

## Minimum OS version

Call `SetMinOS` before the first `AddSection` to emit an `LC_BUILD_VERSION`
load command. The SDK version is set equal to the minimum OS version, which
the linker accepts for relocatable objects.

```go
f.SetMinOS(macho.MacOS, 14, 0)   // macOS 14.0
f.SetMinOS(macho.IOS,   17, 0)   // iOS 17.0
```

Available platform constants: `MacOS`, `IOS`, `TVOS`, `WatchOS`.

## Code signing

If the resulting binary will be immediately ad-hoc signed with `codesign(1)`
on Darwin ARM64, reserve space for the signature:

```go
f.EnableCodesignReserve(true)
```

## Section kinds

Sections are typed via `encoder.SectionKind`. The mapping to Mach-O segments
and section names is fixed:

| `SectionKind` | Segment | Section |
|---|---|---|
| `SectionText` | `__TEXT` | `__text` |
| `SectionData` | `__DATA` | `__data` |
| `SectionROData` | `__TEXT` | `__const` |
| `SectionBSS` | `__DATA` | `__bss` (zerofill) |

BSS sections carry no file bytes; only their virtual size is recorded.

## Symbols and relocations

- Sections with `Exported = true` are emitted as global (`N_EXT`) symbols
  with a leading underscore (`_name`), following Mach-O convention.
- Relocation targets defined within the object but not exported use
  section-relative records (`r_extern = 0`).
- All other relocation targets are emitted as undefined externals
  (`N_UNDF | N_EXT`) for the linker to resolve.
- Addends are written directly into the instruction stream (implicit-addend
  convention); relocation records themselves carry a zero addend.

Supported relocation kinds per architecture:

| Kind | AMD64 | ARM64 |
|---|---|---|
| `mir.RelocPCRel32` | `X86_64_RELOC_BRANCH` | — |
| `mir.RelocPCRel26` | — | `ARM64_RELOC_BRANCH26` |
| `mir.RelocAbs64` | `X86_64_RELOC_UNSIGNED` | `ARM64_RELOC_UNSIGNED` |
| `mir.RelocGOT` | `X86_64_RELOC_GOT_LOAD` | `ARM64_RELOC_GOT_LOAD_PAGE21` |

## API reference

```go
// NewObjectFile returns a File for the given target.
func NewObjectFile(target mir.Target) *File

// AddSection appends a section in declaration order.
func (f *File) AddSection(s enc.Section)

// SetMinOS emits LC_BUILD_VERSION with the given platform and minimum OS version.
func (f *File) SetMinOS(platform Platform, major, minor uint8)

// EnableCodesignReserve reserves space for an ad-hoc code signature.
func (f *File) EnableCodesignReserve(on bool)

// Serialize returns the complete object file as a byte slice.
func (f *File) Serialize() ([]byte, error)

// WriteTo writes the object file directly to w.
func (f *File) WriteTo(w io.Writer) (int64, error)
```