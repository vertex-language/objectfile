# coff

Package `coff` produces COFF relocatable object files (`.obj`) from
[`encoder.Section`](https://pkg.go.dev/github.com/vertex-language/encoder)
values.

```go
import "github.com/vertex-language/objectfile/coff"
```

## Supported targets

| Target | Machine |
|---|---|
| `mir.TargetWindowsAMD64` | `IMAGE_FILE_MACHINE_AMD64` (`0x8664`) |
| `mir.TargetWindowsARM64` | `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`) |

## Quick start

```go
f := coff.NewObjectFile(mir.TargetWindowsAMD64)

for _, s := range sections {
    f.AddSection(s)
}

b, err := f.Serialize()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("output.obj", b, 0o644)
```

## API

### `NewObjectFile(target mir.Target) *File`

Returns a `File` ready to accept sections. Defaults to AMD64 for any target
other than `TargetWindowsARM64`.

### `(*File) AddSection(s enc.Section)`

Appends a section in declaration order. Call once per section before serialising.

### `(*File) SetSubsystem(s Subsystem)`

Records the intended Windows subsystem. Informational only — object files have
no Optional Header, so this is not written to the `.obj` output. Defaults to
`SubsystemConsole`.

| Constant | Value | Subsystem |
|---|---|---|
| `SubsystemUnknown` | 0 | — |
| `SubsystemNative` | 1 | Native |
| `SubsystemWindows` | 2 | GUI |
| `SubsystemConsole` | 3 | Console (default) |
| `SubsystemEFI` | 10 | EFI Application |

### `(*File) Serialize() ([]byte, error)`

Assembles all sections into a complete COFF object file and returns the raw
bytes. Safe to call more than once.

### `(*File) WriteTo(w io.Writer) (int64, error)`

`io.WriterTo` form of `Serialize`.

## Section kinds

| `enc.SectionKind` | COFF name | Characteristics |
|---|---|---|
| `SectionText` | `.text` | `CNT_CODE \| MEM_EXECUTE \| MEM_READ`, 16-byte aligned |
| `SectionData` | `.data` | `CNT_INITIALIZED_DATA \| MEM_READ \| MEM_WRITE`, 8-byte aligned |
| `SectionROData` | `.rdata` | `CNT_INITIALIZED_DATA \| MEM_READ`, 8-byte aligned |
| `SectionBSS` | `.bss` | `CNT_UNINITIALIZED_DATA \| MEM_READ \| MEM_WRITE`, 8-byte aligned, no file bytes |

## Relocations

Addends are implicit: before emitting each section, the serialiser writes
`RelocEntry.Addend` directly into the code bytes at the relocation offset
(4 bytes for most kinds, 8 bytes for `RelocAbs64`). The COFF relocation record
itself records zero.

Supported relocation kinds per target:

**AMD64**

| `enc.RelocKind` | COFF type |
|---|---|
| `RelocPCRel32` | `IMAGE_REL_AMD64_REL32` |
| `RelocAbs64` | `IMAGE_REL_AMD64_ADDR64` |
| `RelocAbs32` | `IMAGE_REL_AMD64_ADDR32` |
| `RelocIAT` | `IMAGE_REL_AMD64_ADDR32NB` |

**ARM64**

| `enc.RelocKind` | COFF type |
|---|---|
| `RelocPCRel26` | `IMAGE_REL_ARM64_BRANCH26` |
| `RelocAbs64` | `IMAGE_REL_ARM64_ADDR64` |
| `RelocAbs32` | `IMAGE_REL_ARM64_ADDR32` |
| `RelocIAT` | `IMAGE_REL_ARM64_ADDR32NB` |

## Output is reproducible

`TimeDateStamp` is always written as zero.