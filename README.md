# objectfile

`objectfile` assembles raw byte sections and relocation records produced by
[`encoder`](https://github.com/vertex-language/encoder) into complete
relocatable object files.

There is **no top-level package**. Import the sub-package for your target
platform directly:

```go
import "github.com/vertex-language/objectfile/elf"   // Linux
import "github.com/vertex-language/objectfile/coff"  // Windows
import "github.com/vertex-language/objectfile/macho" // Darwin
import "github.com/vertex-language/objectfile/flat"  // raw binary (x86 real mode)
```

---

## Compilation pipeline

```text
Frontend IR
    │
    ▼
C IR (ir/c)          ← ABI, structs, bitfields, calling conventions
    │
    ▼
MIR (ir/mir)         ← physical registers, instruction widths, addressing modes
    │
    ▼
encoder/             ← translates mir.Module into raw byte sections + RelocEntry list
    │   amd64/
    │   arm64/
    │   x86/
    │
    ▼
objectfile/          ← packs sections into ELF / COFF / Mach-O / flat
    │   elf/
    │   coff/
    │   macho/
    │   flat/
    │
    ▼
linker → native binary
```

---

## Sub-packages and supported targets

| Sub-package | Targets | Output |
|---|---|---|
| `elf` | `mir.TargetLinuxAMD64`, `mir.TargetLinuxARM64`, `mir.TargetLinuxX86` | `ET_REL` (ELF64 or ELF32) |
| `coff` | `mir.TargetWindowsAMD64`, `mir.TargetWindowsARM64` | COFF relocatable object |
| `macho` | `mir.TargetDarwinAMD64`, `mir.TargetDarwinARM64` | `MH_OBJECT` (Mach-O 64-bit) |
| `flat` | `mir.TargetX86RealMode` | Raw binary — no header, no symbol table |

---

## Quick start

The pattern is identical across all format packages. Lower and encode your
module, then hand the sections to whichever format package matches your target:

```go
mirMod := mir.LowerModule(cModule, mir.TargetLinuxAMD64)

enc := amd64.NewEncoder(mirMod.Target().ABI())
sections, err := enc.Encode(mirMod)
if err != nil {
    return err
}

f := elf.NewObjectFile(mirMod.Target())
for _, s := range sections {
    f.AddSection(s)
}

b, err := f.Serialize()
if err != nil {
    return err
}
os.WriteFile("out.o", b, 0644)
```

Swap `elf.NewObjectFile` for `coff.NewObjectFile` or `macho.NewObjectFile` and
the rest of the code is unchanged. Importing the sub-package directly also
gives access to format-specific options described below.

---

## Common API

Every format package exposes the same three core methods on its `File` type:

```go
// AddSection ingests one encoder.Section. Sections are accumulated in
// declaration order; text before data is conventional but not required.
func (f *File) AddSection(s encoder.Section)

// Serialize assembles all accumulated sections into a complete relocatable
// object file and returns the raw bytes. Safe to call more than once.
func (f *File) Serialize() ([]byte, error)

// WriteTo is the io.WriterTo form of Serialize, writing directly to w
// without buffering the full object in memory.
func (f *File) WriteTo(w io.Writer) (int64, error)
```

---

## Section mapping

`encoder.SectionKind` values are mapped to format-specific section names and
flags automatically by `AddSection`.

| `encoder.SectionKind` | ELF | COFF | Mach-O |
|---|---|---|---|
| `SectionText` | `.text` | `.text` | `__TEXT,__text` |
| `SectionData` | `.data` | `.data` | `__DATA,__data` |
| `SectionROData` | `.rodata` | `.rdata` | `__TEXT,__const` |
| `SectionBSS` | `.bss` | `.bss` | `__DATA,__bss` |

`SectionBSS` sections carry no file bytes. Only the virtual size is recorded
in the section header; no payload is written to disk.

The encoder emits one `SectionText` per function (matching the
`--function-sections` convention). The three data-class kinds are merged across
globals within each format's natural alignment rules.

---

## Relocation translation

`encoder.RelocEntry` values use `mir.RelocKind` tags, which each format
package translates to its native relocation type codes.

### ELF

| `RelocKind` | AMD64 | AArch64 | i386 |
|---|---|---|---|
| `RelocPCRel32` | `R_X86_64_PC32` | — | `R_386_PC32` |
| `RelocPCRel26` | — | `R_AARCH64_CALL26` | — |
| `RelocAbs64` | `R_X86_64_64` | `R_AARCH64_ABS64` | — |
| `RelocAbs32` | `R_X86_64_32` | — | `R_386_32` |
| `RelocGOT` | `R_X86_64_GOTPCREL` | `R_AARCH64_ADR_GOT_PAGE` + `R_AARCH64_LD64_GOT_LO12_NC` | `R_386_GOT32` |

ELF uses explicit-addend `SHT_RELA` records throughout; `RelocEntry.Addend`
flows directly into the relocation table entry.

### COFF

| `RelocKind` | AMD64 | ARM64 |
|---|---|---|
| `RelocPCRel32` | `IMAGE_REL_AMD64_REL32` | — |
| `RelocPCRel26` | — | `IMAGE_REL_ARM64_BRANCH26` |
| `RelocAbs64` | `IMAGE_REL_AMD64_ADDR64` | `IMAGE_REL_ARM64_ADDR64` |
| `RelocAbs32` | `IMAGE_REL_AMD64_ADDR32` | `IMAGE_REL_ARM64_ADDR32` |
| `RelocIAT` | `IMAGE_REL_AMD64_ADDR32NB` | `IMAGE_REL_ARM64_ADDR32NB` |

### Mach-O

| `RelocKind` | AMD64 | ARM64 |
|---|---|---|
| `RelocPCRel32` | `X86_64_RELOC_BRANCH` | — |
| `RelocPCRel26` | — | `ARM64_RELOC_BRANCH26` |
| `RelocAbs64` | `X86_64_RELOC_UNSIGNED` | `ARM64_RELOC_UNSIGNED` |
| `RelocGOT` | `X86_64_RELOC_GOT_LOAD` | `ARM64_RELOC_GOT_LOAD_PAGE21` + `ARM64_RELOC_GOT_LOAD_PAGEOFF12` |

COFF and Mach-O use implicit addends: `Serialize` writes `RelocEntry.Addend`
into the appropriate bytes of `Code` before emitting each section, and records
a zero addend in the relocation table entry.

---

## Format-specific options

Options must be set before the first `AddSection` call.

### ELF (`objectfile/elf`)

```go
f := elf.NewObjectFile(mir.TargetLinuxAMD64)
f.SetOS(elf.OSABI_Linux)   // default: OSABI_None; also OSABI_FreeBSD, OSABI_OpenBSD
f.EnableDWARF(true)        // emit skeleton .debug_info / .debug_abbrev (default: false)
```

### COFF (`objectfile/coff`)

```go
f := coff.NewObjectFile(mir.TargetWindowsAMD64)
f.SetSubsystem(coff.SubsystemConsole) // default; or SubsystemWindows, SubsystemEFI, …
```

### Mach-O (`objectfile/macho`)

```go
f := macho.NewObjectFile(mir.TargetDarwinARM64)
f.SetMinOS(macho.MacOS, 14, 0)   // emit LC_BUILD_VERSION (default: omitted)
f.EnableCodesignReserve(true)    // reserve space for ad-hoc signature (default: false)
```

Available `SetMinOS` platform constants: `MacOS`, `IOS`, `TVOS`, `WatchOS`.

### Flat (`objectfile/flat`)

`flat.NewObjectFile` takes no target argument. All relocations must be fully
resolved before `AddSection` is called — the MIR module may not contain
external symbol references.

```go
f := flat.NewObjectFile()
for _, s := range sections {
    f.AddSection(s)
}
b, _ := f.Serialize() // raw bytes, no header
```

---

## Design notes

**Format, not architecture.** The sub-package split mirrors the linker's
world-view: ELF covers all Linux targets, COFF covers all Windows targets,
Mach-O covers all Darwin targets. Architecture details (`e_machine`, `cpu_type`,
alignment rules) are parameters inside each sub-package, not separate packages.

**Sections are opaque.** `File` treats `encoder.Section` values as finished
byte blobs. It never inspects or rewrites `Code`; it only fills in relocation
fields from `Relocs`, writes section metadata, and builds the symbol table from
`Name` and `Exported`.

**One symbol per section.** Because the encoder emits one `SectionText` per
function, the symbol table maps naturally: one global or local symbol per text
section, one data symbol per data section.

**Addend convention.** ELF addends are explicit (`Rela`). COFF and Mach-O
addends are implicit — embedded in the instruction stream — so the object layer
patches `Code` in place before writing and records zero in the relocation entry.