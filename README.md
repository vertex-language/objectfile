# objectfile

`github.com/vertex-language/objectfile`

Assembles relocatable object files from raw section bytes, symbol definitions,
and relocation records. Supports ELF64 (Linux, \*BSD, freestanding), COFF
(Windows), Mach-O (Darwin), and raw flat binary. No external dependencies —
only the Go standard library.

---

## Installation

```sh
go get github.com/vertex-language/objectfile
```

---

## Import paths

There is no top-level package. Import the `object/` sub-package for shared
types, plus whichever format sub-package matches your target:

```go
import "github.com/vertex-language/objectfile/object" // Section, Symbol, Reloc, Target, Builder
import "github.com/vertex-language/objectfile/elf"    // Linux, *BSD, freestanding
import "github.com/vertex-language/objectfile/coff"   // Windows
import "github.com/vertex-language/objectfile/macho"  // Darwin
import "github.com/vertex-language/objectfile/flat"   // raw binary, no header
```

---

## Package layout

```
objectfile/
├── object/         Shared types — no format dependency
│   ├── target.go   Target, Arch, OS — predefined target constants
│   ├── section.go  Section, SectionKind, SectionFlags
│   ├── symbol.go   Symbol, Binding, SymbolKind
│   ├── reloc.go    Reloc, RelocKind
│   └── builder.go  Builder interface — implemented by every format File
│
├── elf/            ELF64 relocatable object (ET_REL)
│   ├── file.go     elf.File
│   ├── reloc.go    RelocKind → R_* translation tables
│   └── options.go  OSABI, DWARF, GNU stack note
│
├── coff/           COFF relocatable object (PE/COFF)
│   ├── file.go     coff.File
│   ├── reloc.go    RelocKind → IMAGE_REL_* translation tables
│   └── options.go  Subsystem
│
├── macho/          Mach-O relocatable object (MH_OBJECT, 64-bit)
│   ├── file.go     macho.File
│   ├── reloc.go    RelocKind → *_RELOC_* translation tables
│   └── options.go  MinOS (LC_BUILD_VERSION), codesign reserve
│
└── flat/           Raw binary — no header, no symbol table, no relocations
    └── file.go     flat.File
```

---

## Core concepts

### Target

A `Target` is an `(Arch, OS)` pair that tells each format package which
machine encoding, section names, and relocation type codes to use.

```go
// Predefined targets — names follow GOARCH + GOOS conventions.
object.TargetLinuxAMD64
object.TargetLinuxARM64
object.TargetLinuxRISCV64
object.TargetFreestandingAMD64
object.TargetFreestandingARM64
object.TargetFreestandingRISCV64
object.TargetDarwinAMD64
object.TargetDarwinARM64
object.TargetWindowsAMD64
object.TargetWindowsARM64

// Or build your own:
t := object.Target{Arch: object.ArchARM64, OS: object.OSDarwin}
```

### Section

`Section` is the fundamental unit of content. The caller fills it and hands it
to a format `File` via `AddSection`. The format package maps `Kind` to the
correct platform-specific section name and flags — you never write `.text` or
`__TEXT,__text` yourself unless you're using `SectionCustom`.

```go
type Section struct {
    Kind    SectionKind   // SectionText, SectionData, SectionROData, SectionBSS, …
    Custom  string        // non-empty only when Kind == SectionCustom
    Align   uint32        // alignment in bytes; 0 = format default for Kind
    Code    []byte        // raw bytes; nil/empty for BSS and zero-fill sections
    VSize   uint64        // virtual size; for BSS may exceed len(Code); 0 = len(Code)
    Symbols []Symbol      // symbols defined at byte offsets within this section
    Relocs  []Reloc       // relocations to apply within Code
    Flags   SectionFlags  // FlagLinkOnce, FlagNoDeadStrip
}
```

### Symbol

```go
type Symbol struct {
    Name      string
    Offset    uint32     // byte offset from start of Section.Code
    Size      uint32     // 0 = unknown / not specified
    Binding   Binding    // BindingLocal, BindingGlobal, BindingWeak
    Kind      SymbolKind // SymFunc, SymData, SymSection
    DLLExport bool       // COFF only: emit /EXPORT:<name> in .drectve
}
```

### Reloc

```go
type Reloc struct {
    Offset uint32     // byte offset within Section.Code where the fixup is applied
    Symbol string     // target symbol name; need not be in this object file
    Kind   RelocKind  // RelocAbs64, RelocPCRel32, RelocPLT32, …
    Addend int64      // logical addend — encoding is format-driven, not caller-driven
}
```

The addend convention is uniform from the caller's perspective: set
`Reloc.Addend` to the logical addend and forget about it. ELF writes it into
`r_addend` and leaves `Code` alone (`SHT_RELA`). COFF and Mach-O bake it into
the instruction bytes at `Reloc.Offset` before emitting and record zero in the
relocation table entry.

### Builder

Every format `File` implements this three-method interface:

```go
type Builder interface {
    AddSection(s Section)
    Serialize() ([]byte, error)
    WriteTo(w io.Writer) (int64, error)
}
```

Format-specific options (OSABI, subsystem, min-OS version) live on the
concrete `File` type and must be configured before the first `AddSection` call.

---

## Format packages

### `elf` — ELF64 relocatable object

Supports `TargetLinux*`, `TargetFreestanding*`, and any `Target` with
`OSLinux` or `OSFreestanding`. Produces `ELFCLASS64` little-endian `ET_REL`
objects for AMD64, ARM64, and RISC-V 64. `ArchX86` produces `ELFCLASS32`.

```go
f := elf.NewFile(object.TargetLinuxAMD64)

// Options — set before the first AddSection call.
f.SetOSABI(elf.OSABI_Linux)   // default: OSABI_None
                               // also: OSABI_FreeBSD, OSABI_OpenBSD, OSABI_Standalone
f.EnableDWARF(true)           // emit skeleton .debug_info / .debug_abbrev (default: false)
f.EnableGNUStack(false)       // omit .note.GNU-stack (default: true — marks stack non-exec)

f.AddSection(sec)
b, err := f.Serialize()
```

Relocation sections use `SHT_RELA` (explicit addends). `FlagLinkOnce` emits
an `SHT_GROUP` COMDAT group keyed on the first global symbol in the section.

### `coff` — COFF relocatable object

Supports `TargetWindowsAMD64` and `TargetWindowsARM64`.

```go
f := coff.NewFile(object.TargetWindowsAMD64)

// Options — set before the first AddSection call.
f.SetSubsystem(coff.SubsystemConsole)  // default
                                        // also: SubsystemWindows, SubsystemEFI,
                                        //       SubsystemBootApp, SubsystemNative

f.AddSection(sec)
b, err := f.Serialize()
```

COFF uses implicit addends — `Serialize` patches `Reloc.Addend` into `Code`
before writing and records zero in the relocation table entry. `FlagLinkOnce`
maps to `IMAGE_COMDAT_SELECT_ANY`. `Symbol.DLLExport = true` emits an
`__imp_` stub and a `.drectve /EXPORT:<name>` directive.

### `macho` — Mach-O MH\_OBJECT

Supports `TargetDarwinAMD64` and `TargetDarwinARM64`. Produces 64-bit
little-endian `MH_OBJECT` files.

```go
f := macho.NewFile(object.TargetDarwinARM64)

// Options — set before the first AddSection call.
f.SetMinOS(macho.MacOS, 14, 0)      // emit LC_BUILD_VERSION (default: omitted)
                                     // platform: MacOS, IOS, TVOS, WatchOS, VisionOS
f.EnableCodesignReserve(true)        // reserve LC_CODE_SIGNATURE space (default: false)

f.AddSection(sec)
b, err := f.Serialize()
```

Mach-O uses implicit addends. `FlagLinkOnce` marks all global symbols in the
section with `N_WEAK_DEF`. `SectionCustom` takes a `"segment,section"` name
(e.g. `"__DATA,__objc_classlist"`); `AddSection` returns an error if the
format is malformed.

### `flat` — raw binary

No header, no symbol table, no relocation records. All symbol references must
be pre-resolved before sections are added. `AddSection` returns an error if
the section's `Relocs` slice is non-empty. Symbols are silently discarded.
`SectionBSS` emits `VSize` zero bytes (unlike other formats, flat binary must
be fully self-contained).

```go
f := flat.NewFile()
f.SetBaseAddress(0x7C00) // default: 0x0000 — informational only, does not alter layout

f.AddSection(sec)
b, err := f.Serialize()
```

---

## Usage examples

### Simple function — ELF (x86-64)

```go
package main

import (
    "os"
    "github.com/vertex-language/objectfile/elf"
    "github.com/vertex-language/objectfile/object"
)

func main() {
    code := []byte{
        0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, // mov rax, 42
        0xc3,                                        // ret
    }

    f := elf.NewFile(object.TargetLinuxAMD64)
    f.AddSection(object.Section{
        Kind:  object.SectionText,
        Align: 16,
        Code:  code,
        Symbols: []object.Symbol{
            {
                Name:    "answer",
                Offset:  0,
                Size:    uint32(len(code)),
                Binding: object.BindingGlobal,
                Kind:    object.SymFunc,
            },
        },
    })

    b, err := f.Serialize()
    if err != nil {
        panic(err)
    }
    os.WriteFile("answer.o", b, 0644)
}
```

### Calling an external symbol — PC-relative relocation

```go
// Emits: call puts; ret
code := []byte{
    0xe8, 0x00, 0x00, 0x00, 0x00, // CALL rel32  ← relocation placeholder
    0xc3,                          // RET
}

f := elf.NewFile(object.TargetLinuxAMD64)
f.AddSection(object.Section{
    Kind:  object.SectionText,
    Align: 16,
    Code:  code,
    Symbols: []object.Symbol{
        {Name: "greet", Offset: 0, Size: uint32(len(code)),
            Binding: object.BindingGlobal, Kind: object.SymFunc},
    },
    Relocs: []object.Reloc{
        {
            Offset: 1,               // first byte of the rel32 field
            Symbol: "puts",
            Kind:   object.RelocPCRel32,
            Addend: -4,              // ELF RELA: displacement is relative to end of insn
        },
    },
})
```

### COMDAT — one copy across translation units (ELF)

```go
f := elf.NewFile(object.TargetLinuxAMD64)
f.AddSection(object.Section{
    Kind:  object.SectionText,
    Align: 16,
    Code:  inlineBytes,
    Flags: object.FlagLinkOnce,
    Symbols: []object.Symbol{
        {Name: "inline_max", Offset: 0, Size: uint32(len(inlineBytes)),
            Binding: object.BindingGlobal, Kind: object.SymFunc},
    },
})
```

### DLL export (COFF / Windows)

```go
f := coff.NewFile(object.TargetWindowsAMD64)
f.AddSection(object.Section{
    Kind:  object.SectionText,
    Align: 16,
    Code:  fnBytes,
    Symbols: []object.Symbol{
        {Name: "MyExport", Offset: 0, Size: uint32(len(fnBytes)),
            Binding: object.BindingGlobal, Kind: object.SymFunc,
            DLLExport: true},
    },
})
```

### Constructor registration and custom section (Mach-O)

```go
f := macho.NewFile(object.TargetDarwinARM64)
f.SetMinOS(macho.MacOS, 14, 0)

// constructor pointer — dyld calls my_init before main
f.AddSection(object.Section{
    Kind:  object.SectionInitArray,
    Align: 8,
    Code:  make([]byte, 8),
    Relocs: []object.Reloc{
        {Offset: 0, Symbol: "my_init", Kind: object.RelocAbs64},
    },
})

// ObjC class list
f.AddSection(object.Section{
    Kind:   object.SectionCustom,
    Custom: "__DATA,__objc_classlist",
    Align:  8,
    Code:   classListBytes,
    Relocs: []object.Reloc{
        {Offset: 0, Symbol: "_OBJC_CLASS_$_MyClass", Kind: object.RelocAbs64},
    },
})
```

### Raw flat binary — x86 real-mode boot sector

```go
f := flat.NewFile()
f.SetBaseAddress(0x7C00)

bootsector := buildBootSector() // all references already encoded in the bytes
bootsector[510], bootsector[511] = 0x55, 0xAA

f.AddSection(object.Section{
    Kind:  object.SectionText,
    Align: 1,
    Code:  bootsector,
})

b, _ := f.Serialize()
os.WriteFile("boot.bin", b, 0644)
```

### Selecting a format at runtime

The library deliberately does not provide a format-picker to avoid forcing
callers to link all three format packages. Write this helper in your own
application:

```go
func newBuilder(t object.Target) object.Builder {
    switch t.OS {
    case object.OSLinux, object.OSFreestanding:
        return elf.NewFile(t)
    case object.OSDarwin:
        return macho.NewFile(t)
    case object.OSWindows:
        return coff.NewFile(t)
    }
    panic("unsupported OS")
}
```

---

## Section kind mapping

| `SectionKind`       | ELF              | COFF          | Mach-O                                        |
|---------------------|------------------|---------------|-----------------------------------------------|
| `SectionText`       | `.text`          | `.text`       | `__TEXT,__text`                               |
| `SectionData`       | `.data`          | `.data`       | `__DATA,__data`                               |
| `SectionROData`     | `.rodata`        | `.rdata`      | `__TEXT,__const`                              |
| `SectionBSS`        | `.bss`           | `.bss`        | `__DATA,__bss`                                |
| `SectionUnwind`     | `.eh_frame`      | `.pdata` + `.xdata` | `__TEXT,__unwind_info` + `__TEXT,__eh_frame` |
| `SectionInitArray`  | `.init_array`    | `.CRT$XCU`    | `__DATA,__mod_init_func`                      |
| `SectionFiniArray`  | `.fini_array`    | `.CRT$XTZ`    | `__DATA,__mod_term_func`                      |
| `SectionTLS` (init) | `.tdata`         | `.tls`        | `__DATA,__thread_data`                        |
| `SectionTLS` (zero) | `.tbss`          | `.tls$ZZZ`    | `__DATA,__thread_bss`                         |
| `SectionCustom`     | as given         | as given      | as given (`"seg,sect"`)                       |

`SectionBSS` and zero-fill `SectionTLS` carry no file bytes in any structured
format — only the virtual size is written to the section header. `flat` is the
exception: it emits `VSize` zero bytes because it has no header to carry the
reservation.

---

## Relocation kind mapping

### ELF — explicit addends (`SHT_RELA`)

`Reloc.Addend` flows directly into `r_addend`. `Code` is never patched.

| `RelocKind`      | AMD64                     | ARM64                                    | RISC-V 64            |
|------------------|---------------------------|------------------------------------------|----------------------|
| `RelocAbs64`     | `R_X86_64_64`             | `R_AARCH64_ABS64`                        | `R_RISCV_64`         |
| `RelocAbs32`     | `R_X86_64_32`             | `R_AARCH64_ABS32`                        | `R_RISCV_32`         |
| `RelocPCRel32`   | `R_X86_64_PC32`           | —                                        | —                    |
| `RelocPLT32`     | `R_X86_64_PLT32`          | —                                        | —                    |
| `RelocGOTLoad`   | `R_X86_64_GOTPCREL`       | —                                        | —                    |
| `RelocPCRel26`   | —                         | `R_AARCH64_CALL26`                       | —                    |
| `RelocADRPage21` | —                         | `R_AARCH64_ADR_PREL_PG_HI21`            | —                    |
| `RelocAddOff12`  | —                         | `R_AARCH64_ADD_ABS_LO12_NC`             | —                    |
| `RelocGOTPage21` | —                         | `R_AARCH64_ADR_GOT_PAGE`                | —                    |
| `RelocGOTOff12`  | —                         | `R_AARCH64_LD64_GOT_LO12_NC`           | —                    |
| `RelocRISCVCall` | —                         | —                                        | `R_RISCV_CALL_PLT`   |
| `RelocRISCVHI20` | —                         | —                                        | `R_RISCV_HI20`       |
| `RelocRISCVLO12I`| —                         | —                                        | `R_RISCV_LO12_I`     |
| `RelocRISCVLO12S`| —                         | —                                        | `R_RISCV_LO12_S`     |
| `RelocTLSGD`     | `R_X86_64_TLSGD`          | `R_AARCH64_TLSGD_ADR_PAGE21`            | `R_RISCV_TLS_GD_HI20`|
| `RelocTLSIE`     | `R_X86_64_GOTTPOFF`       | `R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21`   | `R_RISCV_TLS_GOT_HI20`|
| `RelocTLSLE`     | `R_X86_64_TPOFF32`        | `R_AARCH64_TLSLE_ADD_TPREL_LO12_NC`    | `R_RISCV_TPREL_HI20` |

### COFF — implicit addends

`Serialize` patches `Reloc.Addend` into `Code` before writing.

| `RelocKind`    | AMD64                      | ARM64                      |
|----------------|----------------------------|----------------------------|
| `RelocAbs64`   | `IMAGE_REL_AMD64_ADDR64`   | `IMAGE_REL_ARM64_ADDR64`   |
| `RelocAbs32`   | `IMAGE_REL_AMD64_ADDR32`   | `IMAGE_REL_ARM64_ADDR32`   |
| `RelocPCRel32` | `IMAGE_REL_AMD64_REL32`    | —                          |
| `RelocPCRel26` | —                          | `IMAGE_REL_ARM64_BRANCH26` |
| `RelocIAT`     | `IMAGE_REL_AMD64_ADDR32NB` | `IMAGE_REL_ARM64_ADDR32NB` |
| `RelocTLSIE`   | `IMAGE_REL_AMD64_SECREL`   | `IMAGE_REL_ARM64_SECREL`   |

### Mach-O — implicit addends

`Serialize` patches `Code` in place; relocation entries carry zero.

| `RelocKind`      | AMD64                    | ARM64                              |
|------------------|--------------------------|------------------------------------|
| `RelocAbs64`     | `X86_64_RELOC_UNSIGNED`  | `ARM64_RELOC_UNSIGNED`             |
| `RelocPCRel32`   | `X86_64_RELOC_BRANCH`    | —                                  |
| `RelocGOTLoad`   | `X86_64_RELOC_GOT_LOAD`  | —                                  |
| `RelocPCRel26`   | —                        | `ARM64_RELOC_BRANCH26`             |
| `RelocADRPage21` | —                        | `ARM64_RELOC_PAGE21`               |
| `RelocAddOff12`  | —                        | `ARM64_RELOC_PAGEOFF12`            |
| `RelocGOTPage21` | —                        | `ARM64_RELOC_GOT_LOAD_PAGE21`      |
| `RelocGOTOff12`  | —                        | `ARM64_RELOC_GOT_LOAD_PAGEOFF12`   |
| `RelocTLSGD`     | `X86_64_RELOC_TLV`       | `ARM64_RELOC_TLVP_LOAD_PAGE21`     |

---

## Design notes

**No external dependencies.** The entire module imports nothing outside the Go
standard library.

**Format, not architecture, drives the sub-package split.** ELF covers every
Linux and freestanding target across all three supported architectures. COFF
covers all Windows targets. Mach-O covers all Darwin targets. Architecture
differences (`e_machine`, `cpu_type`, relocation encodings, alignment defaults)
are internal parameters within each format package.

**`object.Builder` is the seam.** The interface has three methods.
Format-specific options live on the concrete `File` type and must be set before
the first `AddSection`. The `Builder` interface deliberately does not expose
them, so any code that targets `object.Builder` is format-agnostic.

**Addend encoding is format-driven, not caller-driven.** The caller always sets
`Reloc.Addend` to the logical value. ELF writes it to `r_addend` and leaves
`Code` alone. COFF and Mach-O patch `Code` in place. Callers are shielded from
the difference entirely.

**`flat` is not a special case.** It implements `object.Builder` exactly like
the other format packages, and can be substituted anywhere a `Builder` is
accepted. The constraint that relocations must be pre-resolved is enforced in
`WriteTo`, not at the interface level.