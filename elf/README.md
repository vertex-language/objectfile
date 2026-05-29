# elf

Package `elf` produces ELF relocatable object files (`ET_REL`) from
[`encoder.Section`](https://pkg.go.dev/github.com/vertex-language/encoder)
values.

```go
import "github.com/vertex-language/objectfile/elf"
```

## Supported targets

| Target | Architecture | Class |
|---|---|---|
| `mir.TargetLinuxAMD64` | x86-64 | ELF64 |
| `mir.TargetLinuxARM64` | AArch64 | ELF64 |
| `mir.TargetLinuxX86` | i386 | ELF32 |

All output is little-endian and uses explicit-addend `SHT_RELA` relocation
sections.

## Basic usage

```go
f := elf.NewObjectFile(mir.TargetLinuxAMD64)

for _, s := range sections {
    f.AddSection(s)
}

b, err := f.Serialize()
if err != nil {
    log.Fatal(err)
}
os.WriteFile("out.o", b, 0o644)
```

## Options

### OS/ABI

The default `EI_OSABI` is `OSABI_None` (System V / unspecified), which is
accepted by all Linux toolchains. Override it when targeting a specific
platform:

```go
f.SetOS(elf.OSABI_FreeBSD)
```

| Constant | Value | Platform |
|---|---|---|
| `OSABI_None` | 0 | System V / unspecified (default) |
| `OSABI_Linux` | 3 | GNU / Linux |
| `OSABI_FreeBSD` | 9 | FreeBSD |
| `OSABI_OpenBSD` | 12 | OpenBSD |

### DWARF

```go
f.EnableDWARF(true)
```

Emits skeleton `.debug_info` / `.debug_abbrev` sections so downstream tooling
can attach DWARF without re-linking. Full DWARF generation is a future
extension.

## Streaming output

`File` implements `io.WriterTo`, so you can write directly to any `io.Writer`
without buffering the full object in memory:

```go
f.WriteTo(w)
```

## Section types and relocation kinds

Sections are mapped to ELF section types based on their `enc.SectionKind`:

| Kind | ELF type | Flags |
|---|---|---|
| `SectionText` | `SHT_PROGBITS` | `AX` (alloc + exec) |
| `SectionData` | `SHT_PROGBITS` | `AW` (alloc + write) |
| `SectionROData` | `SHT_PROGBITS` | `A` (alloc) |
| `SectionBSS` | `SHT_NOBITS` | `AW` (alloc + write) |

Supported relocation kinds per target:

| Kind | AMD64 | AArch64 | i386 |
|---|---|---|---|
| `RelocAbs64` | `R_X86_64_64` | `R_AARCH64_ABS64` | — |
| `RelocAbs32` | `R_X86_64_32` | — | `R_386_32` |
| `RelocPCRel32` | `R_X86_64_PC32` | — | `R_386_PC32` |
| `RelocPCRel26` | — | `R_AARCH64_CALL26` | — |
| `RelocGOT` | `R_X86_64_GOTPCREL` | `R_AARCH64_ADR_GOT_PAGE` | `R_386_GOT32` |

## File layout

```
ELF header
.text / .data / .rodata / .bss   (one per encoder.Section)
.rela<name>                       (one per section that has relocations)
.symtab
.strtab
.shstrtab
Section header table
```

Exported sections produce `STB_GLOBAL` symbols. External relocation targets
produce `STB_GLOBAL / SHN_UNDEF` symbols. All `STB_LOCAL` symbols precede
globals in `.symtab` as required by the ELF spec.