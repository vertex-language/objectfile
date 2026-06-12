// Package elf produces ELF relocatable object files (ET_REL).
//
// 64-bit ELFCLASS64 little-endian output is used for AMD64 (EM_X86_64 = 62),
// AArch64 (EM_AARCH64 = 183), and RISC-V 64 (EM_RISCV = 243).
// 32-bit ELFCLASS32 little-endian output is used for x86 (EM_386 = 3).
//
// All output uses SHT_RELA relocation sections with explicit addends.
package elf

import (
	"bytes"
	"fmt"
	"io"

	"github.com/vertex-language/objectfile/object"
)

// ── ELF identification constants ──────────────────────────────────────────────

const (
	eiClass   = 4
	eiData    = 5
	eiVersion = 6
	eiOSABI   = 7
)

const (
	elfClass32 = 1
	elfClass64 = 2
)

const elfData2LSB = 1
const evCurrent = 1
const etRel = 1

// e_machine values for supported architectures.
const (
	emI386    uint16 = 3
	emX86_64  uint16 = 62
	emAARCH64 uint16 = 183
	emRISCV   uint16 = 243
)

// ── OSABI ─────────────────────────────────────────────────────────────────────

// OSABI identifies the OS/ABI written to e_ident[EI_OSABI].
type OSABI uint8

const (
	OSABI_None       OSABI = 0
	OSABI_Linux      OSABI = 3
	OSABI_FreeBSD    OSABI = 9
	OSABI_OpenBSD    OSABI = 12
	OSABI_Standalone OSABI = 255
)

// ── File ──────────────────────────────────────────────────────────────────────

// File accumulates object.Section values and serialises them into a
// complete ELF relocatable object file (ET_REL).
//
// Typical usage:
//
//	f := elf.NewFile(object.TargetLinuxAMD64)
//	f.AddSection(sec)
//	b, err := f.Serialize()
type File struct {
	target   object.Target
	machine  uint16
	is64     bool
	osabi    OSABI
	dwarf    bool
	gnuStack bool
	sections []object.Section
}

// NewFile returns an ELF File configured for the given target.
func NewFile(t object.Target) *File {
	f := &File{
		target:   t,
		osabi:    OSABI_None,
		gnuStack: true, // emit .note.GNU-stack by default (marks stack non-exec)
	}
	switch t.Arch {
	case object.ArchAMD64:
		f.machine, f.is64 = emX86_64, true
	case object.ArchARM64:
		f.machine, f.is64 = emAARCH64, true
	case object.ArchRISCV64:
		f.machine, f.is64 = emRISCV, true
	case object.ArchX86:
		f.machine, f.is64 = emI386, false
	default:
		f.machine, f.is64 = emX86_64, true
	}
	return f
}

// SetOSABI overrides the EI_OSABI byte in the file header.
// The default is OSABI_None (System V / unspecified).
func (f *File) SetOSABI(o OSABI) { f.osabi = o }

// EnableDWARF controls emission of skeleton .debug_info / .debug_abbrev sections.
func (f *File) EnableDWARF(on bool) { f.dwarf = on }

// EnableGNUStack controls emission of a .note.GNU-stack section.
// Default: true — emits the section with no SHF_EXECINSTR, signalling a
// non-executable stack. Set to false to omit the section entirely.
func (f *File) EnableGNUStack(on bool) { f.gnuStack = on }

// AddSection appends one section. Implements object.Builder.
func (f *File) AddSection(s object.Section) { f.sections = append(f.sections, s) }

// Serialize assembles all accumulated sections into a complete ELF
// relocatable object file. Safe to call more than once.
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

// relocType maps a format-agnostic RelocKind to the ELF-native type number
// for the file's e_machine. Returns an error for unsupported combinations.
func (f *File) relocType(k object.RelocKind) (uint32, error) {
	switch f.machine {
	case emX86_64:
		switch k {
		case object.RelocAbs64:   return rX86_64_64, nil
		case object.RelocAbs32:   return rX86_64_32, nil
		case object.RelocPCRel32: return rX86_64_PC32, nil
		case object.RelocPLT32:   return rX86_64_PLT32, nil
		case object.RelocGOTLoad: return rX86_64_GOTPCREL, nil
		case object.RelocTLSGD:   return rX86_64_TLSGD, nil
		case object.RelocTLSIE:   return rX86_64_GOTTPOFF, nil
		case object.RelocTLSLE:   return rX86_64_TPOFF32, nil
		}
	case emAARCH64:
		switch k {
		case object.RelocAbs64:     return rAARCH64_ABS64, nil
		case object.RelocAbs32:     return rAARCH64_ABS32, nil
		case object.RelocPCRel26:   return rAARCH64_CALL26, nil
		case object.RelocADRPage21: return rAARCH64_ADR_PREL_PG_HI21, nil
		case object.RelocAddOff12:  return rAARCH64_ADD_ABS_LO12_NC, nil
		case object.RelocGOTPage21: return rAARCH64_ADR_GOT_PAGE, nil
		case object.RelocGOTOff12:  return rAARCH64_LD64_GOT_LO12_NC, nil
		case object.RelocTLSGD:     return rAARCH64_TLSGD_ADR_PAGE21, nil
		case object.RelocTLSIE:     return rAARCH64_TLSIE_ADR_GOTTPREL_PAGE21, nil
		case object.RelocTLSLE:     return rAARCH64_TLSLE_ADD_TPREL_LO12_NC, nil
		}
	case emI386:
		switch k {
		case object.RelocAbs32:   return r386_32, nil
		case object.RelocPCRel32: return r386_PC32, nil
		case object.RelocGOTLoad: return r386_GOT32, nil
		}
	case emRISCV:
		switch k {
		case object.RelocAbs64:      return rRISCV_64, nil
		case object.RelocAbs32:      return rRISCV_32, nil
		case object.RelocRISCVCall:  return rRISCV_CALL_PLT, nil
		case object.RelocRISCVHI20:  return rRISCV_HI20, nil
		case object.RelocRISCVLO12I: return rRISCV_LO12_I, nil
		case object.RelocRISCVLO12S: return rRISCV_LO12_S, nil
		case object.RelocTLSGD:      return rRISCV_TLS_GD_HI20, nil
		case object.RelocTLSIE:      return rRISCV_TLS_GOT_HI20, nil
		case object.RelocTLSLE:      return rRISCV_TPREL_HI20, nil
		}
	}
	return 0, fmt.Errorf("elf: unsupported relocation %v for e_machine %d", k, f.machine)
}