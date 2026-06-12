package object

// RelocKind is a format-agnostic relocation type. Format packages translate
// these to native type codes.
type RelocKind uint16

const (
	// Absolute — all architectures
	RelocAbs64 RelocKind = iota // 64-bit absolute symbol address
	RelocAbs32                  // 32-bit absolute symbol address

	// x86-64
	RelocPCRel32 // 32-bit PC-relative displacement
	RelocPLT32   // 32-bit PC-relative through PLT
	RelocGOTLoad // RIP-relative load from GOT slot

	// AArch64
	RelocPCRel26   // B/BL 26-bit PC-relative
	RelocADRPage21 // ADRP 21-bit page-delta
	RelocAddOff12  // ADD/LDR low 12-bit page offset
	RelocGOTPage21 // ADRP to GOT entry page
	RelocGOTOff12  // LDR low 12-bit offset into GOT entry

	// RISC-V 64
	RelocRISCVCall  // AUIPC+JALR call pair
	RelocRISCVHI20  // LUI/AUIPC high 20 bits
	RelocRISCVLO12I // ADDI/JALR low 12 bits, I-type
	RelocRISCVLO12S // SW/SH/SB low 12 bits, S-type

	// Thread-local storage — all architectures
	RelocTLSGD // General Dynamic: call __tls_get_addr
	RelocTLSIE // Initial Exec: load TP-relative offset from GOT
	RelocTLSLE // Local Exec: TP-relative offset, resolved at link time

	// COFF-specific
	RelocIAT // Import Address Table
)

// Reloc describes one relocation applied within a Section.
type Reloc struct {
	Offset uint32
	Symbol string   // target symbol name; need not be defined in this object file
	Kind   RelocKind
	Addend int64    // logical addend; encoding is format-driven, not caller-driven
}