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
	RelocAddOff12  // ADD low 12-bit page offset (unshifted)
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

	// AArch64 scaled symbol-low-12 for loads/stores.
	//
	// RelocAddOff12 places the unshifted low 12 bits of the symbol address, as
	// an ADD expects. A scaled load/store, however, holds offset>>log2(size) in
	// its imm12 field, so the linker must shift the low-12 value by the access
	// scale before inserting it — which is exactly what the size-specific
	// R_AARCH64_LDSTn_ABS_LO12_NC relocations do. Using RelocAddOff12 on a
	// non-byte load/store would write the wrong bits, so each access width gets
	// its own kind.
	//
	// ELF: R_AARCH64_LDST{8,16,32,64,128}_ABS_LO12_NC.
	// Mach-O: all collapse to ARM64_RELOC_PAGEOFF12 (the linker derives the
	// shift from the instruction encoding).
	RelocLDST8Off12   // 1-byte access  (no shift)
	RelocLDST16Off12  // 2-byte access  (>>1)
	RelocLDST32Off12  // 4-byte access  (>>2)
	RelocLDST64Off12  // 8-byte access  (>>3)
	RelocLDST128Off12 // 16-byte access (>>4)
)

// Reloc describes one relocation applied within a Section.
type Reloc struct {
	Offset uint32
	Symbol string    // target symbol name; need not be defined in this object file
	Kind   RelocKind
	Addend int64     // logical addend; encoding is format-driven, not caller-driven
}