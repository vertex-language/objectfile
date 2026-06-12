package object

// Arch identifies the instruction set architecture.
type Arch uint8

const (
	ArchAMD64   Arch = iota
	ArchARM64
	ArchRISCV64
	ArchX86 // 32-bit x86; used with flat only
)

// OS selects ABI conventions, section naming, and dynamic-linker assumptions.
type OS uint8

const (
	OSLinux        OS = iota
	OSDarwin
	OSWindows
	OSFreestanding
)

// Target is the (Arch, OS) pair that drives section naming,
// relocation encoding, and symbol-table layout inside each format package.
type Target struct {
	Arch Arch
	OS   OS
}

// Predefined targets. Names follow GOARCH + GOOS conventions.
var (
	TargetLinuxAMD64          = Target{ArchAMD64, OSLinux}
	TargetLinuxARM64          = Target{ArchARM64, OSLinux}
	TargetLinuxRISCV64        = Target{ArchRISCV64, OSLinux}
	TargetFreestandingAMD64   = Target{ArchAMD64, OSFreestanding}
	TargetFreestandingARM64   = Target{ArchARM64, OSFreestanding}
	TargetFreestandingRISCV64 = Target{ArchRISCV64, OSFreestanding}
	TargetDarwinAMD64         = Target{ArchAMD64, OSDarwin}
	TargetDarwinARM64         = Target{ArchARM64, OSDarwin}
	TargetWindowsAMD64        = Target{ArchAMD64, OSWindows}
	TargetWindowsARM64        = Target{ArchARM64, OSWindows}
)