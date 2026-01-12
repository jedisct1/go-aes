package aes

import (
	"golang.org/x/sys/cpu"
)

// CPUFeatures holds information about available CPU hardware acceleration
// features for AES operations. These flags are automatically detected at
// package initialization and used to select optimal implementations.
type CPUFeatures struct {
	HasAESNI     bool // Intel AES-NI instructions (AESENC/AESDEC)
	HasARMCrypto bool // ARM Crypto Extensions (AESE/AESD)
	HasVAES      bool // Vector AES instructions (VAESENC/VAESDEC)
	HasAVX2      bool // AVX2 support for 256-bit vectors (2 AES blocks with VAES)
	HasAVX512    bool // AVX512 support for 512-bit vectors (4 AES blocks with VAES)
}

// CPU holds the detected CPU features for the current processor.
// This variable is initialized automatically at package init time.
// Check these fields to determine which hardware acceleration is available.
var CPU CPUFeatures

func init() {
	detectCPUFeatures()
}

// detectCPUFeatures detects available AES hardware acceleration
func detectCPUFeatures() {
	CPU.HasAESNI = cpu.X86.HasAES
	CPU.HasARMCrypto = cpu.ARM64.HasAES
	CPU.HasVAES = cpu.X86.HasAVX512VAES
	CPU.HasAVX2 = cpu.X86.HasAVX2
	CPU.HasAVX512 = cpu.X86.HasAVX512F
}

// UseHardwareAcceleration returns true if single-block hardware AES acceleration
// is available (Intel AES-NI or ARM Crypto Extensions). When true, *HW functions
// will use hardware instructions instead of software implementations.
func UseHardwareAcceleration() bool {
	return CPU.HasAESNI || CPU.HasARMCrypto
}

// UseVectorAcceleration returns true if vector AES acceleration (VAES) is
// available for parallel block processing. This requires VAES support plus
// either AVX2 (for 2 blocks) or AVX512 (for 4 blocks).
func UseVectorAcceleration() bool {
	return CPU.HasVAES && (CPU.HasAVX2 || CPU.HasAVX512)
}

// OptimalParallelBlocks returns the optimal number of AES blocks that should
// be processed in parallel on the current CPU for best performance:
//   - 4: AVX512 with VAES, or ARM Crypto Extensions
//   - 2: AVX2 with VAES (without AVX512), or ARM Crypto Extensions
//   - 1: Single-block hardware acceleration only, or software fallback
//
// Use this function to decide whether to use Block2, Block4, or single Block
// operations for maximum throughput.
func OptimalParallelBlocks() int {
	if CPU.HasVAES && CPU.HasAVX512 {
		return 4
	}
	if CPU.HasVAES && CPU.HasAVX2 {
		return 2
	}
	if CPU.HasARMCrypto {
		// ARM Crypto Extensions benefit from parallel ops (reduced boundary crossings)
		// even without SIMD parallelism
		return 4
	}
	if CPU.HasAESNI {
		// AES-NI alone doesn't benefit from parallel ops as much
		return 2
	}
	return 1
}
