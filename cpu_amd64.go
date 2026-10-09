//go:build amd64 && !purego

package aes

import "golang.org/x/sys/cpu"

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// hasVAES reads the VAES bit (CPUID leaf 7, ECX bit 9) directly.
// golang.org/x/sys/cpu only reports it when AVX-512 is enabled, but the
// VEX-encoded YMM form only needs AVX, and CPUs such as AMD Zen 3 and Intel
// Alder Lake have VAES without AVX-512.
// HasAVX2 implies that leaf 7 exists and that the OS saves YMM registers.
func hasVAES() bool {
	if !cpu.X86.HasAVX2 {
		return false
	}
	_, _, ecx7, _ := cpuid(7, 0)
	return ecx7&(1<<9) != 0
}
