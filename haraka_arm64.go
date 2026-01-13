//go:build arm64 && !purego

package aes

// Hardware-accelerated Haraka v2 using ARM Crypto extensions

//go:noescape
func haraka256HW(out *[32]byte, input *[32]byte, rc *[40][16]byte)

//go:noescape
func haraka512HW(out *[32]byte, input *[64]byte, rc *[40][16]byte)

// Haraka256HW computes Haraka-256 with hardware acceleration if available.
func Haraka256HW(input *[32]byte) [32]byte {
	var out [32]byte
	if CPU.HasARMCrypto {
		haraka256HW(&out, input, &harakaRC128)
	} else {
		out = Haraka256(input)
	}
	return out
}

// Haraka512HW computes Haraka-512 with hardware acceleration if available.
func Haraka512HW(input *[64]byte) [32]byte {
	var out [32]byte
	if CPU.HasARMCrypto {
		haraka512HW(&out, input, &harakaRC128)
	} else {
		out = Haraka512(input)
	}
	return out
}
