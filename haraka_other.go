//go:build (!amd64 && !arm64) || purego

package aes

// Haraka256HW falls back to software implementation on non-accelerated platforms.
func Haraka256HW(input *[32]byte) [32]byte {
	return Haraka256(input)
}

// Haraka512HW falls back to software implementation on non-accelerated platforms.
func Haraka512HW(input *[64]byte) [32]byte {
	return Haraka512(input)
}
