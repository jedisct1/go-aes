//go:build !amd64 && !arm64
// +build !amd64,!arm64

package aes

// Fallback implementations for platforms without hardware AES support

// Vistrutah256EncryptHW encrypts using software implementation (no HW on this platform)
func Vistrutah256EncryptHW(plaintext, ciphertext, key []byte, rounds int) {
	Vistrutah256Encrypt(plaintext, ciphertext, key, rounds)
}

// Vistrutah256DecryptHW decrypts using software implementation (no HW on this platform)
func Vistrutah256DecryptHW(ciphertext, plaintext, key []byte, rounds int) {
	Vistrutah256Decrypt(ciphertext, plaintext, key, rounds)
}

// Vistrutah512EncryptHW encrypts using software implementation (no HW on this platform)
func Vistrutah512EncryptHW(plaintext, ciphertext, key []byte, rounds int) {
	Vistrutah512Encrypt(plaintext, ciphertext, key, rounds)
}

// Vistrutah512DecryptHW decrypts using software implementation (no HW on this platform)
func Vistrutah512DecryptHW(ciphertext, plaintext, key []byte, rounds int) {
	Vistrutah512Decrypt(ciphertext, plaintext, key, rounds)
}
