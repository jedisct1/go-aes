//go:build arm64
// +build arm64

package aes

// Assembly functions - implemented in vistrutah_arm64.s
func vistrutah256EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, p4, p5 *byte)
func vistrutah256DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, p4inv, p5inv *byte)
func vistrutah512EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)
func vistrutah512DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)

// Vistrutah256EncryptHW encrypts a 256-bit block using ARM Crypto
func Vistrutah256EncryptHW(plaintext, ciphertext, key []byte, rounds int) {
	if !CPU.HasARMCrypto {
		Vistrutah256Encrypt(plaintext, ciphertext, key, rounds)
		return
	}

	keySize := len(key)
	if keySize != 16 && keySize != 32 {
		panic("vistrutah256: key must be 16 or 32 bytes")
	}

	vistrutah256EncryptAsm(
		&plaintext[0], &ciphertext[0], &key[0],
		keySize, rounds,
		&vistrutahRoundConstants[0][0],
		&vistrutahP4[0], &vistrutahP5[0],
	)
}

// Vistrutah256DecryptHW decrypts a 256-bit block using ARM Crypto
func Vistrutah256DecryptHW(ciphertext, plaintext, key []byte, rounds int) {
	if !CPU.HasARMCrypto {
		Vistrutah256Decrypt(ciphertext, plaintext, key, rounds)
		return
	}

	keySize := len(key)
	if keySize != 16 && keySize != 32 {
		panic("vistrutah256: key must be 16 or 32 bytes")
	}

	vistrutah256DecryptAsm(
		&ciphertext[0], &plaintext[0], &key[0],
		keySize, rounds,
		&vistrutahRoundConstants[0][0],
		&vistrutahP4Inv[0], &vistrutahP5Inv[0],
	)
}

// Vistrutah512EncryptHW encrypts a 512-bit block using ARM Crypto
func Vistrutah512EncryptHW(plaintext, ciphertext, key []byte, rounds int) {
	if !CPU.HasARMCrypto {
		Vistrutah512Encrypt(plaintext, ciphertext, key, rounds)
		return
	}

	keySize := len(key)
	if keySize != 32 && keySize != 64 {
		panic("vistrutah512: key must be 32 or 64 bytes")
	}

	vistrutah512EncryptAsm(
		&plaintext[0], &ciphertext[0], &key[0],
		keySize, rounds,
		&vistrutahRoundConstants[0][0],
		&vistrutahKexpShuffle[0],
	)
}

// Vistrutah512DecryptHW decrypts a 512-bit block using ARM Crypto
func Vistrutah512DecryptHW(ciphertext, plaintext, key []byte, rounds int) {
	if !CPU.HasARMCrypto {
		Vistrutah512Decrypt(ciphertext, plaintext, key, rounds)
		return
	}

	keySize := len(key)
	if keySize != 32 && keySize != 64 {
		panic("vistrutah512: key must be 32 or 64 bytes")
	}

	vistrutah512DecryptAsm(
		&ciphertext[0], &plaintext[0], &key[0],
		keySize, rounds,
		&vistrutahRoundConstants[0][0],
		&vistrutahKexpShuffle[0],
	)
}
