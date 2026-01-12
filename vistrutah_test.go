package aes

import (
	"bytes"
	"testing"
)

// reverseBits reverses bits in a byte (matches reference implementation)
func reverseBits(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result = (result << 1) | (b & 1)
		b >>= 1
	}
	return result
}

// Reference test vectors from the C implementation
// Key: key[i] = reverseBits(i+1)
// Plaintext: plaintext[i] = i

func TestVistrutah256ReferenceVectors(t *testing.T) {
	// Prepare key and plaintext
	var key [32]byte
	var plaintext [32]byte
	for i := 0; i < 32; i++ {
		key[i] = reverseBits(byte(i + 1))
		plaintext[i] = byte(i)
	}

	tests := []struct {
		name     string
		rounds   int
		expected [32]byte
	}{
		{
			name:   "10 rounds (ROUNDS_SHORT)",
			rounds: Vistrutah256RoundsShort,
			expected: [32]byte{
				0xA9, 0x80, 0x3C, 0xC5, 0x4F, 0x27, 0x74, 0x53,
				0x66, 0xA4, 0xF7, 0xE7, 0x99, 0xA3, 0x4E, 0x24,
				0xF4, 0xC6, 0x9E, 0x37, 0xC2, 0x7E, 0x13, 0xC0,
				0x32, 0xD8, 0x0E, 0xE5, 0x7F, 0x9F, 0xA3, 0x6E,
			},
		},
		{
			name:   "14 rounds (ROUNDS_LONG)",
			rounds: Vistrutah256RoundsLong,
			expected: [32]byte{
				0x04, 0x22, 0x7D, 0x3C, 0xD0, 0x0D, 0x1C, 0x7B,
				0xE7, 0xDA, 0x78, 0x6B, 0x8C, 0x88, 0xF9, 0x59,
				0x4E, 0x11, 0x43, 0x17, 0x22, 0x1C, 0x74, 0x30,
				0xB4, 0x7E, 0xD2, 0x1E, 0x8E, 0xB1, 0x5B, 0xBD,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ciphertext [32]byte
			var decrypted [32]byte

			// Encrypt
			Vistrutah256Encrypt(plaintext[:], ciphertext[:], key[:], tc.rounds)

			if !bytes.Equal(ciphertext[:], tc.expected[:]) {
				t.Errorf("encryption mismatch:\n  got:      %x\n  expected: %x", ciphertext, tc.expected)
			}

			// Decrypt and verify round-trip
			Vistrutah256Decrypt(ciphertext[:], decrypted[:], key[:], tc.rounds)

			if !bytes.Equal(decrypted[:], plaintext[:]) {
				t.Errorf("decryption mismatch:\n  got:      %x\n  expected: %x", decrypted, plaintext)
			}
		})
	}
}

func TestVistrutah512ReferenceVectors(t *testing.T) {
	// Prepare key and plaintext
	var key [32]byte
	var plaintext [64]byte
	for i := 0; i < 32; i++ {
		key[i] = reverseBits(byte(i + 1))
	}
	for i := 0; i < 64; i++ {
		plaintext[i] = byte(i)
	}

	tests := []struct {
		name     string
		rounds   int
		expected [64]byte
	}{
		{
			name:   "10 rounds, 256-bit key (ROUNDS_SHORT_256KEY)",
			rounds: Vistrutah512RoundsShort256Key,
			expected: [64]byte{
				0x09, 0xC3, 0x87, 0x69, 0x84, 0x35, 0x50, 0x41, 0xA4, 0x9A,
				0xCF, 0x0C, 0xB8, 0x68, 0xE2, 0x64, 0x58, 0x52, 0x35, 0xE0,
				0x58, 0x20, 0x05, 0x5C, 0x80, 0x8A, 0x3A, 0x03, 0xEA, 0xAE,
				0x15, 0x7B, 0x00, 0x10, 0x0B, 0xC9, 0xB3, 0x01, 0x16, 0x96,
				0xC0, 0xE1, 0xE8, 0x95, 0xE2, 0x16, 0x0C, 0xCC, 0xEF, 0x31,
				0xA3, 0x45, 0x4E, 0x21, 0x6C, 0xA0, 0x1B, 0xCF, 0x63, 0x66,
				0xF5, 0x84, 0xE2, 0x36,
			},
		},
		{
			name:   "12 rounds, 256-bit key (ROUNDS_SHORT_512KEY)",
			rounds: Vistrutah512RoundsShort512Key,
			expected: [64]byte{
				0xA6, 0x90, 0x27, 0x48, 0xC6, 0xF1, 0xF9, 0x33, 0x3C, 0xA6,
				0x12, 0xB8, 0x5F, 0x86, 0x56, 0x1F, 0xD0, 0x46, 0x62, 0xE3,
				0xC4, 0x05, 0xAC, 0x50, 0x13, 0x16, 0x82, 0x6A, 0x70, 0x2F,
				0xCD, 0x4A, 0x23, 0x45, 0x94, 0xF8, 0xF9, 0xA5, 0xDD, 0xA2,
				0x78, 0xD4, 0x4C, 0xC7, 0x23, 0xF5, 0xB8, 0x76, 0x72, 0x00,
				0x0E, 0x42, 0x37, 0xE3, 0x82, 0x39, 0xC1, 0xBC, 0x06, 0x59,
				0x1D, 0xE6, 0x29, 0x7C,
			},
		},
		{
			name:   "14 rounds, 256-bit key (ROUNDS_LONG_256KEY)",
			rounds: Vistrutah512RoundsLong256Key,
			expected: [64]byte{
				0xA8, 0x75, 0xE9, 0xF9, 0x13, 0x0B, 0xE6, 0x8B, 0x68, 0x67,
				0xCB, 0x66, 0xF4, 0x03, 0x18, 0xEC, 0x7E, 0x16, 0xA3, 0xA0,
				0x50, 0x16, 0x51, 0xFF, 0xF3, 0xBE, 0x08, 0xFE, 0x70, 0xB3,
				0xC7, 0x96, 0x0D, 0x9B, 0x1A, 0x83, 0x44, 0xC9, 0xEB, 0x61,
				0xC2, 0xBF, 0xCB, 0xF2, 0xF6, 0x02, 0x8E, 0x1F, 0xCD, 0x94,
				0x6B, 0xFF, 0xC9, 0x5B, 0xB4, 0x2F, 0x9E, 0x0E, 0x87, 0x61,
				0x75, 0x83, 0x19, 0xE3,
			},
		},
		{
			name:   "18 rounds, 256-bit key (ROUNDS_LONG_512KEY)",
			rounds: Vistrutah512RoundsLong512Key,
			expected: [64]byte{
				0x6D, 0x7F, 0x18, 0x33, 0x6B, 0x35, 0xED, 0x4D, 0x78, 0x5D,
				0xF2, 0x2D, 0xCE, 0x13, 0x49, 0x35, 0xAF, 0x3F, 0xC1, 0x4F,
				0xD7, 0xC3, 0x80, 0x48, 0x85, 0x3E, 0xEE, 0x54, 0x02, 0x1C,
				0xFB, 0x56, 0xBD, 0x30, 0x66, 0x96, 0xAD, 0x4C, 0x1E, 0x49,
				0x82, 0xFD, 0x41, 0x36, 0xB5, 0x7D, 0x65, 0xEE, 0x0F, 0xE4,
				0xB0, 0xC1, 0x05, 0x43, 0xDB, 0x5C, 0x9C, 0xAF, 0xFB, 0x7C,
				0xBD, 0x26, 0x61, 0x13,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ciphertext [64]byte
			var decrypted [64]byte

			// Encrypt
			Vistrutah512Encrypt(plaintext[:], ciphertext[:], key[:], tc.rounds)

			if !bytes.Equal(ciphertext[:], tc.expected[:]) {
				t.Errorf("encryption mismatch:\n  got:      %x\n  expected: %x", ciphertext, tc.expected)
			}

			// Decrypt and verify round-trip
			Vistrutah512Decrypt(ciphertext[:], decrypted[:], key[:], tc.rounds)

			if !bytes.Equal(decrypted[:], plaintext[:]) {
				t.Errorf("decryption mismatch:\n  got:      %x\n  expected: %x", decrypted, plaintext)
			}
		})
	}
}

func TestVistrutah256RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		keySize  int
		rounds   int
		patterns []struct {
			name string
			data func() (key, pt []byte)
		}
	}{
		{
			name:    "128-bit key, 10 rounds",
			keySize: 16,
			rounds:  Vistrutah256RoundsShort,
		},
		{
			name:    "256-bit key, 10 rounds",
			keySize: 32,
			rounds:  Vistrutah256RoundsShort,
		},
		{
			name:    "256-bit key, 14 rounds",
			keySize: 32,
			rounds:  Vistrutah256RoundsLong,
		},
	}

	patterns := []struct {
		name string
		key  [32]byte
		pt   [32]byte
	}{
		{
			name: "all zeros",
			key:  [32]byte{},
			pt:   [32]byte{},
		},
		{
			name: "all ones",
			key:  [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			pt:   [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "sequential",
			key:  [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
			pt:   [32]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		},
	}

	for _, tc := range tests {
		for _, p := range patterns {
			t.Run(tc.name+"/"+p.name, func(t *testing.T) {
				var ciphertext [32]byte
				var decrypted [32]byte

				key := p.key[:tc.keySize]

				Vistrutah256Encrypt(p.pt[:], ciphertext[:], key, tc.rounds)
				Vistrutah256Decrypt(ciphertext[:], decrypted[:], key, tc.rounds)

				if !bytes.Equal(decrypted[:], p.pt[:]) {
					t.Errorf("round-trip failed:\n  plaintext: %x\n  decrypted: %x", p.pt, decrypted)
				}
			})
		}
	}
}

func TestVistrutah512RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		rounds  int
	}{
		{"256-bit key, 10 rounds", 32, Vistrutah512RoundsShort256Key},
		{"256-bit key, 12 rounds", 32, Vistrutah512RoundsShort512Key},
		{"256-bit key, 14 rounds", 32, Vistrutah512RoundsLong256Key},
		{"256-bit key, 18 rounds", 32, Vistrutah512RoundsLong512Key},
		{"512-bit key, 12 rounds", 64, Vistrutah512RoundsShort512Key},
		{"512-bit key, 18 rounds", 64, Vistrutah512RoundsLong512Key},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test with sequential pattern
			var key [64]byte
			var plaintext [64]byte
			for i := 0; i < 64; i++ {
				key[i] = byte(i)
				plaintext[i] = byte(i * 17)
			}

			var ciphertext [64]byte
			var decrypted [64]byte

			Vistrutah512Encrypt(plaintext[:], ciphertext[:], key[:tc.keySize], tc.rounds)
			Vistrutah512Decrypt(ciphertext[:], decrypted[:], key[:tc.keySize], tc.rounds)

			if !bytes.Equal(decrypted[:], plaintext[:]) {
				t.Errorf("round-trip failed:\n  plaintext: %x\n  decrypted: %x", plaintext, decrypted)
			}
		})
	}
}

func TestMixingLayer256(t *testing.T) {
	// Test that mixing layer is self-inverse (after applying inv)
	var s0, s1 Block
	for i := 0; i < 16; i++ {
		s0[i] = byte(i)
		s1[i] = byte(i + 16)
	}
	original0, original1 := s0, s1

	mixingLayer256(&s0, &s1)
	invMixingLayer256(&s0, &s1)

	if s0 != original0 || s1 != original1 {
		t.Errorf("mixing layer inverse failed:\n  got:      %x %x\n  expected: %x %x", s0, s1, original0, original1)
	}
}

func TestMixingLayer512(t *testing.T) {
	var s0, s1, s2, s3 Block
	for i := 0; i < 16; i++ {
		s0[i] = byte(i)
		s1[i] = byte(i + 16)
		s2[i] = byte(i + 32)
		s3[i] = byte(i + 48)
	}
	original0, original1, original2, original3 := s0, s1, s2, s3

	mixingLayer512(&s0, &s1, &s2, &s3)
	invMixingLayer512(&s0, &s1, &s2, &s3)

	if s0 != original0 || s1 != original1 || s2 != original2 || s3 != original3 {
		t.Errorf("mixing layer 512 inverse failed")
	}
}

func BenchmarkVistrutah256Encrypt(b *testing.B) {
	var key [32]byte
	var plaintext [32]byte
	var ciphertext [32]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
		plaintext[i] = byte(i)
	}

	b.ResetTimer()
	b.SetBytes(32)

	for range b.N {
		Vistrutah256Encrypt(plaintext[:], ciphertext[:], key[:], Vistrutah256RoundsLong)
	}
}

func BenchmarkVistrutah256Decrypt(b *testing.B) {
	var key [32]byte
	var plaintext [32]byte
	var ciphertext [32]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
		plaintext[i] = byte(i)
	}

	Vistrutah256Encrypt(plaintext[:], ciphertext[:], key[:], Vistrutah256RoundsLong)

	b.ResetTimer()
	b.SetBytes(32)

	for range b.N {
		Vistrutah256Decrypt(ciphertext[:], plaintext[:], key[:], Vistrutah256RoundsLong)
	}
}

func BenchmarkVistrutah512Encrypt(b *testing.B) {
	var key [32]byte
	var plaintext [64]byte
	var ciphertext [64]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		plaintext[i] = byte(i)
	}

	b.ResetTimer()
	b.SetBytes(64)

	for range b.N {
		Vistrutah512Encrypt(plaintext[:], ciphertext[:], key[:], Vistrutah512RoundsLong256Key)
	}
}

func BenchmarkVistrutah512Decrypt(b *testing.B) {
	var key [32]byte
	var plaintext [64]byte
	var ciphertext [64]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		plaintext[i] = byte(i)
	}

	Vistrutah512Encrypt(plaintext[:], ciphertext[:], key[:], Vistrutah512RoundsLong256Key)

	b.ResetTimer()
	b.SetBytes(64)

	for range b.N {
		Vistrutah512Decrypt(ciphertext[:], plaintext[:], key[:], Vistrutah512RoundsLong256Key)
	}
}

func TestVistrutahHWMatchesSW(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("no hardware AES support")
	}

	t.Run("Vistrutah256", func(t *testing.T) {
		for _, rounds := range []int{Vistrutah256RoundsShort, Vistrutah256RoundsLong} {
			for _, keySize := range []int{16, 32} {
				var key [32]byte
				var plaintext [32]byte
				for i := range key {
					key[i] = byte(i * 7)
				}
				for i := range plaintext {
					plaintext[i] = byte(i * 11)
				}

				var ctSW, ctHW [32]byte
				Vistrutah256Encrypt(plaintext[:], ctSW[:], key[:keySize], rounds)
				Vistrutah256EncryptHW(plaintext[:], ctHW[:], key[:keySize], rounds)

				if ctSW != ctHW {
					t.Errorf("encrypt mismatch (rounds=%d, keySize=%d):\n  SW: %x\n  HW: %x", rounds, keySize, ctSW, ctHW)
				}

				var ptSW, ptHW [32]byte
				Vistrutah256Decrypt(ctSW[:], ptSW[:], key[:keySize], rounds)
				Vistrutah256DecryptHW(ctSW[:], ptHW[:], key[:keySize], rounds)

				if ptSW != ptHW {
					t.Errorf("decrypt mismatch (rounds=%d, keySize=%d):\n  SW: %x\n  HW: %x", rounds, keySize, ptSW, ptHW)
				}

				if ptSW != plaintext {
					t.Errorf("round-trip failed (rounds=%d, keySize=%d)", rounds, keySize)
				}
			}
		}
	})

	t.Run("Vistrutah512", func(t *testing.T) {
		for _, rounds := range []int{Vistrutah512RoundsShort256Key, Vistrutah512RoundsShort512Key, Vistrutah512RoundsLong256Key, Vistrutah512RoundsLong512Key} {
			for _, keySize := range []int{32, 64} {
				var key [64]byte
				var plaintext [64]byte
				for i := range key {
					key[i] = byte(i * 7)
				}
				for i := range plaintext {
					plaintext[i] = byte(i * 11)
				}

				var ctSW, ctHW [64]byte
				Vistrutah512Encrypt(plaintext[:], ctSW[:], key[:keySize], rounds)
				Vistrutah512EncryptHW(plaintext[:], ctHW[:], key[:keySize], rounds)

				if ctSW != ctHW {
					t.Errorf("encrypt mismatch (rounds=%d, keySize=%d):\n  SW: %x\n  HW: %x", rounds, keySize, ctSW, ctHW)
				}

				var ptSW, ptHW [64]byte
				Vistrutah512Decrypt(ctSW[:], ptSW[:], key[:keySize], rounds)
				Vistrutah512DecryptHW(ctSW[:], ptHW[:], key[:keySize], rounds)

				if ptSW != ptHW {
					t.Errorf("decrypt mismatch (rounds=%d, keySize=%d):\n  SW: %x\n  HW: %x", rounds, keySize, ptSW, ptHW)
				}

				if ptSW != plaintext {
					t.Errorf("round-trip failed (rounds=%d, keySize=%d)", rounds, keySize)
				}
			}
		}
	})
}

func BenchmarkVistrutah256EncryptHW(b *testing.B) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		b.Skip("no hardware AES support")
	}

	var key [32]byte
	var plaintext [32]byte
	var ciphertext [32]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
		plaintext[i] = byte(i)
	}

	b.ResetTimer()
	b.SetBytes(32)

	for range b.N {
		Vistrutah256EncryptHW(plaintext[:], ciphertext[:], key[:], Vistrutah256RoundsLong)
	}
}

func BenchmarkVistrutah256DecryptHW(b *testing.B) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		b.Skip("no hardware AES support")
	}

	var key [32]byte
	var plaintext [32]byte
	var ciphertext [32]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
		plaintext[i] = byte(i)
	}

	Vistrutah256EncryptHW(plaintext[:], ciphertext[:], key[:], Vistrutah256RoundsLong)

	b.ResetTimer()
	b.SetBytes(32)

	for range b.N {
		Vistrutah256DecryptHW(ciphertext[:], plaintext[:], key[:], Vistrutah256RoundsLong)
	}
}

func BenchmarkVistrutah512EncryptHW(b *testing.B) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		b.Skip("no hardware AES support")
	}

	var key [32]byte
	var plaintext [64]byte
	var ciphertext [64]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		plaintext[i] = byte(i)
	}

	b.ResetTimer()
	b.SetBytes(64)

	for range b.N {
		Vistrutah512EncryptHW(plaintext[:], ciphertext[:], key[:], Vistrutah512RoundsLong256Key)
	}
}

func BenchmarkVistrutah512DecryptHW(b *testing.B) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		b.Skip("no hardware AES support")
	}

	var key [32]byte
	var plaintext [64]byte
	var ciphertext [64]byte

	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 64; i++ {
		plaintext[i] = byte(i)
	}

	Vistrutah512EncryptHW(plaintext[:], ciphertext[:], key[:], Vistrutah512RoundsLong256Key)

	b.ResetTimer()
	b.SetBytes(64)

	for range b.N {
		Vistrutah512DecryptHW(ciphertext[:], plaintext[:], key[:], Vistrutah512RoundsLong256Key)
	}
}
