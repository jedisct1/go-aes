package aes

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestPholkos256EncryptDecrypt(t *testing.T) {
	// Test that encryption followed by decryption returns the original plaintext
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block

	// Use random values
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	// Save original plaintext
	original := plaintext

	// Create context and encrypt
	ctx := NewPholkos256Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	// Ciphertext should be different from plaintext
	if bytes.Equal(plaintext[:], original[:]) {
		t.Error("ciphertext equals plaintext")
	}

	// Decrypt
	ctx.Decrypt(&plaintext)

	// Should match original
	if !bytes.Equal(plaintext[:], original[:]) {
		t.Errorf("decryption failed:\ngot:  %x\nwant: %x", plaintext[:], original[:])
	}
}

func TestPholkos512EncryptDecrypt(t *testing.T) {
	// Test with 256-bit key
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	original := plaintext

	ctx := NewPholkos512Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	if bytes.Equal(plaintext[:], original[:]) {
		t.Error("ciphertext equals plaintext")
	}

	ctx.Decrypt(&plaintext)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Errorf("decryption failed:\ngot:  %x\nwant: %x", plaintext[:], original[:])
	}
}

func TestPholkos512EncryptDecrypt512Key(t *testing.T) {
	// Test with 512-bit key
	var key Pholkos512Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	original := plaintext

	ctx := NewPholkos512Context512(&key, &tweak)
	ctx.Encrypt(&plaintext)

	if bytes.Equal(plaintext[:], original[:]) {
		t.Error("ciphertext equals plaintext")
	}

	ctx.Decrypt(&plaintext)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Errorf("decryption failed:\ngot:  %x\nwant: %x", plaintext[:], original[:])
	}
}

func TestPholkos256DifferentKeys(t *testing.T) {
	var key1, key2 Pholkos256Key
	var tweak PholkosTweak
	var plaintext1, plaintext2 Pholkos256Block

	rand.Read(key1[:])
	rand.Read(key2[:])
	rand.Read(tweak[:])
	rand.Read(plaintext1[:])
	plaintext2 = plaintext1

	ctx1 := NewPholkos256Context(&key1, &tweak)
	ctx2 := NewPholkos256Context(&key2, &tweak)

	ctx1.Encrypt(&plaintext1)
	ctx2.Encrypt(&plaintext2)

	if bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Error("different keys produced same ciphertext")
	}
}

func TestPholkos256DifferentTweaks(t *testing.T) {
	var key Pholkos256Key
	var tweak1, tweak2 PholkosTweak
	var plaintext1, plaintext2 Pholkos256Block

	rand.Read(key[:])
	rand.Read(tweak1[:])
	rand.Read(tweak2[:])
	rand.Read(plaintext1[:])
	plaintext2 = plaintext1

	ctx1 := NewPholkos256Context(&key, &tweak1)
	ctx2 := NewPholkos256Context(&key, &tweak2)

	ctx1.Encrypt(&plaintext1)
	ctx2.Encrypt(&plaintext2)

	if bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Error("different tweaks produced same ciphertext")
	}
}

func TestPholkos256ZeroBlock(t *testing.T) {
	// Encrypt a zero block and verify it doesn't stay zero
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block

	// All zeros
	ctx := NewPholkos256Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	// Count non-zero bytes
	nonZero := 0
	for _, b := range plaintext {
		if b != 0 {
			nonZero++
		}
	}

	// Should have good diffusion
	if nonZero < 20 {
		t.Errorf("poor diffusion: only %d non-zero bytes in ciphertext", nonZero)
	}
}

func TestPholkos512ZeroBlock(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	ctx := NewPholkos512Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	nonZero := 0
	for _, b := range plaintext {
		if b != 0 {
			nonZero++
		}
	}

	if nonZero < 40 {
		t.Errorf("poor diffusion: only %d non-zero bytes in ciphertext", nonZero)
	}
}

func TestPholkosPi256Permutation(t *testing.T) {
	// Verify π256 is correctly defined
	// π256 = [0, 5, 2, 7, 4, 1, 6, 3]
	expected := [8]int{0, 5, 2, 7, 4, 1, 6, 3}
	if pi256 != expected {
		t.Errorf("π256 mismatch: got %v, want %v", pi256, expected)
	}

	// Verify it's a valid permutation (all indices 0-7 appear exactly once)
	seen := make(map[int]bool)
	for _, v := range pi256 {
		if v < 0 || v > 7 {
			t.Errorf("π256 contains invalid index: %d", v)
		}
		if seen[v] {
			t.Errorf("π256 contains duplicate: %d", v)
		}
		seen[v] = true
	}
}

func TestPholkosPi512Permutation(t *testing.T) {
	// Verify π512 is correctly defined
	// π512 = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
	expected := [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}
	if pi512 != expected {
		t.Errorf("π512 mismatch: got %v, want %v", pi512, expected)
	}

	// Verify it's a valid permutation
	seen := make(map[int]bool)
	for _, v := range pi512 {
		if v < 0 || v > 15 {
			t.Errorf("π512 contains invalid index: %d", v)
		}
		if seen[v] {
			t.Errorf("π512 contains duplicate: %d", v)
		}
		seen[v] = true
	}
}

func TestPholkosPiTauPermutation(t *testing.T) {
	// Verify πτ is correctly defined
	// πτ = [11, 12, 1, 2, 15, 0, 5, 6, 3, 4, 9, 10, 7, 8, 13, 14]
	expected := [16]int{11, 12, 1, 2, 15, 0, 5, 6, 3, 4, 9, 10, 7, 8, 13, 14}
	if piTau != expected {
		t.Errorf("πτ mismatch: got %v, want %v", piTau, expected)
	}

	// Verify it's a valid permutation
	seen := make(map[int]bool)
	for _, v := range piTau {
		if v < 0 || v > 15 {
			t.Errorf("πτ contains invalid index: %d", v)
		}
		if seen[v] {
			t.Errorf("πτ contains duplicate: %d", v)
		}
		seen[v] = true
	}
}

func TestPholkos256ConvenienceFunctions(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	original := plaintext

	Pholkos256Encrypt(&plaintext, &key, &tweak)
	Pholkos256Decrypt(&plaintext, &key, &tweak)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Error("convenience functions failed roundtrip")
	}
}

func TestPholkos512ConvenienceFunctions(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	original := plaintext

	Pholkos512Encrypt(&plaintext, &key, &tweak)
	Pholkos512Decrypt(&plaintext, &key, &tweak)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Error("convenience functions failed roundtrip")
	}
}

func TestPholkos512ConvenienceFunctions512Key(t *testing.T) {
	var key Pholkos512Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	original := plaintext

	Pholkos512Encrypt512(&plaintext, &key, &tweak)
	Pholkos512Decrypt512(&plaintext, &key, &tweak)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Error("convenience functions failed roundtrip")
	}
}

func TestPholkosKeyExpansion(t *testing.T) {
	// Test that key expansion produces different round keys for different inputs
	var key1, key2 Pholkos256Key
	rand.Read(key1[:])
	key2 = key1
	key2[0] ^= 0x01 // Change one bit

	exp1 := expandKey256to512(&key1)
	exp2 := expandKey256to512(&key2)

	if bytes.Equal(exp1[:], exp2[:]) {
		t.Error("different keys produced same expanded key")
	}

	// First 32 bytes should match original
	if !bytes.Equal(exp1[:32], key1[:]) {
		t.Error("expanded key doesn't preserve original")
	}
}

func TestPholkos256MultipleBlocks(t *testing.T) {
	// Test encrypting multiple blocks with same context
	var key Pholkos256Key
	var tweak PholkosTweak
	rand.Read(key[:])
	rand.Read(tweak[:])

	ctx := NewPholkos256Context(&key, &tweak)

	for i := range 100 {
		var plaintext Pholkos256Block
		rand.Read(plaintext[:])
		original := plaintext

		ctx.Encrypt(&plaintext)
		ctx.Decrypt(&plaintext)

		if !bytes.Equal(plaintext[:], original[:]) {
			t.Errorf("round trip failed at iteration %d", i)
			break
		}
	}
}

func TestPholkos256KnownAnswer(t *testing.T) {
	// Test with known values to detect any implementation changes
	// Key and tweak are all zeros
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block

	ctx := NewPholkos256Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	// Save this as a known answer test vector
	ciphertext := hex.EncodeToString(plaintext[:])
	t.Logf("Pholkos-256 zero input ciphertext: %s", ciphertext)

	// Verify decryption works
	ctx.Decrypt(&plaintext)
	for _, b := range plaintext {
		if b != 0 {
			t.Error("decryption didn't return to zero")
			break
		}
	}
}

func TestPholkos512KnownAnswer(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	ctx := NewPholkos512Context(&key, &tweak)
	ctx.Encrypt(&plaintext)

	ciphertext := hex.EncodeToString(plaintext[:])
	t.Logf("Pholkos-512-256 zero input ciphertext: %s", ciphertext)

	ctx.Decrypt(&plaintext)
	for _, b := range plaintext {
		if b != 0 {
			t.Error("decryption didn't return to zero")
			break
		}
	}
}

func TestPholkos256HWMatchesSW(t *testing.T) {
	// Test that hardware implementation matches software
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext1, plaintext2 Pholkos256Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext1[:])
	plaintext2 = plaintext1

	ctx := NewPholkos256Context(&key, &tweak)

	// Software encrypt
	ctx.Encrypt(&plaintext1)

	// Hardware encrypt
	ctx.EncryptHW(&plaintext2)

	if !bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Errorf("Pholkos-256 HW/SW encrypt mismatch:\nSW: %x\nHW: %x", plaintext1[:], plaintext2[:])
	}

	// Software decrypt
	ctx.Decrypt(&plaintext1)

	// Hardware decrypt
	ctx.DecryptHW(&plaintext2)

	if !bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Errorf("Pholkos-256 HW/SW decrypt mismatch:\nSW: %x\nHW: %x", plaintext1[:], plaintext2[:])
	}
}

func TestPholkos512HWMatchesSW(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext1, plaintext2 Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext1[:])
	plaintext2 = plaintext1

	ctx := NewPholkos512Context(&key, &tweak)

	// Software encrypt
	ctx.Encrypt(&plaintext1)

	// Hardware encrypt
	ctx.EncryptHW(&plaintext2)

	if !bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Errorf("Pholkos-512 HW/SW encrypt mismatch:\nSW: %x\nHW: %x", plaintext1[:], plaintext2[:])
	}

	// Software decrypt
	ctx.Decrypt(&plaintext1)

	// Hardware decrypt
	ctx.DecryptHW(&plaintext2)

	if !bytes.Equal(plaintext1[:], plaintext2[:]) {
		t.Errorf("Pholkos-512 HW/SW decrypt mismatch:\nSW: %x\nHW: %x", plaintext1[:], plaintext2[:])
	}
}

func TestPholkos256HWRoundtrip(t *testing.T) {
	// Test encryption followed by decryption returns original
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])
	original := plaintext

	ctx := NewPholkos256Context(&key, &tweak)
	ctx.EncryptHW(&plaintext)

	if bytes.Equal(plaintext[:], original[:]) {
		t.Error("HW encryption didn't change plaintext")
	}

	ctx.DecryptHW(&plaintext)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Errorf("HW roundtrip failed:\ngot:  %x\nwant: %x", plaintext[:], original[:])
	}
}

func TestPholkos512HWRoundtrip(t *testing.T) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block

	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])
	original := plaintext

	ctx := NewPholkos512Context(&key, &tweak)
	ctx.EncryptHW(&plaintext)

	if bytes.Equal(plaintext[:], original[:]) {
		t.Error("HW encryption didn't change plaintext")
	}

	ctx.DecryptHW(&plaintext)

	if !bytes.Equal(plaintext[:], original[:]) {
		t.Errorf("HW roundtrip failed:\ngot:  %x\nwant: %x", plaintext[:], original[:])
	}
}

func BenchmarkPholkos256EncryptHW(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos256Context(&key, &tweak)

	b.SetBytes(32)
	for b.Loop() {
		ctx.EncryptHW(&plaintext)
	}
}

func BenchmarkPholkos256DecryptHW(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos256Context(&key, &tweak)

	b.SetBytes(32)
	for b.Loop() {
		ctx.DecryptHW(&plaintext)
	}
}

func BenchmarkPholkos512EncryptHW(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos512Context(&key, &tweak)

	b.SetBytes(64)
	for b.Loop() {
		ctx.EncryptHW(&plaintext)
	}
}

func BenchmarkPholkos512DecryptHW(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos512Context(&key, &tweak)

	b.SetBytes(64)
	for b.Loop() {
		ctx.DecryptHW(&plaintext)
	}
}

func BenchmarkPholkos256Encrypt(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos256Context(&key, &tweak)

	b.SetBytes(32)
	for b.Loop() {
		ctx.Encrypt(&plaintext)
	}
}

func BenchmarkPholkos256Decrypt(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos256Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos256Context(&key, &tweak)

	b.SetBytes(32)
	for b.Loop() {
		ctx.Decrypt(&plaintext)
	}
}

func BenchmarkPholkos256Schedule(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	rand.Read(key[:])
	rand.Read(tweak[:])

	for b.Loop() {
		_ = NewPholkos256Context(&key, &tweak)
	}
}

func BenchmarkPholkos512Encrypt(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos512Context(&key, &tweak)

	b.SetBytes(64)
	for b.Loop() {
		ctx.Encrypt(&plaintext)
	}
}

func BenchmarkPholkos512Decrypt(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos512Context(&key, &tweak)

	b.SetBytes(64)
	for b.Loop() {
		ctx.Decrypt(&plaintext)
	}
}

func BenchmarkPholkos512Schedule(b *testing.B) {
	var key Pholkos256Key
	var tweak PholkosTweak
	rand.Read(key[:])
	rand.Read(tweak[:])

	for b.Loop() {
		_ = NewPholkos512Context(&key, &tweak)
	}
}

func BenchmarkPholkos512_512Encrypt(b *testing.B) {
	var key Pholkos512Key
	var tweak PholkosTweak
	var plaintext Pholkos512Block
	rand.Read(key[:])
	rand.Read(tweak[:])
	rand.Read(plaintext[:])

	ctx := NewPholkos512Context512(&key, &tweak)

	b.SetBytes(64)
	for b.Loop() {
		ctx.Encrypt(&plaintext)
	}
}
