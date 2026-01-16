package cymric

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from the Zig implementation
var testKey = [32]byte{
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
}

var testAD = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
var testNonce = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
var testPlaintext = []byte{0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}

func TestCymric1EncryptDecrypt_12_4_3(t *testing.T) {
	// Test case 1: Cymric1 with 12-byte nonce, 4-byte message, 3-byte AD
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:4]
	ad := testAD[:3]

	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	err := ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Encrypt failed: %v", err)
	}

	// Expected output from Zig implementation
	expected := "d17c93e9ad73aadd3b236dc271429d39791df3ee"
	got := hex.EncodeToString(append(ctext, tag[:]...))
	if got != expected {
		t.Errorf("Cymric1 (12, 4, 3) output mismatch:\n  got:  %s\n  want: %s", got, expected)
	}

	// Decrypt and verify
	ptext := make([]byte, len(ctext))
	err = ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Decrypt failed: %v", err)
	}

	if !bytes.Equal(ptext, msg) {
		t.Errorf("Decrypted plaintext mismatch:\n  got:  %x\n  want: %x", ptext, msg)
	}
}

func TestCymric1EncryptDecrypt_8_8_4(t *testing.T) {
	// Test case 2: Cymric1 with 8-byte nonce, 8-byte message, 4-byte AD
	ctx := NewContext(&testKey)

	nonce := testNonce[:8]
	msg := testPlaintext[:8]
	ad := testAD[:4]

	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	err := ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Encrypt failed: %v", err)
	}

	// Expected output from Zig implementation
	expected := "0483f0afe6eb84f4b88195894220e20d1440098b7a684d63"
	got := hex.EncodeToString(append(ctext, tag[:]...))
	if got != expected {
		t.Errorf("Cymric1 (8, 8, 4) output mismatch:\n  got:  %s\n  want: %s", got, expected)
	}

	// Decrypt and verify
	ptext := make([]byte, len(ctext))
	err = ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Decrypt failed: %v", err)
	}

	if !bytes.Equal(ptext, msg) {
		t.Errorf("Decrypted plaintext mismatch:\n  got:  %x\n  want: %x", ptext, msg)
	}
}

func TestCymric2EncryptDecrypt_12_16_3(t *testing.T) {
	// Test case 3: Cymric2 with 12-byte nonce, 16-byte message, 3-byte AD
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:16]
	ad := testAD[:3]

	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	err := ctx.Cymric2Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric2Encrypt failed: %v", err)
	}

	// Expected output from Zig implementation
	expected := "d17c93e97967b01dd662166c5518d49395a65518044e82d303cf236a31a9ac45"
	got := hex.EncodeToString(append(ctext, tag[:]...))
	if got != expected {
		t.Errorf("Cymric2 (12, 16, 3) output mismatch:\n  got:  %s\n  want: %s", got, expected)
	}

	// Decrypt and verify
	ptext := make([]byte, len(ctext))
	err = ctx.Cymric2Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric2Decrypt failed: %v", err)
	}

	if !bytes.Equal(ptext, msg) {
		t.Errorf("Decrypted plaintext mismatch:\n  got:  %x\n  want: %x", ptext, msg)
	}
}

func TestCymric1AuthenticationFailure(t *testing.T) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:4]
	ad := testAD[:3]

	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	err := ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Encrypt failed: %v", err)
	}

	// Corrupt the tag
	tag[0] ^= 0xff

	// Decrypt should fail
	ptext := make([]byte, len(ctext))
	err = ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != ErrAuthenticationFailed {
		t.Errorf("Expected authentication failure, got: %v", err)
	}

	// Output should be zeroed
	for i, b := range ptext {
		if b != 0 {
			t.Errorf("Output not zeroed at position %d: %02x", i, b)
		}
	}
}

func TestCymric2AuthenticationFailure(t *testing.T) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:16]
	ad := testAD[:3]

	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	err := ctx.Cymric2Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric2Encrypt failed: %v", err)
	}

	// Corrupt the ciphertext
	ctext[0] ^= 0xff

	// Decrypt should fail
	ptext := make([]byte, len(ctext))
	err = ctx.Cymric2Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != ErrAuthenticationFailed {
		t.Errorf("Expected authentication failure, got: %v", err)
	}

	// Output should be zeroed
	for i, b := range ptext {
		if b != 0 {
			t.Errorf("Output not zeroed at position %d: %02x", i, b)
		}
	}
}

func TestCymric1InputValidation(t *testing.T) {
	ctx := NewContext(&testKey)

	var tag [TagBytes]byte

	// Test: msg + nonce > 16
	err := ctx.Cymric1Encrypt(make([]byte, 10), &tag, make([]byte, 10), make([]byte, 0), make([]byte, 10))
	if err != ErrInvalidInputLength {
		t.Errorf("Expected ErrInvalidInputLength for msg+nonce > 16, got: %v", err)
	}

	// Test: nonce + ad > 15
	err = ctx.Cymric1Encrypt(make([]byte, 4), &tag, make([]byte, 4), make([]byte, 8), make([]byte, 8))
	if err != ErrInvalidInputLength {
		t.Errorf("Expected ErrInvalidInputLength for nonce+ad > 15, got: %v", err)
	}
}

func TestCymric2InputValidation(t *testing.T) {
	ctx := NewContext(&testKey)

	var tag [TagBytes]byte

	// Test: msg > 16
	err := ctx.Cymric2Encrypt(make([]byte, 17), &tag, make([]byte, 17), make([]byte, 0), make([]byte, 0))
	if err != ErrInvalidInputLength {
		t.Errorf("Expected ErrInvalidInputLength for msg > 16, got: %v", err)
	}

	// Test: nonce + ad > 15
	err = ctx.Cymric2Encrypt(make([]byte, 4), &tag, make([]byte, 4), make([]byte, 8), make([]byte, 8))
	if err != ErrInvalidInputLength {
		t.Errorf("Expected ErrInvalidInputLength for nonce+ad > 15, got: %v", err)
	}
}

func TestCymric1EmptyMessage(t *testing.T) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := []byte{}
	ad := testAD[:3]

	ctext := make([]byte, 0)
	var tag [TagBytes]byte

	err := ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Encrypt failed with empty message: %v", err)
	}

	// Decrypt and verify
	ptext := make([]byte, 0)
	err = ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric1Decrypt failed with empty message: %v", err)
	}
}

func TestCymric2EmptyMessage(t *testing.T) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := []byte{}
	ad := testAD[:3]

	ctext := make([]byte, 0)
	var tag [TagBytes]byte

	err := ctx.Cymric2Encrypt(ctext, &tag, msg, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric2Encrypt failed with empty message: %v", err)
	}

	// Decrypt and verify
	ptext := make([]byte, 0)
	err = ctx.Cymric2Decrypt(ptext, ctext, &tag, ad, nonce)
	if err != nil {
		t.Fatalf("Cymric2Decrypt failed with empty message: %v", err)
	}
}

func BenchmarkCymric1Encrypt(b *testing.B) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:4]
	ad := testAD[:3]
	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	b.ResetTimer()
	b.SetBytes(int64(len(msg)))

	for b.Loop() {
		_ = ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)
	}
}

func BenchmarkCymric1Decrypt(b *testing.B) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:4]
	ad := testAD[:3]
	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	_ = ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)

	ptext := make([]byte, len(ctext))

	b.ResetTimer()
	b.SetBytes(int64(len(msg)))

	for b.Loop() {
		_ = ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
	}
}

func BenchmarkCymric2Encrypt(b *testing.B) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:16]
	ad := testAD[:3]
	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	b.ResetTimer()
	b.SetBytes(int64(len(msg)))

	for b.Loop() {
		_ = ctx.Cymric2Encrypt(ctext, &tag, msg, ad, nonce)
	}
}

func BenchmarkCymric2Decrypt(b *testing.B) {
	ctx := NewContext(&testKey)

	nonce := testNonce[:12]
	msg := testPlaintext[:16]
	ad := testAD[:3]
	ctext := make([]byte, len(msg))
	var tag [TagBytes]byte

	_ = ctx.Cymric2Encrypt(ctext, &tag, msg, ad, nonce)

	ptext := make([]byte, len(ctext))

	b.ResetTimer()
	b.SetBytes(int64(len(msg)))

	for b.Loop() {
		_ = ctx.Cymric2Decrypt(ptext, ctext, &tag, ad, nonce)
	}
}
