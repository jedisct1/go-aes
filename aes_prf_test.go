package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAESPRFBasic tests basic AES-PRF functionality
func TestAESPRFBasic(t *testing.T) {
	// Test with all zeros
	key := make([]byte, 16)
	input := make([]byte, 16)

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	var block Block
	copy(block[:], input)

	prf.PRF(&block)

	// The output should be deterministic and non-zero
	if bytes.Equal(block[:], input) {
		t.Error("PRF output equals input (should be different)")
	}

	// Verify that the same input produces the same output
	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block[:], block2[:]) {
		t.Error("PRF is not deterministic")
	}
}

// TestAESPRFDeterministic verifies that same inputs produce same outputs
func TestAESPRFDeterministic(t *testing.T) {
	key := []byte("0123456789abcdef")
	input := []byte("fedcba9876543210")

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	var block1 Block
	copy(block1[:], input)
	prf.PRF(&block1)

	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block1[:], block2[:]) {
		t.Errorf("PRF is not deterministic\nFirst: %x\nSecond: %x",
			block1, block2)
	}
}

// TestAESPRFDifferentInputs tests that different inputs produce different outputs
func TestAESPRFDifferentInputs(t *testing.T) {
	key := make([]byte, 16)
	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	input1 := make([]byte, 16)
	input2 := make([]byte, 16)
	input2[0] = 1

	var block1 Block
	copy(block1[:], input1)
	prf.PRF(&block1)

	var block2 Block
	copy(block2[:], input2)
	prf.PRF(&block2)

	if bytes.Equal(block1[:], block2[:]) {
		t.Error("Different inputs produced same output")
	}
}

// TestAESPRFDifferentKeys tests that different keys produce different outputs
func TestAESPRFDifferentKeys(t *testing.T) {
	input := make([]byte, 16)

	key1 := make([]byte, 16)
	prf1, err := NewAESPRF(key1)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	key2 := make([]byte, 16)
	key2[0] = 1
	prf2, err := NewAESPRF(key2)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	var block1 Block
	copy(block1[:], input)
	prf1.PRF(&block1)

	var block2 Block
	copy(block2[:], input)
	prf2.PRF(&block2)

	if bytes.Equal(block1[:], block2[:]) {
		t.Error("Different keys produced same output")
	}
}

// TestAESPRFWithAES192 tests AES-PRF with AES-192 key
func TestAESPRFWithAES192(t *testing.T) {
	key := make([]byte, 24) // AES-192 key
	input := make([]byte, 16)

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF with AES-192 key failed: %v", err)
	}

	var block Block
	copy(block[:], input)
	prf.PRF(&block)

	// Should produce deterministic output
	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block[:], block2[:]) {
		t.Error("PRF with AES-192 key is not deterministic")
	}
}

// TestAESPRFWithAES256 tests AES-PRF with AES-256 key
func TestAESPRFWithAES256(t *testing.T) {
	key := make([]byte, 32) // AES-256 key
	input := make([]byte, 16)

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF with AES-256 key failed: %v", err)
	}

	var block Block
	copy(block[:], input)
	prf.PRF(&block)

	// Should produce deterministic output
	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block[:], block2[:]) {
		t.Error("PRF with AES-256 key is not deterministic")
	}
}

// TestAESPRFTestVector tests with a known test vector
// This test vector can be updated once we have reference implementation outputs
func TestAESPRFTestVector(t *testing.T) {
	// Key: 16 bytes of zeros
	key, _ := hex.DecodeString("00000000000000000000000000000000")

	// Input: 16 bytes of zeros
	input, _ := hex.DecodeString("00000000000000000000000000000000")

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	var block Block
	copy(block[:], input)
	prf.PRF(&block)

	// Output (this will be the reference once we verify the implementation)
	output := hex.EncodeToString(block[:])
	t.Logf("Test vector - Key: all zeros, Input: all zeros\nOutput: %s", output)

	// PRF should produce deterministic output
	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block[:], block2[:]) {
		t.Error("PRF is not deterministic for test vector")
	}
}

// TestAESPRFTestVector2 tests with another test vector
func TestAESPRFTestVector2(t *testing.T) {
	// Key: sequential bytes
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Input: sequential bytes
	input, _ := hex.DecodeString("00112233445566778899aabbccddeeff")

	prf, err := NewAESPRF(key)
	if err != nil {
		t.Fatalf("NewAESPRF failed: %v", err)
	}

	var block Block
	copy(block[:], input)
	prf.PRF(&block)

	// Output (this will be the reference once we verify the implementation)
	output := hex.EncodeToString(block[:])
	t.Logf("Test vector 2 - Key: %x, Input: %x\nOutput: %s", key, input, output)

	// PRF should produce deterministic output
	var block2 Block
	copy(block2[:], input)
	prf.PRF(&block2)

	if !bytes.Equal(block[:], block2[:]) {
		t.Error("PRF is not deterministic for test vector 2")
	}
}

// BenchmarkAESPRF benchmarks the AES-PRF implementation
func BenchmarkAESPRF(b *testing.B) {
	key := make([]byte, 16)
	input := make([]byte, 16)

	prf, err := NewAESPRF(key)
	if err != nil {
		b.Fatalf("NewAESPRF failed: %v", err)
	}

	var block Block
	copy(block[:], input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(block[:], input)
		prf.PRF(&block)
	}
}
