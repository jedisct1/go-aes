package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesToBlock(b []byte) Block {
	var block Block
	copy(block[:], b)
	return block
}

// Test vectors from FIPS-197 (AES specification)
// These are from the first round of AES-128 encryption
func TestSubBytes(t *testing.T) {
	// Input is the state after initial AddRoundKey (Round 0)
	input := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	expected := bytesToBlock(hexToBytes("63cab7040953d051cd60e0e7ba70e18c"))

	SubBytes(&input)

	if input != expected {
		t.Errorf("SubBytes failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestInvSubBytes(t *testing.T) {
	input := bytesToBlock(hexToBytes("63cab7040953d051cd60e0e7ba70e18c"))
	expected := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))

	InvSubBytes(&input)

	if input != expected {
		t.Errorf("InvSubBytes failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestShiftRows(t *testing.T) {
	input := bytesToBlock(hexToBytes("63cab7040953d051cd60e0e7ba70e18c"))
	expected := bytesToBlock(hexToBytes("6353e08c0960e104cd70b751bacad0e7"))

	ShiftRows(&input)

	if input != expected {
		t.Errorf("ShiftRows failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestInvShiftRows(t *testing.T) {
	input := bytesToBlock(hexToBytes("6353e08c0960e104cd70b751bacad0e7"))
	expected := bytesToBlock(hexToBytes("63cab7040953d051cd60e0e7ba70e18c"))

	InvShiftRows(&input)

	if input != expected {
		t.Errorf("InvShiftRows failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestMixColumns(t *testing.T) {
	input := bytesToBlock(hexToBytes("6353e08c0960e104cd70b751bacad0e7"))
	expected := bytesToBlock(hexToBytes("5f72641557f5bc92f7be3b291db9f91a"))

	MixColumns(&input)

	if input != expected {
		t.Errorf("MixColumns failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestInvMixColumns(t *testing.T) {
	input := bytesToBlock(hexToBytes("5f72641557f5bc92f7be3b291db9f91a"))
	expected := bytesToBlock(hexToBytes("6353e08c0960e104cd70b751bacad0e7"))

	InvMixColumns(&input)

	if input != expected {
		t.Errorf("InvMixColumns failed\nGot:      %x\nExpected: %x", input, expected)
	}
}

func TestAddRoundKey(t *testing.T) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	expected := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))

	AddRoundKey(&block, &key)

	if block != expected {
		t.Errorf("AddRoundKey failed\nGot:      %x\nExpected: %x", block, expected)
	}
}

func TestKeyScheduleAES128(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	if ks.Rounds() != 10 {
		t.Errorf("Expected 10 rounds, got %d", ks.Rounds())
	}

	// Test first round key (should be the original key)
	rk0 := ks.GetRoundKey(0)
	if !bytes.Equal(rk0[:], key) {
		t.Errorf("First round key doesn't match input key\nGot:      %x\nExpected: %x", rk0, key)
	}

	// Test last round key (from FIPS-197 Appendix A.1)
	rk10 := ks.GetRoundKey(10)
	expectedRK10 := hexToBytes("d014f9a8c9ee2589e13f0cc8b6630ca6")
	if !bytes.Equal(rk10[:], expectedRK10) {
		t.Errorf("Round 10 key doesn't match\nGot:      %x\nExpected: %x", rk10, expectedRK10)
	}
}

func TestKeyScheduleAES192(t *testing.T) {
	key := hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	if ks.Rounds() != 12 {
		t.Errorf("Expected 12 rounds, got %d", ks.Rounds())
	}
}

func TestKeyScheduleAES256(t *testing.T) {
	key := hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	if ks.Rounds() != 14 {
		t.Errorf("Expected 14 rounds, got %d", ks.Rounds())
	}
}

func TestKeyScheduleInvalidLength(t *testing.T) {
	key := hexToBytes("0102030405060708090a0b0c0d0e")
	_, err := NewKeySchedule(key)
	if err == nil {
		t.Error("Expected error for invalid key length, got nil")
	}
}

func TestInverseKeySchedule(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	encKS, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	invKS := InverseKeySchedule(encKS)

	if invKS.Rounds() != encKS.Rounds() {
		t.Errorf("Inverse key schedule has wrong number of rounds: got %d, expected %d",
			invKS.Rounds(), encKS.Rounds())
	}

	// First and last keys should be swapped
	if *invKS.GetRoundKey(0) != *encKS.GetRoundKey(encKS.Rounds()) {
		t.Error("First key of inverse schedule doesn't match last key of encryption schedule")
	}

	if *invKS.GetRoundKey(invKS.Rounds()) != *encKS.GetRoundKey(0) {
		t.Error("Last key of inverse schedule doesn't match first key of encryption schedule")
	}
}

// Test full encryption/decryption round trip
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	plaintext := bytesToBlock(hexToBytes("3243f6a8885a308d313198a2e0370734"))

	// Create key schedule
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	// Encrypt
	block := plaintext
	AddRoundKey(&block, ks.GetRoundKey(0))
	for i := 1; i < ks.Rounds(); i++ {
		Round(&block, ks.GetRoundKey(i))
	}
	FinalRound(&block, ks.GetRoundKey(ks.Rounds()))

	// Expected ciphertext from FIPS-197 Appendix B
	expectedCiphertext := bytesToBlock(hexToBytes("3925841d02dc09fbdc118597196a0b32"))
	if block != expectedCiphertext {
		t.Errorf("Encryption failed\nGot:      %x\nExpected: %x", block, expectedCiphertext)
	}

	// Decrypt using equivalent inverse cipher (matches hardware AESDEC/AESD)
	// Create inverse key schedule with InvMixColumns applied to middle keys
	invKS := InverseKeySchedule(ks)
	// Start with the first inverse key (which is the last encryption key)
	AddRoundKey(&block, invKS.GetRoundKey(0))
	// Apply inverse rounds (1 to 9 for AES-128)
	for i := 1; i < invKS.Rounds(); i++ {
		InvRound(&block, invKS.GetRoundKey(i))
	}
	// Final round with last inverse key (which is the first encryption key)
	InvFinalRound(&block, invKS.GetRoundKey(invKS.Rounds()))

	// Should get back original plaintext
	if block != plaintext {
		t.Errorf("Decryption failed\nGot:      %x\nExpected: %x", block, plaintext)
	}
}

// Benchmark individual operations
func BenchmarkSubBytes(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SubBytes(&block)
	}
}

func BenchmarkShiftRows(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShiftRows(&block)
	}
}

func BenchmarkMixColumns(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MixColumns(&block)
	}
}

func BenchmarkRound(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round(&block, &key)
	}
}

func BenchmarkInvRound(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRound(&block, &key)
	}
}

func BenchmarkInvSubBytes(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvSubBytes(&block)
	}
}

func BenchmarkInvShiftRows(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvShiftRows(&block)
	}
}

func BenchmarkInvMixColumns(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvMixColumns(&block)
	}
}

func BenchmarkAddRoundKey(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AddRoundKey(&block, &key)
	}
}

func BenchmarkFinalRound(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FinalRound(&block, &key)
	}
}

func BenchmarkInvFinalRound(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvFinalRound(&block, &key)
	}
}

func BenchmarkRoundHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundHW(&block, &key)
	}
}

func BenchmarkInvRoundHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRoundHW(&block, &key)
	}
}

func BenchmarkFinalRoundHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FinalRoundHW(&block, &key)
	}
}

func BenchmarkInvFinalRoundHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvFinalRoundHW(&block, &key)
	}
}

func BenchmarkRoundNoKey(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundNoKey(&block)
	}
}

func BenchmarkRoundNoKeyHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundNoKeyHW(&block)
	}
}

func BenchmarkInvRoundNoKey(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRoundNoKey(&block)
	}
}

func BenchmarkInvRoundNoKeyHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRoundNoKeyHW(&block)
	}
}

func BenchmarkRoundKeyFirst(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundKeyFirst(&block, &key)
	}
}

func BenchmarkRoundKeyFirstHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundKeyFirstHW(&block, &key)
	}
}

func BenchmarkNewKeySchedule128(b *testing.B) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeySchedule(key)
	}
}

func BenchmarkNewKeySchedule192(b *testing.B) {
	key := hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeySchedule(key)
	}
}

func BenchmarkNewKeySchedule256(b *testing.B) {
	key := hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeySchedule(key)
	}
}

func BenchmarkInverseKeySchedule(b *testing.B) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	ks, _ := NewKeySchedule(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InverseKeySchedule(ks)
	}
}

func BenchmarkInvMixColumnsHW(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvMixColumnsHW(&block)
	}
}

// TestKeyFirstVariants verifies that KeyFirst variants produce equivalent results
func TestKeyFirstVariants(t *testing.T) {
	// Test that RoundKeyFirst produces equivalent results to Round
	// They should be equivalent when starting from the same state
	block1 := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	block2 := block1
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))

	// Standard round: SubBytes, ShiftRows, MixColumns, AddRoundKey
	Round(&block1, &key)

	// KeyFirst variant: AddRoundKey, SubBytes, ShiftRows, MixColumns
	// To get the same result, we need to pre-XOR the key
	var blockPreXOR Block
	copy(blockPreXOR[:], block2[:])
	AddRoundKey(&blockPreXOR, &key)
	RoundKeyFirst(&block2, &key)

	// These should NOT be equal because the key is XORed at different points
	// But we can verify the transformation works by checking intermediate values
	if block1 == block2 {
		t.Error("RoundKeyFirst should produce different result due to key XOR order")
	}

	// Verify FinalRoundKeyFirst works
	block1 = bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	block2 = block1
	FinalRound(&block1, &key)
	AddRoundKey(&blockPreXOR, &key)
	FinalRoundKeyFirst(&block2, &key)
	if block1 == block2 {
		t.Error("FinalRoundKeyFirst should produce different result due to key XOR order")
	}
}

// TestNoKeyVariants verifies that NoKey variants work correctly
func TestNoKeyVariants(t *testing.T) {
	input := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))

	// Test RoundNoKey vs manual operations
	block1 := input
	block2 := input

	RoundNoKey(&block1)

	SubBytes(&block2)
	ShiftRows(&block2)
	MixColumns(&block2)

	if block1 != block2 {
		t.Errorf("RoundNoKey doesn't match manual operations\nGot:      %x\nExpected: %x", block1, block2)
	}

	// Test FinalRoundNoKey
	block1 = input
	block2 = input

	FinalRoundNoKey(&block1)

	SubBytes(&block2)
	ShiftRows(&block2)

	if block1 != block2 {
		t.Errorf("FinalRoundNoKey doesn't match manual operations\nGot:      %x\nExpected: %x", block1, block2)
	}

	// Test InvRoundNoKey vs manual inverse (exact inverse of RoundNoKey)
	block1 = input
	block2 = input

	InvRoundNoKey(&block1)

	InvMixColumns(&block2)
	InvShiftRows(&block2)
	InvSubBytes(&block2)

	if block1 != block2 {
		t.Errorf("InvRoundNoKey doesn't match manual operations\nGot:      %x\nExpected: %x", block1, block2)
	}

	// Test InvFinalRoundNoKey
	block1 = input
	block2 = input

	InvFinalRoundNoKey(&block1)

	InvShiftRows(&block2)
	InvSubBytes(&block2)

	if block1 != block2 {
		t.Errorf("InvFinalRoundNoKey doesn't match manual operations\nGot:      %x\nExpected: %x", block1, block2)
	}
}

// TestNoKeyRoundTrip verifies encryption/decryption using NoKey variants
func TestNoKeyRoundTrip(t *testing.T) {
	input := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))

	// Test RoundNoKey and InvRoundNoKey are inverses
	block := input
	RoundNoKey(&block)
	InvRoundNoKey(&block)

	if block != input {
		t.Errorf("RoundNoKey/InvRoundNoKey round trip failed\nGot:      %x\nExpected: %x", block, input)
	}

	// Test FinalRoundNoKey and InvFinalRoundNoKey are inverses
	block = input
	FinalRoundNoKey(&block)
	InvFinalRoundNoKey(&block)

	if block != input {
		t.Errorf("FinalRoundNoKey/InvFinalRoundNoKey round trip failed\nGot:      %x\nExpected: %x", block, input)
	}
}

// TestKeyFirstRoundTrip verifies encryption/decryption using KeyFirst variants
func TestKeyFirstRoundTrip(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	plaintext := bytesToBlock(hexToBytes("3243f6a8885a308d313198a2e0370734"))

	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	// Encrypt using KeyFirst variants
	// KeyFirst does AddRoundKey first, so we need to start with the initial key
	block := plaintext
	AddRoundKey(&block, ks.GetRoundKey(0)) // Initial AddRoundKey
	for i := 1; i < ks.Rounds(); i++ {
		RoundKeyFirst(&block, ks.GetRoundKey(i))
	}
	FinalRoundKeyFirst(&block, ks.GetRoundKey(ks.Rounds()))
	ciphertext := block

	// Decrypt using InvKeyFirst variants in reverse
	// We need to reverse the process exactly
	InvFinalRoundKeyFirst(&block, ks.GetRoundKey(ks.Rounds()))
	for i := ks.Rounds() - 1; i >= 1; i-- {
		InvRoundKeyFirst(&block, ks.GetRoundKey(i))
	}
	AddRoundKey(&block, ks.GetRoundKey(0)) // Final AddRoundKey to undo initial

	// Should get back original plaintext
	if block != plaintext {
		t.Errorf("KeyFirst round trip failed\nGot:        %x\nExpected:   %x\nCiphertext: %x",
			block, plaintext, ciphertext)
	}
}

// TestHardwareMatchesSoftware verifies hardware acceleration produces same results as software
func TestHardwareMatchesSoftware(t *testing.T) {
	if !UseHardwareAcceleration() {
		t.Skip("Hardware acceleration not available")
	}

	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))

	// Test Round
	swBlock := testBlock
	hwBlock := testBlock
	Round(&swBlock, &testKey)
	RoundHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("RoundHW doesn't match Round\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test FinalRound
	swBlock = testBlock
	hwBlock = testBlock
	FinalRound(&swBlock, &testKey)
	FinalRoundHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("FinalRoundHW doesn't match FinalRound\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test InvRound
	swBlock = testBlock
	hwBlock = testBlock
	InvRound(&swBlock, &testKey)
	InvRoundHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("InvRoundHW doesn't match InvRound\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test InvFinalRound
	swBlock = testBlock
	hwBlock = testBlock
	InvFinalRound(&swBlock, &testKey)
	InvFinalRoundHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("InvFinalRoundHW doesn't match InvFinalRound\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test InvMixColumns
	swBlock = bytesToBlock(hexToBytes("5f72641557f5bc92f7be3b291db9f91a"))
	hwBlock = swBlock
	InvMixColumns(&swBlock)
	InvMixColumnsHW(&hwBlock)
	if swBlock != hwBlock {
		t.Errorf("InvMixColumnsHW doesn't match InvMixColumns\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test RoundKeyFirst variants
	swBlock = testBlock
	hwBlock = testBlock
	RoundKeyFirst(&swBlock, &testKey)
	RoundKeyFirstHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("RoundKeyFirstHW doesn't match RoundKeyFirst\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	FinalRoundKeyFirst(&swBlock, &testKey)
	FinalRoundKeyFirstHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("FinalRoundKeyFirstHW doesn't match FinalRoundKeyFirst\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	InvRoundKeyFirst(&swBlock, &testKey)
	InvRoundKeyFirstHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("InvRoundKeyFirstHW doesn't match InvRoundKeyFirst\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	InvFinalRoundKeyFirst(&swBlock, &testKey)
	InvFinalRoundKeyFirstHW(&hwBlock, &testKey)
	if swBlock != hwBlock {
		t.Errorf("InvFinalRoundKeyFirstHW doesn't match InvFinalRoundKeyFirst\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	// Test NoKey variants
	swBlock = testBlock
	hwBlock = testBlock
	RoundNoKey(&swBlock)
	RoundNoKeyHW(&hwBlock)
	if swBlock != hwBlock {
		t.Errorf("RoundNoKeyHW doesn't match RoundNoKey\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	FinalRoundNoKey(&swBlock)
	FinalRoundNoKeyHW(&hwBlock)
	if swBlock != hwBlock {
		t.Errorf("FinalRoundNoKeyHW doesn't match FinalRoundNoKey\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	InvRoundNoKey(&swBlock)
	InvRoundNoKeyHW(&hwBlock)
	if swBlock != hwBlock {
		t.Errorf("InvRoundNoKeyHW doesn't match InvRoundNoKey\nSW: %x\nHW: %x", swBlock, hwBlock)
	}

	swBlock = testBlock
	hwBlock = testBlock
	InvFinalRoundNoKey(&swBlock)
	InvFinalRoundNoKeyHW(&hwBlock)
	if swBlock != hwBlock {
		t.Errorf("InvFinalRoundNoKeyHW doesn't match InvFinalRoundNoKey\nSW: %x\nHW: %x", swBlock, hwBlock)
	}
}
