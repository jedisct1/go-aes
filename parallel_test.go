package aes

import (
	"testing"
)

func TestBlock2GetSetBlock(t *testing.T) {
	var b2 Block2
	block0 := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	block1 := bytesToBlock(hexToBytes("ffeeddccbbaa99887766554433221100"))

	b2.SetBlock(0, &block0)
	b2.SetBlock(1, &block1)

	retrieved0 := b2.GetBlock(0)
	retrieved1 := b2.GetBlock(1)

	if *retrieved0 != block0 {
		t.Errorf("Block2.GetBlock(0) failed\nGot:      %x\nExpected: %x", retrieved0, block0)
	}

	if *retrieved1 != block1 {
		t.Errorf("Block2.GetBlock(1) failed\nGot:      %x\nExpected: %x", retrieved1, block1)
	}
}

func TestBlock4GetSetBlock(t *testing.T) {
	var b4 Block4
	block0 := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	block1 := bytesToBlock(hexToBytes("ffeeddccbbaa99887766554433221100"))
	block2 := bytesToBlock(hexToBytes("0123456789abcdeffedcba9876543210"))
	block3 := bytesToBlock(hexToBytes("fedcba98765432100123456789abcdef"))

	b4.SetBlock(0, &block0)
	b4.SetBlock(1, &block1)
	b4.SetBlock(2, &block2)
	b4.SetBlock(3, &block3)

	if *b4.GetBlock(0) != block0 {
		t.Errorf("Block4.GetBlock(0) failed")
	}
	if *b4.GetBlock(1) != block1 {
		t.Errorf("Block4.GetBlock(1) failed")
	}
	if *b4.GetBlock(2) != block2 {
		t.Errorf("Block4.GetBlock(2) failed")
	}
	if *b4.GetBlock(3) != block3 {
		t.Errorf("Block4.GetBlock(3) failed")
	}
}

// Helper to create Key2 with the same key for both blocks
func makeKey2(key *Block) *Key2 {
	var k Key2
	k.SetKey(0, key)
	k.SetKey(1, key)
	return &k
}

// Helper to create Key4 with the same key for all blocks
func makeKey4(key *Block) *Key4 {
	var k Key4
	k.SetKey(0, key)
	k.SetKey(1, key)
	k.SetKey(2, key)
	k.SetKey(3, key)
	return &k
}

func TestRound2Software(t *testing.T) {
	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))

	// Process blocks individually
	block0 := testBlock
	block1 := testBlock
	Round(&block0, &testKey)
	Round(&block1, &testKey)

	// Process blocks in parallel
	var blocks Block2
	blocks.SetBlock(0, &testBlock)
	blocks.SetBlock(1, &testBlock)
	Round2(&blocks, makeKey2(&testKey))

	// Results should match
	if *blocks.GetBlock(0) != block0 {
		t.Errorf("Round2 block 0 doesn't match\nGot:      %x\nExpected: %x", blocks.GetBlock(0), block0)
	}
	if *blocks.GetBlock(1) != block1 {
		t.Errorf("Round2 block 1 doesn't match\nGot:      %x\nExpected: %x", blocks.GetBlock(1), block1)
	}
}

func TestRound4Software(t *testing.T) {
	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))

	// Process blocks individually
	blocks := [4]Block{testBlock, testBlock, testBlock, testBlock}
	for i := range blocks {
		Round(&blocks[i], &testKey)
	}

	// Process blocks in parallel
	var blocks4 Block4
	for i := 0; i < 4; i++ {
		blocks4.SetBlock(i, &testBlock)
	}
	Round4(&blocks4, makeKey4(&testKey))

	// Results should match
	for i := 0; i < 4; i++ {
		if *blocks4.GetBlock(i) != blocks[i] {
			t.Errorf("Round4 block %d doesn't match\nGot:      %x\nExpected: %x", i, blocks4.GetBlock(i), blocks[i])
		}
	}
}

func TestInvRound2Software(t *testing.T) {
	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))

	// Process blocks individually
	block0 := testBlock
	block1 := testBlock
	InvRound(&block0, &testKey)
	InvRound(&block1, &testKey)

	// Process blocks in parallel
	var blocks Block2
	blocks.SetBlock(0, &testBlock)
	blocks.SetBlock(1, &testBlock)
	InvRound2(&blocks, makeKey2(&testKey))

	// Results should match
	if *blocks.GetBlock(0) != block0 {
		t.Errorf("InvRound2 block 0 doesn't match")
	}
	if *blocks.GetBlock(1) != block1 {
		t.Errorf("InvRound2 block 1 doesn't match")
	}
}

func TestParallelEncryptionRoundTrip(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	plaintext0 := bytesToBlock(hexToBytes("3243f6a8885a308d313198a2e0370734"))
	plaintext1 := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))

	// Encrypt using Block2
	var blocks Block2
	blocks.SetBlock(0, &plaintext0)
	blocks.SetBlock(1, &plaintext1)

	// Initial AddRoundKey
	block0 := blocks.GetBlock(0)
	block1 := blocks.GetBlock(1)
	AddRoundKey(block0, ks.GetRoundKey(0))
	AddRoundKey(block1, ks.GetRoundKey(0))

	// Rounds
	for i := 1; i < ks.Rounds(); i++ {
		Round2(&blocks, makeKey2(ks.GetRoundKey(i)))
	}
	FinalRound2(&blocks, makeKey2(ks.GetRoundKey(ks.Rounds())))

	ciphertext0 := *blocks.GetBlock(0)
	ciphertext1 := *blocks.GetBlock(1)

	// Decrypt using equivalent inverse cipher
	invKS := InverseKeySchedule(ks)
	AddRoundKey(blocks.GetBlock(0), invKS.GetRoundKey(0))
	AddRoundKey(blocks.GetBlock(1), invKS.GetRoundKey(0))
	for i := 1; i < invKS.Rounds(); i++ {
		InvRound2(&blocks, makeKey2(invKS.GetRoundKey(i)))
	}
	InvFinalRound2(&blocks, makeKey2(invKS.GetRoundKey(invKS.Rounds())))

	// Should get back original plaintext
	if *blocks.GetBlock(0) != plaintext0 {
		t.Errorf("Parallel encryption/decryption failed for block 0\nGot:        %x\nExpected:   %x\nCiphertext: %x",
			blocks.GetBlock(0), plaintext0, ciphertext0)
	}
	if *blocks.GetBlock(1) != plaintext1 {
		t.Errorf("Parallel encryption/decryption failed for block 1\nGot:        %x\nExpected:   %x\nCiphertext: %x",
			blocks.GetBlock(1), plaintext1, ciphertext1)
	}
}

func TestParallel4EncryptionRoundTrip(t *testing.T) {
	key := hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
	ks, err := NewKeySchedule(key)
	if err != nil {
		t.Fatalf("NewKeySchedule failed: %v", err)
	}

	plaintexts := [4]Block{
		bytesToBlock(hexToBytes("3243f6a8885a308d313198a2e0370734")),
		bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff")),
		bytesToBlock(hexToBytes("0123456789abcdeffedcba9876543210")),
		bytesToBlock(hexToBytes("fedcba98765432100123456789abcdef")),
	}

	// Encrypt using Block4
	var blocks Block4
	for i := 0; i < 4; i++ {
		blocks.SetBlock(i, &plaintexts[i])
	}

	// Initial AddRoundKey
	for i := 0; i < 4; i++ {
		AddRoundKey(blocks.GetBlock(i), ks.GetRoundKey(0))
	}

	// Rounds
	for i := 1; i < ks.Rounds(); i++ {
		Round4(&blocks, makeKey4(ks.GetRoundKey(i)))
	}
	FinalRound4(&blocks, makeKey4(ks.GetRoundKey(ks.Rounds())))

	// Decrypt using equivalent inverse cipher
	invKS := InverseKeySchedule(ks)
	for i := 0; i < 4; i++ {
		AddRoundKey(blocks.GetBlock(i), invKS.GetRoundKey(0))
	}
	for i := 1; i < invKS.Rounds(); i++ {
		InvRound4(&blocks, makeKey4(invKS.GetRoundKey(i)))
	}
	InvFinalRound4(&blocks, makeKey4(invKS.GetRoundKey(invKS.Rounds())))

	// Should get back original plaintext
	for i := 0; i < 4; i++ {
		if *blocks.GetBlock(i) != plaintexts[i] {
			t.Errorf("Parallel encryption/decryption failed for block %d", i)
		}
	}
}

func TestHardwareMatchesSoftwareParallel(t *testing.T) {
	// Test VAES on Intel/AMD platforms
	if !UseVectorAcceleration() && !CPU.HasARMCrypto {
		t.Skip("Vector hardware acceleration not available")
	}

	// Skip VAES-specific tests on ARM (different implementation)
	if CPU.HasARMCrypto && !UseVectorAcceleration() {
		t.Skip("Running ARM-specific hardware tests separately")
	}

	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys2 := makeKey2(&testKey)
	keys4 := makeKey4(&testKey)

	// Test Round2HW
	var swBlocks, hwBlocks Block2
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	Round2(&swBlocks, keys2)
	Round2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("Round2HW doesn't match Round2\nSW: %x\nHW: %x", swBlocks, hwBlocks)
	}

	// Test FinalRound2HW
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	FinalRound2(&swBlocks, keys2)
	FinalRound2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("FinalRound2HW doesn't match FinalRound2")
	}

	// Test InvRound2HW
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	InvRound2(&swBlocks, keys2)
	InvRound2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("InvRound2HW doesn't match InvRound2")
	}

	// Test InvFinalRound2HW
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	InvFinalRound2(&swBlocks, keys2)
	InvFinalRound2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("InvFinalRound2HW doesn't match InvFinalRound2")
	}

	// Test Round4HW (if AVX512 is available)
	if CPU.HasAVX512 {
		var swBlocks4, hwBlocks4 Block4
		for i := 0; i < 4; i++ {
			swBlocks4.SetBlock(i, &testBlock)
			hwBlocks4.SetBlock(i, &testBlock)
		}

		Round4(&swBlocks4, keys4)
		Round4HW(&hwBlocks4, keys4)

		if swBlocks4 != hwBlocks4 {
			t.Errorf("Round4HW doesn't match Round4")
		}

		// Test FinalRound4HW
		for i := 0; i < 4; i++ {
			swBlocks4.SetBlock(i, &testBlock)
			hwBlocks4.SetBlock(i, &testBlock)
		}

		FinalRound4(&swBlocks4, keys4)
		FinalRound4HW(&hwBlocks4, keys4)

		if swBlocks4 != hwBlocks4 {
			t.Errorf("FinalRound4HW doesn't match FinalRound4")
		}

		// Test InvRound4HW
		for i := 0; i < 4; i++ {
			swBlocks4.SetBlock(i, &testBlock)
			hwBlocks4.SetBlock(i, &testBlock)
		}

		InvRound4(&swBlocks4, keys4)
		InvRound4HW(&hwBlocks4, keys4)

		if swBlocks4 != hwBlocks4 {
			t.Errorf("InvRound4HW doesn't match InvRound4")
		}

		// Test InvFinalRound4HW
		for i := 0; i < 4; i++ {
			swBlocks4.SetBlock(i, &testBlock)
			hwBlocks4.SetBlock(i, &testBlock)
		}

		InvFinalRound4(&swBlocks4, keys4)
		InvFinalRound4HW(&hwBlocks4, keys4)

		if swBlocks4 != hwBlocks4 {
			t.Errorf("InvFinalRound4HW doesn't match InvFinalRound4")
		}
	}
}

func TestNoKeyVariantsParallel(t *testing.T) {
	input := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))

	// Test RoundNoKey2 vs manual operations
	var blocks Block2
	blocks.SetBlock(0, &input)
	blocks.SetBlock(1, &input)

	expected0 := input
	expected1 := input
	RoundNoKey(&expected0)
	RoundNoKey(&expected1)

	RoundNoKey2(&blocks)

	if *blocks.GetBlock(0) != expected0 || *blocks.GetBlock(1) != expected1 {
		t.Errorf("RoundNoKey2 doesn't match individual RoundNoKey calls")
	}

	// Test round trip
	InvRoundNoKey2(&blocks)

	if *blocks.GetBlock(0) != input || *blocks.GetBlock(1) != input {
		t.Errorf("RoundNoKey2/InvRoundNoKey2 round trip failed")
	}
}

func BenchmarkRoundSingle(b *testing.B) {
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round(&block, &key)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkRound2Software(b *testing.B) {
	var blocks Block2
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	blocks.SetBlock(0, &block)
	blocks.SetBlock(1, &block)
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey2(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round2(&blocks, keys)
	}
	b.ReportMetric(float64(2*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkRound2HW(b *testing.B) {
	var blocks Block2
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	blocks.SetBlock(0, &block)
	blocks.SetBlock(1, &block)
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey2(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round2HW(&blocks, keys)
	}
	b.ReportMetric(float64(2*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkRound4Software(b *testing.B) {
	var blocks Block4
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	for i := 0; i < 4; i++ {
		blocks.SetBlock(i, &block)
	}
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey4(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round4(&blocks, keys)
	}
	b.ReportMetric(float64(4*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkRound4HW(b *testing.B) {
	var blocks Block4
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	for i := 0; i < 4; i++ {
		blocks.SetBlock(i, &block)
	}
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey4(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Round4HW(&blocks, keys)
	}
	b.ReportMetric(float64(4*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkInvRound2Software(b *testing.B) {
	var blocks Block2
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	blocks.SetBlock(0, &block)
	blocks.SetBlock(1, &block)
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey2(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRound2(&blocks, keys)
	}
	b.ReportMetric(float64(2*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkInvRound2HW(b *testing.B) {
	var blocks Block2
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	blocks.SetBlock(0, &block)
	blocks.SetBlock(1, &block)
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey2(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRound2HW(&blocks, keys)
	}
	b.ReportMetric(float64(2*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkInvRound4Software(b *testing.B) {
	var blocks Block4
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	for i := 0; i < 4; i++ {
		blocks.SetBlock(i, &block)
	}
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey4(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRound4(&blocks, keys)
	}
	b.ReportMetric(float64(4*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

func BenchmarkInvRound4HW(b *testing.B) {
	var blocks Block4
	block := bytesToBlock(hexToBytes("00112233445566778899aabbccddeeff"))
	for i := 0; i < 4; i++ {
		blocks.SetBlock(i, &block)
	}
	key := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys := makeKey4(&key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvRound4HW(&blocks, keys)
	}
	b.ReportMetric(float64(4*b.N)/b.Elapsed().Seconds()/1e9, "blocks/sec(G)")
}

// TestARMParallelBoundaryReduction verifies ARM parallel ops work correctly
// This test is important because ARM parallel variants reduce Go/Assembly boundary crossings
func TestARMParallelBoundaryReduction(t *testing.T) {
	if !CPU.HasARMCrypto {
		t.Skip("ARM Crypto not available")
	}

	testBlock := bytesToBlock(hexToBytes("00102030405060708090a0b0c0d0e0f0"))
	testKey := bytesToBlock(hexToBytes("000102030405060708090a0b0c0d0e0f"))
	keys2 := makeKey2(&testKey)
	keys4 := makeKey4(&testKey)

	// Test that ARM hardware parallel functions match software
	var swBlocks, hwBlocks Block2
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	Round2(&swBlocks, keys2)
	Round2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("ARM Round2HW doesn't match Round2\nSW: %x\nHW: %x", swBlocks, hwBlocks)
	}

	// Test 4-block variant
	var swBlocks4, hwBlocks4 Block4
	for i := 0; i < 4; i++ {
		swBlocks4.SetBlock(i, &testBlock)
		hwBlocks4.SetBlock(i, &testBlock)
	}

	Round4(&swBlocks4, keys4)
	Round4HW(&hwBlocks4, keys4)

	if swBlocks4 != hwBlocks4 {
		t.Errorf("ARM Round4HW doesn't match Round4")
	}

	// Test KeyFirst variants (more efficient on ARM - no zero-key workaround needed)
	swBlocks.SetBlock(0, &testBlock)
	swBlocks.SetBlock(1, &testBlock)
	hwBlocks = swBlocks

	RoundKeyFirst2(&swBlocks, keys2)
	RoundKeyFirst2HW(&hwBlocks, keys2)

	if swBlocks != hwBlocks {
		t.Errorf("ARM RoundKeyFirst2HW doesn't match RoundKeyFirst2")
	}
}
