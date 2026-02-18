//go:build ignore

package main

import (
	"encoding/hex"
	"fmt"

	aes "github.com/jedisct1/go-aes"
)

func main() {
	fmt.Println("=== Parallel AES Block Processing Example ===\n")

	// Create AES-128 key
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}

	// Create key schedule
	ks, err := aes.NewKeySchedule(key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Key: %x\n", key)
	fmt.Printf("AES-%d with %d rounds\n\n", len(key)*8, ks.Rounds())

	// Example 1: Process 2 blocks in parallel
	fmt.Println("--- Processing 2 blocks in parallel ---")
	processTwo(ks)

	fmt.Println()

	// Example 2: Process 4 blocks in parallel
	fmt.Println("--- Processing 4 blocks in parallel ---")
	processFour(ks)

	// Check CPU support
	fmt.Println("\n--- CPU Support ---")
	fmt.Printf("AES-NI: %v\n", aes.CPU.HasAESNI)
	fmt.Printf("ARM Crypto: %v\n", aes.CPU.HasARMCrypto)
	fmt.Printf("VAES: %v\n", aes.CPU.HasVAES)
	fmt.Printf("AVX2: %v\n", aes.CPU.HasAVX2)
	fmt.Printf("AVX512: %v\n", aes.CPU.HasAVX512)
	fmt.Printf("Vector acceleration available: %v\n", aes.UseVectorAcceleration())
}

// Helper to create Key2 with the same key for both blocks
func makeKey2(key *aes.Block) *aes.Key2 {
	var k aes.Key2
	k.SetKey(0, key)
	k.SetKey(1, key)
	return &k
}

// Helper to create Key4 with the same key for all blocks
func makeKey4(key *aes.Block) *aes.Key4 {
	var k aes.Key4
	k.SetKey(0, key)
	k.SetKey(1, key)
	k.SetKey(2, key)
	k.SetKey(3, key)
	return &k
}

func processTwo(ks *aes.KeySchedule) {
	// Create two different plaintext blocks
	plaintext1 := []byte("Block 1 plaintext data here!12345678")[:16]
	plaintext2 := []byte("Block 2 plaintext data here!87654321")[:16]

	// Create Block2 and set the blocks
	var blocks aes.Block2
	var block1, block2 aes.Block
	copy(block1[:], plaintext1)
	copy(block2[:], plaintext2)
	blocks.SetBlock(0, &block1)
	blocks.SetBlock(1, &block2)

	fmt.Printf("Plaintext 1: %x\n", plaintext1)
	fmt.Printf("Plaintext 2: %x\n", plaintext2)

	// Encrypt using parallel operations
	// Initial AddRoundKey
	aes.AddRoundKey(blocks.GetBlock(0), ks.GetRoundKey(0))
	aes.AddRoundKey(blocks.GetBlock(1), ks.GetRoundKey(0))

	// Main rounds using hardware-accelerated parallel operations
	for i := 1; i < ks.Rounds(); i++ {
		aes.Round2HW(&blocks, makeKey2(ks.GetRoundKey(i)))
	}

	// Final round
	aes.FinalRound2HW(&blocks, makeKey2(ks.GetRoundKey(ks.Rounds())))

	ciphertext1 := *blocks.GetBlock(0)
	ciphertext2 := *blocks.GetBlock(1)

	fmt.Printf("Ciphertext 1: %x\n", ciphertext1)
	fmt.Printf("Ciphertext 2: %x\n", ciphertext2)

	// Decrypt using inverse key schedule (required for equivalent inverse cipher)
	invKS := aes.InverseKeySchedule(ks)

	aes.AddRoundKey(blocks.GetBlock(0), invKS.GetRoundKey(0))
	aes.AddRoundKey(blocks.GetBlock(1), invKS.GetRoundKey(0))

	for i := 1; i < invKS.Rounds(); i++ {
		aes.InvRound2HW(&blocks, makeKey2(invKS.GetRoundKey(i)))
	}

	aes.InvFinalRound2(&blocks, makeKey2(invKS.GetRoundKey(invKS.Rounds())))

	recovered1 := *blocks.GetBlock(0)
	recovered2 := *blocks.GetBlock(1)

	fmt.Printf("Recovered 1: %s\n", hex.EncodeToString(recovered1[:]))
	fmt.Printf("Recovered 2: %s\n", hex.EncodeToString(recovered2[:]))

	// Verify
	if recovered1 == block1 && recovered2 == block2 {
		fmt.Println("Encryption/decryption successful!")
	} else {
		fmt.Println("Encryption/decryption failed!")
	}
}

func processFour(ks *aes.KeySchedule) {
	// Create four different plaintext blocks
	plaintexts := [4]string{
		"Block A data!...",
		"Block B data!...",
		"Block C data!...",
		"Block D data!...",
	}

	// Create Block4 and set the blocks
	var blocks aes.Block4
	var originalBlocks [4]aes.Block

	for i := 0; i < 4; i++ {
		copy(originalBlocks[i][:], []byte(plaintexts[i]))
		blocks.SetBlock(i, &originalBlocks[i])
		fmt.Printf("Plaintext %d: %x\n", i, originalBlocks[i])
	}

	// Encrypt using parallel operations
	// Initial AddRoundKey
	for i := 0; i < 4; i++ {
		aes.AddRoundKey(blocks.GetBlock(i), ks.GetRoundKey(0))
	}

	// Main rounds using hardware-accelerated parallel operations
	for round := 1; round < ks.Rounds(); round++ {
		aes.Round4HW(&blocks, makeKey4(ks.GetRoundKey(round)))
	}

	// Final round
	aes.FinalRound4HW(&blocks, makeKey4(ks.GetRoundKey(ks.Rounds())))

	// Print ciphertexts
	for i := 0; i < 4; i++ {
		fmt.Printf("Ciphertext %d: %x\n", i, blocks.GetBlock(i))
	}

	// Decrypt using inverse key schedule (required for equivalent inverse cipher)
	invKS := aes.InverseKeySchedule(ks)

	for i := 0; i < 4; i++ {
		aes.AddRoundKey(blocks.GetBlock(i), invKS.GetRoundKey(0))
	}

	for round := 1; round < invKS.Rounds(); round++ {
		aes.InvRound4HW(&blocks, makeKey4(invKS.GetRoundKey(round)))
	}

	aes.InvFinalRound4(&blocks, makeKey4(invKS.GetRoundKey(invKS.Rounds())))

	// Verify
	allMatch := true
	for i := 0; i < 4; i++ {
		recovered := *blocks.GetBlock(i)
		fmt.Printf("Recovered %d: %s\n", i, hex.EncodeToString(recovered[:]))
		if recovered != originalBlocks[i] {
			allMatch = false
		}
	}

	if allMatch {
		fmt.Println("Encryption/decryption successful for all 4 blocks!")
	} else {
		fmt.Println("Encryption/decryption failed!")
	}
}
