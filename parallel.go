package aes

import "unsafe"

// Block2 represents two 128-bit AES blocks (32 bytes total) for parallel
// processing. Used with AVX2/VAES (256-bit vectors) or ARM Crypto Extensions
// to process two independent blocks simultaneously. Layout: [block0|block1]
// where each block is 16 bytes.
type Block2 [32]byte

// Block4 represents four 128-bit AES blocks (64 bytes total) for parallel
// processing. Used with AVX512/VAES (512-bit vectors) or ARM Crypto Extensions
// to process four independent blocks simultaneously. Layout: [block0|block1|block2|block3]
// where each block is 16 bytes.
type Block4 [64]byte

// Key2 represents two 128-bit round keys (32 bytes total) for parallel processing.
// Each block in a Block2 can be processed with its corresponding key, enabling
// different keys per lane. Layout: [key0|key1] where each key is 16 bytes.
type Key2 [32]byte

// Key4 represents four 128-bit round keys (64 bytes total) for parallel processing.
// Each block in a Block4 can be processed with its corresponding key, enabling
// different keys per lane. Layout: [key0|key1|key2|key3] where each key is 16 bytes.
type Key4 [64]byte

// Helper functions for efficient pointer extraction without slice allocation
// These use unsafe.Pointer + unsafe.Add for direct pointer arithmetic

func block2Ptrs(blocks *Block2) (*Block, *Block) {
	p := unsafe.Pointer(blocks)
	return (*Block)(p), (*Block)(unsafe.Add(p, 16))
}

func block4Ptrs(blocks *Block4) (*Block, *Block, *Block, *Block) {
	p := unsafe.Pointer(blocks)
	return (*Block)(p), (*Block)(unsafe.Add(p, 16)), (*Block)(unsafe.Add(p, 32)), (*Block)(unsafe.Add(p, 48))
}

func key2Ptrs(keys *Key2) (*Block, *Block) {
	p := unsafe.Pointer(keys)
	return (*Block)(p), (*Block)(unsafe.Add(p, 16))
}

func key4Ptrs(keys *Key4) (*Block, *Block, *Block, *Block) {
	p := unsafe.Pointer(keys)
	return (*Block)(p), (*Block)(unsafe.Add(p, 16)), (*Block)(unsafe.Add(p, 32)), (*Block)(unsafe.Add(p, 48))
}

// GetKey returns a pointer to the i-th key (0 or 1) from a Key2.
// Panics if i is out of range. Uses unsafe pointer arithmetic for
// zero-overhead direct access.
func (k *Key2) GetKey(i int) *Block {
	if i < 0 || i > 1 {
		panic("Key2 index out of range")
	}
	return (*Block)(unsafe.Add(unsafe.Pointer(k), uintptr(i)*16))
}

// SetKey copies the provided key to the i-th position (0 or 1) in a Key2.
// Panics if i is out of range. Uses direct memory assignment for efficiency.
func (k *Key2) SetKey(i int, key *Block) {
	if i < 0 || i > 1 {
		panic("Key2 index out of range")
	}
	dst := (*Block)(unsafe.Add(unsafe.Pointer(k), uintptr(i)*16))
	*dst = *key
}

// GetKey returns a pointer to the i-th key (0-3) from a Key4.
// Panics if i is out of range. Uses unsafe pointer arithmetic for
// zero-overhead direct access.
func (k *Key4) GetKey(i int) *Block {
	if i < 0 || i > 3 {
		panic("Key4 index out of range")
	}
	return (*Block)(unsafe.Add(unsafe.Pointer(k), uintptr(i)*16))
}

// SetKey copies the provided key to the i-th position (0-3) in a Key4.
// Panics if i is out of range. Uses direct memory assignment for efficiency.
func (k *Key4) SetKey(i int, key *Block) {
	if i < 0 || i > 3 {
		panic("Key4 index out of range")
	}
	dst := (*Block)(unsafe.Add(unsafe.Pointer(k), uintptr(i)*16))
	*dst = *key
}

// GetBlock returns a pointer to the i-th block (0 or 1) from a Block2.
// Panics if i is out of range. Uses unsafe pointer arithmetic for
// zero-overhead direct access.
func (b *Block2) GetBlock(i int) *Block {
	if i < 0 || i > 1 {
		panic("Block2 index out of range")
	}
	return (*Block)(unsafe.Add(unsafe.Pointer(b), uintptr(i)*16))
}

// SetBlock copies the provided block to the i-th position (0 or 1) in a Block2.
// Panics if i is out of range. Uses direct memory assignment for efficiency.
func (b *Block2) SetBlock(i int, block *Block) {
	if i < 0 || i > 1 {
		panic("Block2 index out of range")
	}
	dst := (*Block)(unsafe.Add(unsafe.Pointer(b), uintptr(i)*16))
	*dst = *block
}

// GetBlock returns a pointer to the i-th block (0-3) from a Block4.
// Panics if i is out of range. Uses unsafe pointer arithmetic for
// zero-overhead direct access.
func (b *Block4) GetBlock(i int) *Block {
	if i < 0 || i > 3 {
		panic("Block4 index out of range")
	}
	return (*Block)(unsafe.Add(unsafe.Pointer(b), uintptr(i)*16))
}

// SetBlock copies the provided block to the i-th position (0-3) in a Block4.
// Panics if i is out of range. Uses direct memory assignment for efficiency.
func (b *Block4) SetBlock(i int, block *Block) {
	if i < 0 || i > 3 {
		panic("Block4 index out of range")
	}
	dst := (*Block)(unsafe.Add(unsafe.Pointer(b), uintptr(i)*16))
	*dst = *block
}

// Round2 performs one AES encryption round on 2 blocks simultaneously.
// Each block is processed with its corresponding round key from roundKeys.
// This is a software implementation; use Round2HW for hardware acceleration.
func Round2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	Round(b0, k0)
	Round(b1, k1)
}

// Round4 performs one AES encryption round on 4 blocks simultaneously.
// Each block is processed with its corresponding round key from roundKeys.
// This is a software implementation; use Round4HW for hardware acceleration.
func Round4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	Round(b0, k0)
	Round(b1, k1)
	Round(b2, k2)
	Round(b3, k3)
}

// FinalRound2 performs the final AES encryption round on 2 blocks in parallel (software)
func FinalRound2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	FinalRound(b0, k0)
	FinalRound(b1, k1)
}

// FinalRound4 performs the final AES encryption round on 4 blocks in parallel (software)
func FinalRound4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	FinalRound(b0, k0)
	FinalRound(b1, k1)
	FinalRound(b2, k2)
	FinalRound(b3, k3)
}

// InvRound2 performs one AES decryption round on 2 blocks in parallel (software)
func InvRound2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	InvRound(b0, k0)
	InvRound(b1, k1)
}

// InvRound4 performs one AES decryption round on 4 blocks in parallel (software)
func InvRound4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	InvRound(b0, k0)
	InvRound(b1, k1)
	InvRound(b2, k2)
	InvRound(b3, k3)
}

// InvFinalRound2 performs the final AES decryption round on 2 blocks in parallel (software)
func InvFinalRound2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	InvFinalRound(b0, k0)
	InvFinalRound(b1, k1)
}

// InvFinalRound4 performs the final AES decryption round on 4 blocks in parallel (software)
func InvFinalRound4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	InvFinalRound(b0, k0)
	InvFinalRound(b1, k1)
	InvFinalRound(b2, k2)
	InvFinalRound(b3, k3)
}

// RoundKeyFirst2 performs one AES encryption round on 2 blocks in parallel with key XOR first (software)
func RoundKeyFirst2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	RoundKeyFirst(b0, k0)
	RoundKeyFirst(b1, k1)
}

// RoundKeyFirst4 performs one AES encryption round on 4 blocks in parallel with key XOR first (software)
func RoundKeyFirst4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	RoundKeyFirst(b0, k0)
	RoundKeyFirst(b1, k1)
	RoundKeyFirst(b2, k2)
	RoundKeyFirst(b3, k3)
}

// FinalRoundKeyFirst2 performs the final AES encryption round on 2 blocks in parallel with key XOR first (software)
func FinalRoundKeyFirst2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	FinalRoundKeyFirst(b0, k0)
	FinalRoundKeyFirst(b1, k1)
}

// FinalRoundKeyFirst4 performs the final AES encryption round on 4 blocks in parallel with key XOR first (software)
func FinalRoundKeyFirst4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	FinalRoundKeyFirst(b0, k0)
	FinalRoundKeyFirst(b1, k1)
	FinalRoundKeyFirst(b2, k2)
	FinalRoundKeyFirst(b3, k3)
}

// InvRoundKeyFirst2 performs one AES decryption round on 2 blocks in parallel that inverts RoundKeyFirst (software)
func InvRoundKeyFirst2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	InvRoundKeyFirst(b0, k0)
	InvRoundKeyFirst(b1, k1)
}

// InvRoundKeyFirst4 performs one AES decryption round on 4 blocks in parallel that inverts RoundKeyFirst (software)
func InvRoundKeyFirst4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	InvRoundKeyFirst(b0, k0)
	InvRoundKeyFirst(b1, k1)
	InvRoundKeyFirst(b2, k2)
	InvRoundKeyFirst(b3, k3)
}

// InvFinalRoundKeyFirst2 performs the final AES decryption round on 2 blocks in parallel that inverts FinalRoundKeyFirst (software)
func InvFinalRoundKeyFirst2(blocks *Block2, roundKeys *Key2) {
	b0, b1 := block2Ptrs(blocks)
	k0, k1 := key2Ptrs(roundKeys)
	InvFinalRoundKeyFirst(b0, k0)
	InvFinalRoundKeyFirst(b1, k1)
}

// InvFinalRoundKeyFirst4 performs the final AES decryption round on 4 blocks in parallel that inverts FinalRoundKeyFirst (software)
func InvFinalRoundKeyFirst4(blocks *Block4, roundKeys *Key4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	k0, k1, k2, k3 := key4Ptrs(roundKeys)
	InvFinalRoundKeyFirst(b0, k0)
	InvFinalRoundKeyFirst(b1, k1)
	InvFinalRoundKeyFirst(b2, k2)
	InvFinalRoundKeyFirst(b3, k3)
}

// RoundNoKey2 performs one AES encryption round on 2 blocks in parallel without AddRoundKey (software)
func RoundNoKey2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	RoundNoKey(b0)
	RoundNoKey(b1)
}

// RoundNoKey4 performs one AES encryption round on 4 blocks in parallel without AddRoundKey (software)
func RoundNoKey4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	RoundNoKey(b0)
	RoundNoKey(b1)
	RoundNoKey(b2)
	RoundNoKey(b3)
}

// FinalRoundNoKey2 performs the final AES encryption round on 2 blocks in parallel without AddRoundKey (software)
func FinalRoundNoKey2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	FinalRoundNoKey(b0)
	FinalRoundNoKey(b1)
}

// FinalRoundNoKey4 performs the final AES encryption round on 4 blocks in parallel without AddRoundKey (software)
func FinalRoundNoKey4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	FinalRoundNoKey(b0)
	FinalRoundNoKey(b1)
	FinalRoundNoKey(b2)
	FinalRoundNoKey(b3)
}

// InvRoundNoKey2 performs the inverse of RoundNoKey on 2 blocks in parallel without AddRoundKey (software)
func InvRoundNoKey2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	InvRoundNoKey(b0)
	InvRoundNoKey(b1)
}

// InvRoundNoKey4 performs the inverse of RoundNoKey on 4 blocks in parallel without AddRoundKey (software)
func InvRoundNoKey4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	InvRoundNoKey(b0)
	InvRoundNoKey(b1)
	InvRoundNoKey(b2)
	InvRoundNoKey(b3)
}

// InvFinalRoundNoKey2 performs the inverse of FinalRoundNoKey on 2 blocks in parallel without AddRoundKey (software)
func InvFinalRoundNoKey2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	InvFinalRoundNoKey(b0)
	InvFinalRoundNoKey(b1)
}

// InvFinalRoundNoKey4 performs the inverse of FinalRoundNoKey on 4 blocks in parallel without AddRoundKey (software)
func InvFinalRoundNoKey4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	InvFinalRoundNoKey(b0)
	InvFinalRoundNoKey(b1)
	InvFinalRoundNoKey(b2)
	InvFinalRoundNoKey(b3)
}
