package aes

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

// KeySchedule holds the expanded round keys for AES encryption and decryption.
// A key schedule is created from a cipher key and contains all the per-round
// keys needed for AES operations. The number of rounds depends on the key size:
// 10 rounds for AES-128, 12 for AES-192, and 14 for AES-256.
type KeySchedule struct {
	rounds int     // Number of rounds (10, 12, or 14)
	keys   []Block // Round keys (rounds+1 keys total)
}

// NewKeySchedule creates a key schedule from a cipher key using the AES key
// expansion algorithm. Supported key sizes:
//   - 16 bytes (AES-128): 10 rounds
//   - 24 bytes (AES-192): 12 rounds
//   - 32 bytes (AES-256): 14 rounds
//
// Returns an error if the key length is invalid.
func NewKeySchedule(key []byte) (*KeySchedule, error) {
	keyLen := len(key)
	var rounds int

	switch keyLen {
	case 16:
		rounds = 10
	case 24:
		rounds = 12
	case 32:
		rounds = 14
	default:
		return nil, errors.New("key schedule error: invalid key length")
	}

	ks := &KeySchedule{
		rounds: rounds,
		keys:   make([]Block, rounds+1),
	}

	expandKey(key, ks.keys, rounds)
	return ks, nil
}

// GetRoundKey returns a pointer to the round key for the specified round number
// (0-based indexing). Round 0 is the initial key, and subsequent rounds are the
// expanded keys. Returns nil if the round number is out of range.
func (ks *KeySchedule) GetRoundKey(round int) *Block {
	if round < 0 || round > ks.rounds {
		return nil
	}
	return &ks.keys[round]
}

// Rounds returns the number of AES rounds for this key schedule:
// 10 for AES-128, 12 for AES-192, or 14 for AES-256.
func (ks *KeySchedule) Rounds() int {
	return ks.rounds
}

// subWord applies S-box to each byte in a 4-byte word
func subWord(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 |
		uint32(sbox[(w>>16)&0xff])<<16 |
		uint32(sbox[(w>>8)&0xff])<<8 |
		uint32(sbox[w&0xff])
}

// rotWord rotates a 4-byte word left by one byte
func rotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

// expandKey performs the key expansion algorithm
// Optimized to write directly to roundKeys without intermediate allocation
func expandKey(key []byte, roundKeys []Block, rounds int) {
	keyLen := len(key)
	nk := keyLen / 4 // Number of 32-bit words in the key
	nb := 4          // Number of columns (32-bit words) in the state (always 4 for AES)

	totalWords := nb * (rounds + 1)

	// Use the roundKeys array directly as our word storage
	// Each Block is 16 bytes = 4 uint32 words
	// We'll interpret the contiguous memory as uint32 words
	wordsPtr := unsafe.Pointer(&roundKeys[0])

	// Helper to get word at index i
	getWord := func(i int) uint32 {
		return *(*uint32)(unsafe.Add(wordsPtr, uintptr(i)*4))
	}

	// Helper to set word at index i
	setWord := func(i int, val uint32) {
		*(*uint32)(unsafe.Add(wordsPtr, uintptr(i)*4)) = val
	}

	// Copy the key into the first nk words (big-endian)
	for i := 0; i < nk; i++ {
		setWord(i, binary.BigEndian.Uint32(key[4*i:]))
	}

	// Expand the key
	for i := nk; i < totalWords; i++ {
		temp := getWord(i - 1)

		if i%nk == 0 {
			temp = subWord(rotWord(temp)) ^ (uint32(rcon[i/nk]) << 24)
		} else if nk > 6 && i%nk == 4 {
			temp = subWord(temp)
		}

		setWord(i, getWord(i-nk)^temp)
	}

	// Convert from native endian to big-endian in-place
	// This ensures column-major order output
	for i := 0; i < totalWords; i++ {
		w := getWord(i)
		ptr := (*[4]byte)(unsafe.Add(wordsPtr, uintptr(i)*4))
		ptr[0] = byte(w >> 24)
		ptr[1] = byte(w >> 16)
		ptr[2] = byte(w >> 8)
		ptr[3] = byte(w)
	}
}

// InverseKeySchedule creates a key schedule suitable for AES decryption
// from an encryption key schedule. This applies InvMixColumns to all middle
// round keys and reverses their order to match the "equivalent inverse cipher"
// form from FIPS-197. The first and last keys are copied as-is without
// InvMixColumns.
func InverseKeySchedule(encKS *KeySchedule) *KeySchedule {
	invKS := &KeySchedule{
		rounds: encKS.rounds,
		keys:   make([]Block, encKS.rounds+1),
	}

	// Copy first and last keys as-is
	invKS.keys[0] = encKS.keys[encKS.rounds]
	invKS.keys[encKS.rounds] = encKS.keys[0]

	// Apply InvMixColumns to middle keys and reverse order
	for i := 1; i < encKS.rounds; i++ {
		invKS.keys[i] = encKS.keys[encKS.rounds-i]
		InvMixColumns(&invKS.keys[i])
	}

	return invKS
}
