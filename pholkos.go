package aes

import (
	"encoding/binary"
	"unsafe"
)

// Pholkos is a family of large-state tweakable block ciphers based on the AES
// round function, designed for high security and high performance on modern CPUs.
// It follows the design strategy of Haraka and AESQ with two-round steps.
//
// Versions:
//   - Pholkos-256-256: 256-bit block, 256-bit key, 128-bit tweak, 8 steps
//   - Pholkos-512-256: 512-bit block, 256-bit key, 128-bit tweak, 10 steps
//   - Pholkos-512-512: 512-bit block, 512-bit key, 128-bit tweak, 10 steps

type (
	// Pholkos256Block represents a 256-bit (32-byte) Pholkos-256 block.
	Pholkos256Block [32]byte

	// Pholkos512Block represents a 512-bit (64-byte) Pholkos-512 block.
	Pholkos512Block [64]byte

	// PholkosTweak represents a 128-bit (16-byte) tweak.
	PholkosTweak [16]byte

	// Pholkos256Key represents a 256-bit (32-byte) key for Pholkos-256 or Pholkos-512-256.
	Pholkos256Key [32]byte

	// Pholkos512Key represents a 512-bit (64-byte) key for Pholkos-512-512.
	Pholkos512Key [64]byte
)

// Number of steps for each variant
const (
	pholkos256Steps = 8  // Pholkos-256-256
	pholkos512Steps = 10 // Pholkos-512-256 and Pholkos-512-512
)

// Word-wise permutation π256 for Pholkos-256
// Maps word at index π256[j] to position j
var pi256 = [8]int{0, 5, 2, 7, 4, 1, 6, 3}

// Inverse of π256
var pi256Inv = [8]int{0, 5, 2, 7, 4, 1, 6, 3} // π256 is self-inverse

// Word-wise permutation π512 for Pholkos-512
// Maps word at index π512[j] to position j
var pi512 = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

// Inverse of π512
var pi512Inv [16]int

// Cell permutation πτ for the tweakey schedule
var piTau = [16]int{11, 12, 1, 2, 15, 0, 5, 6, 3, 4, 9, 10, 7, 8, 13, 14}

// Inverse of πτ
var piTauInv [16]int

func init() {
	// Compute inverse permutations
	for i := range 16 {
		pi512Inv[pi512[i]] = i
		piTauInv[piTau[i]] = i
	}
}

// pholkosRoundConstants are the 128-bit round constants derived from π.
// These are the same as Haraka v2 round constants.
// Pholkos-256 uses constants 0-16, Pholkos-512 uses constants 0-20.
var pholkosRoundConstants = harakaRC128

// applyTau applies the cell permutation τ (πτ) to a 128-bit substate.
// τ permutes the bytes according to πτ.
func applyTau(state *Block) {
	var temp Block
	for i := range 16 {
		temp[i] = state[piTau[i]]
	}
	*state = temp
}

// gfDouble multiplies a byte by 2 in GF(2^8) with the AES polynomial.
func gfDouble(b byte) byte {
	return gfMul2(b)
}

// Pholkos256Context holds precomputed round tweakeys for Pholkos-256 encryption.
type Pholkos256Context struct {
	// Round tweakeys: 8 steps × 2 rounds + 1 = 17 round tweakeys
	// Each round tweakey has 2 substates (256 bits total)
	rtk [17][2]Block
}

// Pholkos512Context holds precomputed round tweakeys for Pholkos-512 encryption.
type Pholkos512Context struct {
	// Round tweakeys: 10 steps × 2 rounds + 1 = 21 round tweakeys
	// Each round tweakey has 4 substates (512 bits total)
	rtk [21][4]Block
}

// NewPholkos256Context creates a new Pholkos-256 context with precomputed round tweakeys.
func NewPholkos256Context(key *Pholkos256Key, tweak *PholkosTweak) *Pholkos256Context {
	ctx := &Pholkos256Context{}
	ctx.Schedule(key, tweak)
	return ctx
}

// Schedule computes the round tweakeys from the key and tweak.
func (ctx *Pholkos256Context) Schedule(key *Pholkos256Key, tweak *PholkosTweak) {
	// Number of rounds = steps × 2 = 16
	numRounds := pholkos256Steps * 2

	// Initialize key state K⁰ (no expansion needed for 256-bit key)
	var keyState [2]Block
	copy(keyState[0][:], key[0:16])
	copy(keyState[1][:], key[16:32])

	// Initialize tweak state T⁰
	var tweakState Block
	copy(tweakState[:], tweak[:])

	// Generate round tweakeys
	for i := range numRounds + 1 {
		// γ function: RTK = K ⊕ T, with RC added to first substate
		// Tweak is XORed to each substate (T is 128-bit, repeated to each 128-bit substate)
		for j := range 2 {
			XorBlock(&ctx.rtk[i][j], &keyState[j], &tweakState)
		}
		// Add round constant to first substate only
		XorBlock(&ctx.rtk[i][0], &ctx.rtk[i][0], (*Block)(&pholkosRoundConstants[i]))

		// Update key and tweak states for next round
		if i < numRounds {
			// τ: apply cell permutation to tweak
			applyTau(&tweakState)

			// κ: update key state
			// 1. Apply word permutation π256
			pholkos256PermuteWords(&keyState)
			// 2. Apply τ to each substate
			applyTau(&keyState[0])
			applyTau(&keyState[1])
			// 3. Multiply each byte by 2 in GF(2^8)
			for j := range 2 {
				for b := range 16 {
					keyState[j][b] = gfDouble(keyState[j][b])
				}
			}
		}
	}
}

// Retweak updates only the tweak-dependent parts of the round tweakeys.
func (ctx *Pholkos256Context) Retweak(key *Pholkos256Key, tweak *PholkosTweak) {
	// For efficiency, we just recompute everything
	ctx.Schedule(key, tweak)
}

// pholkos256PermuteWords applies the word-wise permutation π256 to the key state.
func pholkos256PermuteWords(state *[2]Block) {
	// State has 8 words (32-bit each): 4 in each substate
	var words [8]uint32
	words[0] = binary.LittleEndian.Uint32(state[0][0:4])
	words[1] = binary.LittleEndian.Uint32(state[0][4:8])
	words[2] = binary.LittleEndian.Uint32(state[0][8:12])
	words[3] = binary.LittleEndian.Uint32(state[0][12:16])
	words[4] = binary.LittleEndian.Uint32(state[1][0:4])
	words[5] = binary.LittleEndian.Uint32(state[1][4:8])
	words[6] = binary.LittleEndian.Uint32(state[1][8:12])
	words[7] = binary.LittleEndian.Uint32(state[1][12:16])

	var newWords [8]uint32
	for j := range 8 {
		newWords[j] = words[pi256[j]]
	}

	binary.LittleEndian.PutUint32(state[0][0:4], newWords[0])
	binary.LittleEndian.PutUint32(state[0][4:8], newWords[1])
	binary.LittleEndian.PutUint32(state[0][8:12], newWords[2])
	binary.LittleEndian.PutUint32(state[0][12:16], newWords[3])
	binary.LittleEndian.PutUint32(state[1][0:4], newWords[4])
	binary.LittleEndian.PutUint32(state[1][4:8], newWords[5])
	binary.LittleEndian.PutUint32(state[1][8:12], newWords[6])
	binary.LittleEndian.PutUint32(state[1][12:16], newWords[7])
}

// pholkos256PermuteWordsState applies π256 to the cipher state (after a step).
func pholkos256PermuteWordsState(s0, s1 *Block) {
	var words [8]uint32
	words[0] = binary.LittleEndian.Uint32(s0[0:4])
	words[1] = binary.LittleEndian.Uint32(s0[4:8])
	words[2] = binary.LittleEndian.Uint32(s0[8:12])
	words[3] = binary.LittleEndian.Uint32(s0[12:16])
	words[4] = binary.LittleEndian.Uint32(s1[0:4])
	words[5] = binary.LittleEndian.Uint32(s1[4:8])
	words[6] = binary.LittleEndian.Uint32(s1[8:12])
	words[7] = binary.LittleEndian.Uint32(s1[12:16])

	var newWords [8]uint32
	for j := range 8 {
		newWords[j] = words[pi256[j]]
	}

	binary.LittleEndian.PutUint32(s0[0:4], newWords[0])
	binary.LittleEndian.PutUint32(s0[4:8], newWords[1])
	binary.LittleEndian.PutUint32(s0[8:12], newWords[2])
	binary.LittleEndian.PutUint32(s0[12:16], newWords[3])
	binary.LittleEndian.PutUint32(s1[0:4], newWords[4])
	binary.LittleEndian.PutUint32(s1[4:8], newWords[5])
	binary.LittleEndian.PutUint32(s1[8:12], newWords[6])
	binary.LittleEndian.PutUint32(s1[12:16], newWords[7])
}

// pholkos256PermuteWordsStateInv applies π256⁻¹ to the cipher state (for decryption).
func pholkos256PermuteWordsStateInv(s0, s1 *Block) {
	var words [8]uint32
	words[0] = binary.LittleEndian.Uint32(s0[0:4])
	words[1] = binary.LittleEndian.Uint32(s0[4:8])
	words[2] = binary.LittleEndian.Uint32(s0[8:12])
	words[3] = binary.LittleEndian.Uint32(s0[12:16])
	words[4] = binary.LittleEndian.Uint32(s1[0:4])
	words[5] = binary.LittleEndian.Uint32(s1[4:8])
	words[6] = binary.LittleEndian.Uint32(s1[8:12])
	words[7] = binary.LittleEndian.Uint32(s1[12:16])

	var newWords [8]uint32
	for j := range 8 {
		newWords[j] = words[pi256Inv[j]]
	}

	binary.LittleEndian.PutUint32(s0[0:4], newWords[0])
	binary.LittleEndian.PutUint32(s0[4:8], newWords[1])
	binary.LittleEndian.PutUint32(s0[8:12], newWords[2])
	binary.LittleEndian.PutUint32(s0[12:16], newWords[3])
	binary.LittleEndian.PutUint32(s1[0:4], newWords[4])
	binary.LittleEndian.PutUint32(s1[4:8], newWords[5])
	binary.LittleEndian.PutUint32(s1[8:12], newWords[6])
	binary.LittleEndian.PutUint32(s1[12:16], newWords[7])
}

// Encrypt encrypts a 256-bit block using the precomputed round tweakeys.
func (ctx *Pholkos256Context) Encrypt(block *Pholkos256Block) {
	s0 := (*Block)(unsafe.Pointer(&block[0]))
	s1 := (*Block)(unsafe.Pointer(&block[16]))

	// Initial round tweakey addition (RTK⁰)
	XorBlock(s0, s0, &ctx.rtk[0][0])
	XorBlock(s1, s1, &ctx.rtk[0][1])

	// Process steps
	numSteps := pholkos256Steps
	numRounds := numSteps * 2

	for step := range numSteps {
		roundIdx := step * 2

		// Two AES rounds per step
		for r := range 2 {
			rtkIdx := roundIdx + r + 1

			if roundIdx+r < numRounds-1 {
				// Full round: SB, SR, MC, ATK
				Round(s0, &ctx.rtk[rtkIdx][0])
				Round(s1, &ctx.rtk[rtkIdx][1])
			} else {
				// Final round: SB, SR, ATK (no MC)
				FinalRound(s0, &ctx.rtk[rtkIdx][0])
				FinalRound(s1, &ctx.rtk[rtkIdx][1])
			}
		}

		// Word permutation after each step except the last
		if step < numSteps-1 {
			pholkos256PermuteWordsState(s0, s1)
		}
	}
}

// Decrypt decrypts a 256-bit block using the precomputed round tweakeys.
func (ctx *Pholkos256Context) Decrypt(block *Pholkos256Block) {
	s0 := (*Block)(unsafe.Pointer(&block[0]))
	s1 := (*Block)(unsafe.Pointer(&block[16]))

	numSteps := pholkos256Steps
	numRounds := numSteps * 2

	// Process steps in reverse
	for step := numSteps - 1; step >= 0; step-- {
		roundIdx := step * 2

		// Inverse word permutation after each step except the last (first in reverse)
		if step < numSteps-1 {
			pholkos256PermuteWordsStateInv(s0, s1)
		}

		// Two AES rounds per step (in reverse)
		for r := 1; r >= 0; r-- {
			rtkIdx := roundIdx + r + 1

			if roundIdx+r < numRounds-1 {
				// Full inverse round: ATK, MC⁻¹, SR⁻¹, SB⁻¹
				AddRoundKey(s0, &ctx.rtk[rtkIdx][0])
				AddRoundKey(s1, &ctx.rtk[rtkIdx][1])
				InvMixColumns(s0)
				InvMixColumns(s1)
				InvShiftRows(s0)
				InvShiftRows(s1)
				InvSubBytes(s0)
				InvSubBytes(s1)
			} else {
				// Final inverse round: ATK, SR⁻¹, SB⁻¹ (no MC⁻¹)
				// Note: Key XOR comes first (inverse of FinalRound)
				AddRoundKey(s0, &ctx.rtk[rtkIdx][0])
				AddRoundKey(s1, &ctx.rtk[rtkIdx][1])
				InvShiftRows(s0)
				InvShiftRows(s1)
				InvSubBytes(s0)
				InvSubBytes(s1)
			}
		}
	}

	// Inverse of initial round tweakey addition
	XorBlock(s0, s0, &ctx.rtk[0][0])
	XorBlock(s1, s1, &ctx.rtk[0][1])
}

// NewPholkos512Context creates a new Pholkos-512 context with a 256-bit key.
func NewPholkos512Context(key *Pholkos256Key, tweak *PholkosTweak) *Pholkos512Context {
	ctx := &Pholkos512Context{}
	ctx.Schedule256(key, tweak)
	return ctx
}

// NewPholkos512Context512 creates a new Pholkos-512 context with a 512-bit key.
func NewPholkos512Context512(key *Pholkos512Key, tweak *PholkosTweak) *Pholkos512Context {
	ctx := &Pholkos512Context{}
	ctx.Schedule512(key, tweak)
	return ctx
}

// expandKey256to512 expands a 256-bit key to 512 bits using matrix MA.
// MA = circ(11001000) with branch number 4.
func expandKey256to512(key *Pholkos256Key) Pholkos512Key {
	var expanded Pholkos512Key

	// Copy original 256 bits
	copy(expanded[0:32], key[:])

	// Read words K0..K7
	var k [8]uint32
	for i := range 8 {
		k[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	// MA = circ(11001000) means each row has 1s at positions 0, 1, 4
	// Row i: result[i] = k[(i+0)%8] ^ k[(i+1)%8] ^ k[(i+4)%8]
	for i := range 8 {
		expanded[32+i*4] = byte(k[(i+0)%8] ^ k[(i+1)%8] ^ k[(i+4)%8])
		expanded[32+i*4+1] = byte((k[(i+0)%8] ^ k[(i+1)%8] ^ k[(i+4)%8]) >> 8)
		expanded[32+i*4+2] = byte((k[(i+0)%8] ^ k[(i+1)%8] ^ k[(i+4)%8]) >> 16)
		expanded[32+i*4+3] = byte((k[(i+0)%8] ^ k[(i+1)%8] ^ k[(i+4)%8]) >> 24)
	}

	return expanded
}

// Schedule256 computes round tweakeys from a 256-bit key and tweak.
func (ctx *Pholkos512Context) Schedule256(key *Pholkos256Key, tweak *PholkosTweak) {
	// Expand 256-bit key to 512 bits
	expandedKey := expandKey256to512(key)
	ctx.schedule(&expandedKey, tweak)
}

// Schedule512 computes round tweakeys from a 512-bit key and tweak.
func (ctx *Pholkos512Context) Schedule512(key *Pholkos512Key, tweak *PholkosTweak) {
	ctx.schedule(key, tweak)
}

func (ctx *Pholkos512Context) schedule(key *Pholkos512Key, tweak *PholkosTweak) {
	numRounds := pholkos512Steps * 2

	// Initialize key state K⁰
	var keyState [4]Block
	copy(keyState[0][:], key[0:16])
	copy(keyState[1][:], key[16:32])
	copy(keyState[2][:], key[32:48])
	copy(keyState[3][:], key[48:64])

	// Initialize tweak state T⁰
	var tweakState Block
	copy(tweakState[:], tweak[:])

	// Generate round tweakeys
	for i := range numRounds + 1 {
		// γ function: RTK = K ⊕ T, with RC added to first substate
		// Tweak is XORed to each substate (T is 128-bit, j mod 4 for 512-bit)
		for j := range 4 {
			XorBlock(&ctx.rtk[i][j], &keyState[j], &tweakState)
		}
		// Add round constant to first substate only
		XorBlock(&ctx.rtk[i][0], &ctx.rtk[i][0], (*Block)(&pholkosRoundConstants[i]))

		// Update key and tweak states for next round
		if i < numRounds {
			// τ: apply cell permutation to tweak
			applyTau(&tweakState)

			// κ: update key state
			// 1. Apply word permutation π512
			pholkos512PermuteWords(&keyState)
			// 2. Apply τ to each substate
			for j := range 4 {
				applyTau(&keyState[j])
			}
			// 3. Multiply each byte by 2 in GF(2^8)
			for j := range 4 {
				for b := range 16 {
					keyState[j][b] = gfDouble(keyState[j][b])
				}
			}
		}
	}
}

// pholkos512PermuteWords applies the word-wise permutation π512 to the key state.
func pholkos512PermuteWords(state *[4]Block) {
	// State has 16 words (32-bit each): 4 in each substate
	var words [16]uint32
	for s := range 4 {
		words[s*4+0] = binary.LittleEndian.Uint32(state[s][0:4])
		words[s*4+1] = binary.LittleEndian.Uint32(state[s][4:8])
		words[s*4+2] = binary.LittleEndian.Uint32(state[s][8:12])
		words[s*4+3] = binary.LittleEndian.Uint32(state[s][12:16])
	}

	var newWords [16]uint32
	for j := range 16 {
		newWords[j] = words[pi512[j]]
	}

	for s := range 4 {
		binary.LittleEndian.PutUint32(state[s][0:4], newWords[s*4+0])
		binary.LittleEndian.PutUint32(state[s][4:8], newWords[s*4+1])
		binary.LittleEndian.PutUint32(state[s][8:12], newWords[s*4+2])
		binary.LittleEndian.PutUint32(state[s][12:16], newWords[s*4+3])
	}
}

// pholkos512PermuteWordsState applies π512 to the cipher state.
func pholkos512PermuteWordsState(s0, s1, s2, s3 *Block) {
	var words [16]uint32
	words[0] = binary.LittleEndian.Uint32(s0[0:4])
	words[1] = binary.LittleEndian.Uint32(s0[4:8])
	words[2] = binary.LittleEndian.Uint32(s0[8:12])
	words[3] = binary.LittleEndian.Uint32(s0[12:16])
	words[4] = binary.LittleEndian.Uint32(s1[0:4])
	words[5] = binary.LittleEndian.Uint32(s1[4:8])
	words[6] = binary.LittleEndian.Uint32(s1[8:12])
	words[7] = binary.LittleEndian.Uint32(s1[12:16])
	words[8] = binary.LittleEndian.Uint32(s2[0:4])
	words[9] = binary.LittleEndian.Uint32(s2[4:8])
	words[10] = binary.LittleEndian.Uint32(s2[8:12])
	words[11] = binary.LittleEndian.Uint32(s2[12:16])
	words[12] = binary.LittleEndian.Uint32(s3[0:4])
	words[13] = binary.LittleEndian.Uint32(s3[4:8])
	words[14] = binary.LittleEndian.Uint32(s3[8:12])
	words[15] = binary.LittleEndian.Uint32(s3[12:16])

	var newWords [16]uint32
	for j := range 16 {
		newWords[j] = words[pi512[j]]
	}

	binary.LittleEndian.PutUint32(s0[0:4], newWords[0])
	binary.LittleEndian.PutUint32(s0[4:8], newWords[1])
	binary.LittleEndian.PutUint32(s0[8:12], newWords[2])
	binary.LittleEndian.PutUint32(s0[12:16], newWords[3])
	binary.LittleEndian.PutUint32(s1[0:4], newWords[4])
	binary.LittleEndian.PutUint32(s1[4:8], newWords[5])
	binary.LittleEndian.PutUint32(s1[8:12], newWords[6])
	binary.LittleEndian.PutUint32(s1[12:16], newWords[7])
	binary.LittleEndian.PutUint32(s2[0:4], newWords[8])
	binary.LittleEndian.PutUint32(s2[4:8], newWords[9])
	binary.LittleEndian.PutUint32(s2[8:12], newWords[10])
	binary.LittleEndian.PutUint32(s2[12:16], newWords[11])
	binary.LittleEndian.PutUint32(s3[0:4], newWords[12])
	binary.LittleEndian.PutUint32(s3[4:8], newWords[13])
	binary.LittleEndian.PutUint32(s3[8:12], newWords[14])
	binary.LittleEndian.PutUint32(s3[12:16], newWords[15])
}

// pholkos512PermuteWordsStateInv applies π512⁻¹ to the cipher state.
func pholkos512PermuteWordsStateInv(s0, s1, s2, s3 *Block) {
	var words [16]uint32
	words[0] = binary.LittleEndian.Uint32(s0[0:4])
	words[1] = binary.LittleEndian.Uint32(s0[4:8])
	words[2] = binary.LittleEndian.Uint32(s0[8:12])
	words[3] = binary.LittleEndian.Uint32(s0[12:16])
	words[4] = binary.LittleEndian.Uint32(s1[0:4])
	words[5] = binary.LittleEndian.Uint32(s1[4:8])
	words[6] = binary.LittleEndian.Uint32(s1[8:12])
	words[7] = binary.LittleEndian.Uint32(s1[12:16])
	words[8] = binary.LittleEndian.Uint32(s2[0:4])
	words[9] = binary.LittleEndian.Uint32(s2[4:8])
	words[10] = binary.LittleEndian.Uint32(s2[8:12])
	words[11] = binary.LittleEndian.Uint32(s2[12:16])
	words[12] = binary.LittleEndian.Uint32(s3[0:4])
	words[13] = binary.LittleEndian.Uint32(s3[4:8])
	words[14] = binary.LittleEndian.Uint32(s3[8:12])
	words[15] = binary.LittleEndian.Uint32(s3[12:16])

	var newWords [16]uint32
	for j := range 16 {
		newWords[j] = words[pi512Inv[j]]
	}

	binary.LittleEndian.PutUint32(s0[0:4], newWords[0])
	binary.LittleEndian.PutUint32(s0[4:8], newWords[1])
	binary.LittleEndian.PutUint32(s0[8:12], newWords[2])
	binary.LittleEndian.PutUint32(s0[12:16], newWords[3])
	binary.LittleEndian.PutUint32(s1[0:4], newWords[4])
	binary.LittleEndian.PutUint32(s1[4:8], newWords[5])
	binary.LittleEndian.PutUint32(s1[8:12], newWords[6])
	binary.LittleEndian.PutUint32(s1[12:16], newWords[7])
	binary.LittleEndian.PutUint32(s2[0:4], newWords[8])
	binary.LittleEndian.PutUint32(s2[4:8], newWords[9])
	binary.LittleEndian.PutUint32(s2[8:12], newWords[10])
	binary.LittleEndian.PutUint32(s2[12:16], newWords[11])
	binary.LittleEndian.PutUint32(s3[0:4], newWords[12])
	binary.LittleEndian.PutUint32(s3[4:8], newWords[13])
	binary.LittleEndian.PutUint32(s3[8:12], newWords[14])
	binary.LittleEndian.PutUint32(s3[12:16], newWords[15])
}

// Encrypt encrypts a 512-bit block using the precomputed round tweakeys.
func (ctx *Pholkos512Context) Encrypt(block *Pholkos512Block) {
	s0 := (*Block)(unsafe.Pointer(&block[0]))
	s1 := (*Block)(unsafe.Pointer(&block[16]))
	s2 := (*Block)(unsafe.Pointer(&block[32]))
	s3 := (*Block)(unsafe.Pointer(&block[48]))

	// Initial round tweakey addition (RTK⁰)
	XorBlock(s0, s0, &ctx.rtk[0][0])
	XorBlock(s1, s1, &ctx.rtk[0][1])
	XorBlock(s2, s2, &ctx.rtk[0][2])
	XorBlock(s3, s3, &ctx.rtk[0][3])

	// Process steps
	numSteps := pholkos512Steps
	numRounds := numSteps * 2

	for step := range numSteps {
		roundIdx := step * 2

		// Two AES rounds per step
		for r := range 2 {
			rtkIdx := roundIdx + r + 1

			if roundIdx+r < numRounds-1 {
				// Full round: SB, SR, MC, ATK
				Round(s0, &ctx.rtk[rtkIdx][0])
				Round(s1, &ctx.rtk[rtkIdx][1])
				Round(s2, &ctx.rtk[rtkIdx][2])
				Round(s3, &ctx.rtk[rtkIdx][3])
			} else {
				// Final round: SB, SR, ATK (no MC)
				FinalRound(s0, &ctx.rtk[rtkIdx][0])
				FinalRound(s1, &ctx.rtk[rtkIdx][1])
				FinalRound(s2, &ctx.rtk[rtkIdx][2])
				FinalRound(s3, &ctx.rtk[rtkIdx][3])
			}
		}

		// Word permutation after each step except the last
		if step < numSteps-1 {
			pholkos512PermuteWordsState(s0, s1, s2, s3)
		}
	}
}

// Decrypt decrypts a 512-bit block using the precomputed round tweakeys.
func (ctx *Pholkos512Context) Decrypt(block *Pholkos512Block) {
	s0 := (*Block)(unsafe.Pointer(&block[0]))
	s1 := (*Block)(unsafe.Pointer(&block[16]))
	s2 := (*Block)(unsafe.Pointer(&block[32]))
	s3 := (*Block)(unsafe.Pointer(&block[48]))

	numSteps := pholkos512Steps
	numRounds := numSteps * 2

	// Process steps in reverse
	for step := numSteps - 1; step >= 0; step-- {
		roundIdx := step * 2

		// Inverse word permutation after each step except the last (first in reverse)
		if step < numSteps-1 {
			pholkos512PermuteWordsStateInv(s0, s1, s2, s3)
		}

		// Two AES rounds per step (in reverse)
		for r := 1; r >= 0; r-- {
			rtkIdx := roundIdx + r + 1

			if roundIdx+r < numRounds-1 {
				// Full inverse round: ATK, MC⁻¹, SR⁻¹, SB⁻¹
				AddRoundKey(s0, &ctx.rtk[rtkIdx][0])
				AddRoundKey(s1, &ctx.rtk[rtkIdx][1])
				AddRoundKey(s2, &ctx.rtk[rtkIdx][2])
				AddRoundKey(s3, &ctx.rtk[rtkIdx][3])
				InvMixColumns(s0)
				InvMixColumns(s1)
				InvMixColumns(s2)
				InvMixColumns(s3)
				InvShiftRows(s0)
				InvShiftRows(s1)
				InvShiftRows(s2)
				InvShiftRows(s3)
				InvSubBytes(s0)
				InvSubBytes(s1)
				InvSubBytes(s2)
				InvSubBytes(s3)
			} else {
				// Final inverse round: ATK, SR⁻¹, SB⁻¹ (no MC⁻¹)
				// Note: Key XOR comes first (inverse of FinalRound)
				AddRoundKey(s0, &ctx.rtk[rtkIdx][0])
				AddRoundKey(s1, &ctx.rtk[rtkIdx][1])
				AddRoundKey(s2, &ctx.rtk[rtkIdx][2])
				AddRoundKey(s3, &ctx.rtk[rtkIdx][3])
				InvShiftRows(s0)
				InvShiftRows(s1)
				InvShiftRows(s2)
				InvShiftRows(s3)
				InvSubBytes(s0)
				InvSubBytes(s1)
				InvSubBytes(s2)
				InvSubBytes(s3)
			}
		}
	}

	// Inverse of initial round tweakey addition
	XorBlock(s0, s0, &ctx.rtk[0][0])
	XorBlock(s1, s1, &ctx.rtk[0][1])
	XorBlock(s2, s2, &ctx.rtk[0][2])
	XorBlock(s3, s3, &ctx.rtk[0][3])
}

// Pholkos256Encrypt encrypts a single 256-bit block.
// This is a convenience function that creates a context and encrypts.
func Pholkos256Encrypt(block *Pholkos256Block, key *Pholkos256Key, tweak *PholkosTweak) {
	ctx := NewPholkos256Context(key, tweak)
	ctx.Encrypt(block)
}

// Pholkos256Decrypt decrypts a single 256-bit block.
func Pholkos256Decrypt(block *Pholkos256Block, key *Pholkos256Key, tweak *PholkosTweak) {
	ctx := NewPholkos256Context(key, tweak)
	ctx.Decrypt(block)
}

// Pholkos512Encrypt encrypts a single 512-bit block with a 256-bit key.
func Pholkos512Encrypt(block *Pholkos512Block, key *Pholkos256Key, tweak *PholkosTweak) {
	ctx := NewPholkos512Context(key, tweak)
	ctx.Encrypt(block)
}

// Pholkos512Decrypt decrypts a single 512-bit block with a 256-bit key.
func Pholkos512Decrypt(block *Pholkos512Block, key *Pholkos256Key, tweak *PholkosTweak) {
	ctx := NewPholkos512Context(key, tweak)
	ctx.Decrypt(block)
}

// Pholkos512Encrypt512 encrypts a single 512-bit block with a 512-bit key.
func Pholkos512Encrypt512(block *Pholkos512Block, key *Pholkos512Key, tweak *PholkosTweak) {
	ctx := NewPholkos512Context512(key, tweak)
	ctx.Encrypt(block)
}

// Pholkos512Decrypt512 decrypts a single 512-bit block with a 512-bit key.
func Pholkos512Decrypt512(block *Pholkos512Block, key *Pholkos512Key, tweak *PholkosTweak) {
	ctx := NewPholkos512Context512(key, tweak)
	ctx.Decrypt(block)
}
