package aes

// Deoxys-BC-256 Tweakable Block Cipher
// Based on "Deoxys v1.41" (https://competitions.cr.yp.to/round3/deoxysv141.pdf)
//
// Deoxys-BC is a tweakable block cipher using the TWEAKEY framework.
// This file provides:
// - Standard Deoxys-BC-256: 14 rounds with precomputed subtweakeys
// - Generic Deoxys round functions with domain separation support

// Tweakey256 represents a 256-bit tweakey (key || tweak, each 128 bits)
type Tweakey256 [32]byte

// DeoxysBC256RoundKeys holds the 15 precomputed subtweakeys for standard Deoxys-BC-256
type DeoxysBC256RoundKeys struct {
	STK [15]Block
}

// DeoxysBC256RoundKeysHW holds precomputed keys for hardware-accelerated Deoxys-BC-256.
// Includes both encryption keys (STK) and inverse keys (InvSTK) for decryption.
type DeoxysBC256RoundKeysHW struct {
	DeoxysBC256RoundKeys
	// InvSTK holds InvMixColumns(STK[1..13]) for hardware-accelerated decryption.
	// InvSTK[i] corresponds to InvMixColumns(STK[i]) for i in 1..13.
	// InvSTK[0] and InvSTK[14] are unused (first and last rounds don't use InvMixColumns).
	InvSTK [15]Block
}

// DeoxysRoundTweakeys holds expanded tweakey states for domain-separated constructions
type DeoxysRoundTweakeys struct {
	TK1 [17]Block
	TK2 [17]Block
}

// DeoxysPermuteTK applies the h permutation to a tweakey state.
func DeoxysPermuteTK(tk *Block) {
	*tk = Block{
		tk[7], tk[0], tk[13], tk[10], tk[11], tk[4], tk[1], tk[14],
		tk[15], tk[8], tk[5], tk[2], tk[3], tk[12], tk[9], tk[6],
	}
}

// DeoxysLFSR2 applies the LFSR2 transformation to each byte of a tweakey state.
// LFSR2: (b7||...||b0) -> (b6||...||b0||b7⊕b5), polynomial x^8 + x^5 + 1
func DeoxysLFSR2(tk *Block) {
	for i := range tk {
		b := tk[i]
		tk[i] = (b << 1) | (((b >> 7) ^ (b >> 5)) & 1)
	}
}

// deoxysGF256Mul2 applies GF(2^8) multiplication by 2 using AES polynomial.
func deoxysGF256Mul2(tk *Block) {
	for i := range tk {
		b := tk[i]
		tk[i] = (b << 1) ^ ((b >> 7) * 0x1b)
	}
}

// aesRcon returns the AES round constant at position i (0-indexed).
func aesRcon(i int) byte {
	rc := byte(1)
	for j := 0; j < i; j++ {
		rc = (rc << 1) ^ ((rc >> 7) * 0x1b)
	}
	return rc
}

// xorBlocks XORs src into dst.
func xorBlocks(dst, src *Block) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// NewDeoxysBC256 expands a 256-bit tweakey into precomputed subtweakeys.
// Uses GF(2^8) multiplication for TK2 as per SUPERCOP reference.
func NewDeoxysBC256(tweakey *Tweakey256) *DeoxysBC256RoundKeys {
	return &NewDeoxysBC256HW(tweakey).DeoxysBC256RoundKeys
}

// NewDeoxysBC256HW expands a 256-bit tweakey into precomputed subtweakeys for
// hardware-accelerated encryption and decryption. Includes inverse keys.
func NewDeoxysBC256HW(tweakey *Tweakey256) *DeoxysBC256RoundKeysHW {
	rk := &DeoxysBC256RoundKeysHW{}
	var tk1, tk2 Block
	copy(tk1[:], tweakey[0:16])
	copy(tk2[:], tweakey[16:32])

	for i := range rk.STK {
		// Round constant: column 0 = [1,2,4,8], column 1 = [rc,rc,rc,rc]
		rc := aesRcon(15 + i)
		rk.STK[i] = Block{
			1 ^ tk1[0] ^ tk2[0], 2 ^ tk1[1] ^ tk2[1], 4 ^ tk1[2] ^ tk2[2], 8 ^ tk1[3] ^ tk2[3],
			rc ^ tk1[4] ^ tk2[4], rc ^ tk1[5] ^ tk2[5], rc ^ tk1[6] ^ tk2[6], rc ^ tk1[7] ^ tk2[7],
			tk1[8] ^ tk2[8], tk1[9] ^ tk2[9], tk1[10] ^ tk2[10], tk1[11] ^ tk2[11],
			tk1[12] ^ tk2[12], tk1[13] ^ tk2[13], tk1[14] ^ tk2[14], tk1[15] ^ tk2[15],
		}

		// Compute inverse key for decryption (InvMixColumns on middle rounds)
		if i >= 1 && i <= 13 {
			rk.InvSTK[i] = rk.STK[i]
			InvMixColumns(&rk.InvSTK[i])
		}

		DeoxysPermuteTK(&tk1)
		DeoxysPermuteTK(&tk2)
		deoxysGF256Mul2(&tk2)
	}
	return rk
}

// DeoxysBC256Encrypt encrypts a block using Deoxys-BC-256 (14 rounds).
func DeoxysBC256Encrypt(rk *DeoxysBC256RoundKeys, plaintext *Block) Block {
	state := *plaintext
	xorBlocks(&state, &rk.STK[0])

	for r := 1; r <= 13; r++ {
		SubBytes(&state)
		ShiftRows(&state)
		MixColumns(&state)
		xorBlocks(&state, &rk.STK[r])
	}

	SubBytes(&state)
	ShiftRows(&state)
	xorBlocks(&state, &rk.STK[14])
	return state
}

// DeoxysBC256Decrypt decrypts a block using Deoxys-BC-256 (14 rounds).
func DeoxysBC256Decrypt(rk *DeoxysBC256RoundKeys, ciphertext *Block) Block {
	state := *ciphertext
	xorBlocks(&state, &rk.STK[14])
	InvShiftRows(&state)
	InvSubBytes(&state)

	for r := 13; r >= 1; r-- {
		xorBlocks(&state, &rk.STK[r])
		InvMixColumns(&state)
		InvShiftRows(&state)
		InvSubBytes(&state)
	}

	xorBlocks(&state, &rk.STK[0])
	return state
}

// DeoxysExpandTweakey256 expands a tweakey for domain-separated constructions.
// Returns 17 round tweakey states (indices 0-16) using LFSR2.
func DeoxysExpandTweakey256(tweakey *Tweakey256) *DeoxysRoundTweakeys {
	rtk := &DeoxysRoundTweakeys{}
	copy(rtk.TK1[0][:], tweakey[0:16])
	copy(rtk.TK2[0][:], tweakey[16:32])

	for i := 1; i < 17; i++ {
		rtk.TK1[i] = rtk.TK1[i-1]
		DeoxysPermuteTK(&rtk.TK1[i])
		rtk.TK2[i] = rtk.TK2[i-1]
		DeoxysPermuteTK(&rtk.TK2[i])
		DeoxysLFSR2(&rtk.TK2[i])
	}
	return rtk
}

// DeoxysRoundConstant generates a round constant with optional domain separation.
// Format: column 0 = [1,2,4,8], column 1 = [rc,rc,rc,rc], column 2 = [domain,domain,domain,domain]
func DeoxysRoundConstant(domain byte, roundNum int) Block {
	rc := aesRcon(roundNum)
	return Block{
		1, 2, 4, 8,
		rc, rc, rc, rc,
		domain, domain, domain, domain,
		0, 0, 0, 0,
	}
}

// DeoxysAddRoundTweakey XORs round tweakey and round constant into the state.
func DeoxysAddRoundTweakey(state *Block, rtk *DeoxysRoundTweakeys, roundNum int, domain byte) {
	rconst := DeoxysRoundConstant(domain, roundNum)
	for i := range state {
		state[i] ^= rtk.TK1[roundNum][i] ^ rtk.TK2[roundNum][i] ^ rconst[i]
	}
}

// DeoxysRound performs one Deoxys round: AddRoundTweakey, SubBytes, ShiftRows, MixColumns.
func DeoxysRound(state *Block, rtk *DeoxysRoundTweakeys, roundNum int, domain byte) {
	DeoxysAddRoundTweakey(state, rtk, roundNum, domain)
	SubBytes(state)
	ShiftRows(state)
	MixColumns(state)
}
