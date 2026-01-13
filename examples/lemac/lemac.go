package lemac

import (
	"encoding/binary"

	aes "github.com/jedisct1/go-aes"
)

const (
	// LeMacKeySize is the key size in bytes for LeMac (AES-128)
	LeMacKeySize = 16
	// LeMacNonceSize is the nonce size in bytes
	LeMacNonceSize = 16
	// LeMacTagSize is the tag size in bytes (128-bit MAC)
	LeMacTagSize = 16
	// LeMacBlockSize is the message block size in bytes (64 bytes = 4 AES blocks)
	LeMacBlockSize = 64
)

// LeMacContext holds the precomputed state for LeMac MAC computation
type LeMacContext struct {
	initState  [9]aes.Block     // Initial state for absorption phase
	subkeys    [18]aes.Block    // Subkeys for finalization
	nonceKS    *aes.KeySchedule // Key schedule for nonce processing
	finalizeKS *aes.KeySchedule // Key schedule for final encryption
}

// NewLeMacContext initializes a new LeMac context from a 16-byte key
func NewLeMacContext(key [LeMacKeySize]byte) *LeMacContext {
	ctx := &LeMacContext{}
	mainKS, _ := aes.NewKeySchedule(key[:])

	// Derive initial state: k_init[i] = AES(key, i) for i = 0..8
	initBlocks := make([]aes.Block, 9)
	for i := range 9 {
		binary.LittleEndian.PutUint64(initBlocks[i][0:8], uint64(i))
	}
	aes.EncryptBlocksAES128(initBlocks, mainKS)
	copy(ctx.initState[:], initBlocks)

	// Derive subkeys: k_final[i] = AES(key, i+9) for i = 0..17
	subkeyBlocks := make([]aes.Block, 18)
	for i := range 18 {
		binary.LittleEndian.PutUint64(subkeyBlocks[i][0:8], uint64(i+9))
	}
	aes.EncryptBlocksAES128(subkeyBlocks, mainKS)
	copy(ctx.subkeys[:], subkeyBlocks)

	// Derive nonce key: k2 = AES(key, 27)
	var nonceKeyBlock aes.Block
	binary.LittleEndian.PutUint64(nonceKeyBlock[0:8], 27)
	aes.EncryptBlockAES128(&nonceKeyBlock, mainKS)
	ctx.nonceKS, _ = aes.NewKeySchedule(nonceKeyBlock[:])

	// Derive finalize key: k3 = AES(key, 28)
	var finalizeKeyBlock aes.Block
	binary.LittleEndian.PutUint64(finalizeKeyBlock[0:8], 28)
	aes.EncryptBlockAES128(&finalizeKeyBlock, mainKS)
	ctx.finalizeKS, _ = aes.NewKeySchedule(finalizeKeyBlock[:])

	return ctx
}

// LeMac computes the LeMac MAC for a message with the given nonce
func LeMac(ctx *LeMacContext, message []byte, nonce [LeMacNonceSize]byte) [LeMacTagSize]byte {
	finalState := lemacAbsorb(ctx, message)
	return lemacFinalize(ctx, &finalState, nonce)
}

// lemacAbsorb processes the message and returns the final state
func lemacAbsorb(ctx *LeMacContext, message []byte) [9]aes.Block {
	state := ctx.initState
	var rr, r0, r1, r2 aes.Block

	// Process complete 64-byte blocks (4 AES blocks each)
	for offset := 0; offset+LeMacBlockSize <= len(message); offset += LeMacBlockSize {
		var m0, m1, m2, m3 aes.Block
		copy(m0[:], message[offset:])
		copy(m1[:], message[offset+16:])
		copy(m2[:], message[offset+32:])
		copy(m3[:], message[offset+48:])
		lemacRound(&state, &rr, &r0, &r1, &r2, &m0, &m1, &m2, &m3)
	}

	// Padding: append 0x01 followed by zeros
	var padded [LeMacBlockSize]byte
	remaining := len(message) % LeMacBlockSize
	copy(padded[:remaining], message[len(message)-remaining:])
	padded[remaining] = 0x01

	var m0, m1, m2, m3 aes.Block
	copy(m0[:], padded[0:16])
	copy(m1[:], padded[16:32])
	copy(m2[:], padded[32:48])
	copy(m3[:], padded[48:64])
	lemacRound(&state, &rr, &r0, &r1, &r2, &m0, &m1, &m2, &m3)

	// Four blank rounds with zero message blocks
	var zero aes.Block
	for range 4 {
		lemacRound(&state, &rr, &r0, &r1, &r2, &zero, &zero, &zero, &zero)
	}

	return state
}

// lemacRound applies one round of the LeMac state update function
func lemacRound(state *[9]aes.Block, rr, r0, r1, r2, m0, m1, m2, m3 *aes.Block) {
	t := state[8]

	// Update states using hardware-accelerated rounds
	state[8] = state[7]
	aes.RoundHW(&state[8], m3)
	state[7] = state[6]
	aes.RoundHW(&state[7], m1)
	state[6] = state[5]
	aes.RoundHW(&state[6], m1)
	state[5] = state[4]
	aes.RoundHW(&state[5], m0)
	state[4] = state[3]
	aes.RoundHW(&state[4], m0)

	// state[3] uses r1 XOR r2 as the round key
	var keyXor aes.Block
	aes.XorBlock(&keyXor, r1, r2)
	state[3] = state[2]
	aes.RoundHW(&state[3], &keyXor)

	state[2] = state[1]
	aes.RoundHW(&state[2], m3)
	state[1] = state[0]
	aes.RoundHW(&state[1], m3)

	// state[0] gets XORed with saved t and m2
	for i := range 16 {
		state[0][i] ^= t[i] ^ m2[i]
	}

	// Update rolling registers
	*r2 = *r1
	*r1 = *r0
	aes.XorBlock(r0, rr, m1)
	*rr = *m2
}

// lemacFinalize produces the final 16-byte tag using parallel per-block multi-round operations
func lemacFinalize(ctx *LeMacContext, state *[9]aes.Block, nonce [LeMacNonceSize]byte) [LeMacTagSize]byte {
	// Apply modified AES to state blocks using parallel per-block operations
	// Process blocks 0-3 in parallel, each with its own key schedule
	var blocks4 aes.Block4
	blocks4.SetBlock(0, &state[0])
	blocks4.SetBlock(1, &state[1])
	blocks4.SetBlock(2, &state[2])
	blocks4.SetBlock(3, &state[3])

	// Prepare per-block round keys for blocks 0-3
	// Each block i uses subkeys[i], subkeys[i+1], ..., subkeys[i+9], then zero
	var keySets4 aes.PerBlockRoundKeys10_4
	for i := range 4 {
		aes.AddRoundKey(blocks4.GetBlock(i), &ctx.subkeys[i])
		for j := range 10 {
			if j < 9 {
				keySets4[i][j] = ctx.subkeys[i+j+1]
			} else {
				keySets4[i][j] = aes.Block{} // Zero key for round 10
			}
		}
	}

	// Apply 10 full rounds (each with its own keys)
	aes.PerBlockRounds10_4HW(&blocks4, &keySets4)

	// XOR the results
	var t aes.Block
	t = *blocks4.GetBlock(0)
	for i := 1; i < 4; i++ {
		aes.XorBlock(&t, &t, blocks4.GetBlock(i))
	}

	// Process remaining blocks 4-8 individually
	for i := 4; i < 9; i++ {
		var temp aes.Block
		temp = state[i]

		// Modified AES: AddRoundKey + 10 full rounds (last with zero key)
		aes.AddRoundKey(&temp, &ctx.subkeys[i])
		var keys aes.RoundKeys10
		for j := range 9 {
			keys[j] = ctx.subkeys[i+j+1]
		}
		keys[9] = aes.Block{} // Zero key for round 10
		aes.Rounds10HW(&temp, &keys)

		aes.XorBlock(&t, &t, &temp)
	}

	// Add nonce contribution: N XOR AES(k2, N)
	var nonceEnc aes.Block
	copy(nonceEnc[:], nonce[:])
	aes.EncryptBlockAES128(&nonceEnc, ctx.nonceKS)
	aes.XorBlock(&t, &t, &nonceEnc)
	for i := range 16 {
		t[i] ^= nonce[i]
	}

	// Final encryption: AES(k3, t)
	aes.EncryptBlockAES128(&t, ctx.finalizeKS)
	return t
}
