//go:build (!amd64 && !arm64) || purego

package aes

// DeoxysBC256EncryptHW encrypts using Deoxys-BC-256 (software fallback)
func DeoxysBC256EncryptHW(rk *DeoxysBC256RoundKeys, plaintext *Block) Block {
	return DeoxysBC256Encrypt(rk, plaintext)
}

// DeoxysBC256DecryptHW decrypts using Deoxys-BC-256 (software fallback)
func DeoxysBC256DecryptHW(rk *DeoxysBC256RoundKeysHW, ciphertext *Block) Block {
	return DeoxysBC256Decrypt(&rk.DeoxysBC256RoundKeys, ciphertext)
}

// ButterKnifeHW evaluates ButterKnife TPRF (software fallback)
func ButterKnifeHW(tweakey *Tweakey256, input *Block) *ButterKnifeOutput {
	return ButterKnife(tweakey, input)
}

// ButterKnifeContextHW holds pre-expanded tweakey for evaluation
type ButterKnifeContextHW struct {
	// Pre-computed subtweakeys for pre-fork phase (rounds 0-6, 7 keys)
	preForkSTK [7]Block
	// Pre-computed subtweakeys for each branch (8 branches, 9 keys each: rounds 7-15)
	branchSTK [8][9]Block
}

// EvalHWInto evaluates ButterKnife (software fallback), writing the 8 output
// branches into out without allocating.
func (ctx *ButterKnifeContextHW) EvalHWInto(input *Block, out *ButterKnifeOutput) {
	// Pre-fork: 7 rounds with domain 0
	forkState := *input
	for i := 0; i < 7; i++ {
		xorBlocks(&forkState, &ctx.preForkSTK[i])
		RoundNoKey(&forkState)
	}

	// Process each branch
	for j := 0; j < 8; j++ {
		branchState := forkState

		// 8 rounds
		for i := 0; i < 8; i++ {
			xorBlocks(&branchState, &ctx.branchSTK[j][i])
			RoundNoKey(&branchState)
		}

		// Final tweakey addition
		xorBlocks(&branchState, &ctx.branchSTK[j][8])

		// Feed-forward
		xorBlocks(&branchState, &forkState)
		out[j] = branchState
	}
}
