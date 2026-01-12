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

// NewButterKnifeContextHW creates a context with pre-computed subtweakeys
func NewButterKnifeContextHW(tweakey *Tweakey256) *ButterKnifeContextHW {
	ctx := &ButterKnifeContextHW{}
	rtk := DeoxysExpandTweakey256(tweakey)

	// Pre-compute pre-fork subtweakeys (domain 0, rounds 0-6)
	for i := 0; i < 7; i++ {
		rconst := DeoxysRoundConstant(0, i)
		for j := 0; j < 16; j++ {
			ctx.preForkSTK[i][j] = rtk.TK1[i][j] ^ rtk.TK2[i][j] ^ rconst[j]
		}
	}

	// Pre-compute branch subtweakeys (domains 1-8, rounds 7-15)
	for branch := 0; branch < 8; branch++ {
		domain := byte(branch + 1)
		for r := 0; r < 9; r++ {
			roundNum := 7 + r
			rconst := DeoxysRoundConstant(domain, roundNum)
			for j := 0; j < 16; j++ {
				ctx.branchSTK[branch][r][j] = rtk.TK1[roundNum][j] ^ rtk.TK2[roundNum][j] ^ rconst[j]
			}
		}
	}

	return ctx
}

// EvalHW evaluates ButterKnife (software fallback)
func (ctx *ButterKnifeContextHW) EvalHW(input *Block) *ButterKnifeOutput {
	var output ButterKnifeOutput

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
		output[j] = branchState
	}

	return &output
}
