//go:build arm64 && !purego

package aes

// Assembly function declarations for Deoxys-BC-256 and ButterKnife

//go:noescape
func deoxysBC256EncryptASM(state *Block, stk *[15]Block)

//go:noescape
func deoxysBC256DecryptASM(state *Block, stk *DeoxysBC256RoundKeysHW)

//go:noescape
func butterKnifePreForkASM(state *Block, stk *[16]Block)

//go:noescape
func butterKnifeBranchASM(state *Block, forkState *Block, stk *[9]Block)

//go:noescape
func butterKnife4BranchesASM(branches *Block4, forkState *Block, stk *[4][9]Block)

// DeoxysBC256EncryptHW encrypts using hardware-accelerated Deoxys-BC-256
func DeoxysBC256EncryptHW(rk *DeoxysBC256RoundKeys, plaintext *Block) Block {
	if CPU.HasARMCrypto {
		state := *plaintext
		deoxysBC256EncryptASM(&state, &rk.STK)
		return state
	}
	return DeoxysBC256Encrypt(rk, plaintext)
}

// DeoxysBC256DecryptHW decrypts using hardware-accelerated Deoxys-BC-256
func DeoxysBC256DecryptHW(rk *DeoxysBC256RoundKeysHW, ciphertext *Block) Block {
	if CPU.HasARMCrypto {
		state := *ciphertext
		deoxysBC256DecryptASM(&state, rk)
		return state
	}
	return DeoxysBC256Decrypt(&rk.DeoxysBC256RoundKeys, ciphertext)
}

// ButterKnifeHW evaluates ButterKnife TPRF with hardware acceleration
func ButterKnifeHW(tweakey *Tweakey256, input *Block) *ButterKnifeOutput {
	if !CPU.HasARMCrypto {
		return ButterKnife(tweakey, input)
	}

	ctx := NewButterKnifeContextHW(tweakey)
	return ctx.EvalHW(input)
}

// ButterKnifeContextHW holds pre-expanded tweakey for hardware-accelerated evaluation
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
		for r := 0; r < 9; r++ { // rounds 7-15 -> indices 0-8
			roundNum := 7 + r
			rconst := DeoxysRoundConstant(domain, roundNum)
			for j := 0; j < 16; j++ {
				ctx.branchSTK[branch][r][j] = rtk.TK1[roundNum][j] ^ rtk.TK2[roundNum][j] ^ rconst[j]
			}
		}
	}

	return ctx
}

// EvalHW evaluates ButterKnife with hardware acceleration
func (ctx *ButterKnifeContextHW) EvalHW(input *Block) *ButterKnifeOutput {
	if !CPU.HasARMCrypto {
		return ctx.evalSoftware(input)
	}

	var output ButterKnifeOutput

	// Pre-fork: 7 rounds with domain 0
	forkState := *input
	for i := 0; i < 7; i++ {
		// KeyFirst: XOR key, then SubBytes, ShiftRows, MixColumns
		xorBlocks(&forkState, &ctx.preForkSTK[i])
		RoundNoKeyHW(&forkState)
	}

	// Process branches 0-3 in parallel
	var branches03 Block4
	copy(branches03[0:16], forkState[:])
	copy(branches03[16:32], forkState[:])
	copy(branches03[32:48], forkState[:])
	copy(branches03[48:64], forkState[:])

	var stk03 [4][9]Block
	stk03[0] = ctx.branchSTK[0]
	stk03[1] = ctx.branchSTK[1]
	stk03[2] = ctx.branchSTK[2]
	stk03[3] = ctx.branchSTK[3]

	butterKnife4BranchesASM(&branches03, &forkState, &stk03)

	copy(output[0][:], branches03[0:16])
	copy(output[1][:], branches03[16:32])
	copy(output[2][:], branches03[32:48])
	copy(output[3][:], branches03[48:64])

	// Process branches 4-7 in parallel
	var branches47 Block4
	copy(branches47[0:16], forkState[:])
	copy(branches47[16:32], forkState[:])
	copy(branches47[32:48], forkState[:])
	copy(branches47[48:64], forkState[:])

	var stk47 [4][9]Block
	stk47[0] = ctx.branchSTK[4]
	stk47[1] = ctx.branchSTK[5]
	stk47[2] = ctx.branchSTK[6]
	stk47[3] = ctx.branchSTK[7]

	butterKnife4BranchesASM(&branches47, &forkState, &stk47)

	copy(output[4][:], branches47[0:16])
	copy(output[5][:], branches47[16:32])
	copy(output[6][:], branches47[32:48])
	copy(output[7][:], branches47[48:64])

	return &output
}

// evalSoftware is a fallback that uses the precomputed keys with software rounds
func (ctx *ButterKnifeContextHW) evalSoftware(input *Block) *ButterKnifeOutput {
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
