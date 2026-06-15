//go:build amd64 && !purego

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
	if CPU.HasAESNI {
		state := *plaintext
		deoxysBC256EncryptASM(&state, &rk.STK)
		return state
	}
	return DeoxysBC256Encrypt(rk, plaintext)
}

// DeoxysBC256DecryptHW decrypts using hardware-accelerated Deoxys-BC-256
func DeoxysBC256DecryptHW(rk *DeoxysBC256RoundKeysHW, ciphertext *Block) Block {
	if CPU.HasAESNI {
		state := *ciphertext
		deoxysBC256DecryptASM(&state, rk)
		return state
	}
	// Fall back to software using the base keys
	return DeoxysBC256Decrypt(&rk.DeoxysBC256RoundKeys, ciphertext)
}

// ButterKnifeHW evaluates ButterKnife TPRF with hardware acceleration
func ButterKnifeHW(tweakey *Tweakey256, input *Block) *ButterKnifeOutput {
	if !CPU.HasAESNI {
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

// EvalHWInto evaluates ButterKnife with hardware acceleration, writing the 8
// output branches into out without allocating.
func (ctx *ButterKnifeContextHW) EvalHWInto(input *Block, out *ButterKnifeOutput) {
	if !CPU.HasAESNI {
		ctx.evalSoftwareInto(input, out)
		return
	}

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

	copy(out[0][:], branches03[0:16])
	copy(out[1][:], branches03[16:32])
	copy(out[2][:], branches03[32:48])
	copy(out[3][:], branches03[48:64])

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

	copy(out[4][:], branches47[0:16])
	copy(out[5][:], branches47[16:32])
	copy(out[6][:], branches47[32:48])
	copy(out[7][:], branches47[48:64])
}

// evalSoftwareInto is a fallback that uses the precomputed keys with software rounds
func (ctx *ButterKnifeContextHW) evalSoftwareInto(input *Block, out *ButterKnifeOutput) {
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
