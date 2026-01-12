package aes

// ButterKnife is a Tweakable Pseudorandom Function (TPRF) that expands
// a 128-bit input to 1024-bit output (8 branches × 128 bits) using a 256-bit tweakey.
// It uses 7 rounds before the fork point and 8 rounds in each of the 8 parallel branches.
//
// Based on the paper "Masked Iterate-Fork-Iterate: A new Design Paradigm for
// Tweakable Expanding Pseudorandom Function" (https://eprint.iacr.org/2021/1534)

// ButterKnifeOutput holds the 8 output branches (1024 bits total)
type ButterKnifeOutput [8]Block

// ButterKnife computes the ButterKnife TPRF on input using the given tweakey.
// Input: 128-bit block
// Output: 1024 bits (8 × 128-bit blocks)
func ButterKnife(tweakey *Tweakey256, input *Block) *ButterKnifeOutput {
	var output ButterKnifeOutput

	// Expand tweakey
	rtk := DeoxysExpandTweakey256(tweakey)

	// Initialize state with input
	forkState := *input

	// P^0: 7 rounds before branching (domain = 0)
	for i := 0; i < 7; i++ {
		DeoxysRound(&forkState, rtk, i, 0)
	}

	// Fork into 8 branches
	// Each branch: P^j for j=1..8, with 8 rounds each
	for j := 0; j < 8; j++ {
		branchState := forkState
		domain := byte(j + 1)

		// 8 rounds in this branch (rounds 7-14 in the tweakey schedule)
		for i := 0; i < 8; i++ {
			DeoxysRound(&branchState, rtk, 7+i, domain)
		}

		// Final tweakey addition (round 15)
		DeoxysAddRoundTweakey(&branchState, rtk, 15, domain)

		// Feed-forward: Y_j = branchState ⊕ forkState
		for k := 0; k < 16; k++ {
			output[j][k] = branchState[k] ^ forkState[k]
		}
	}

	return &output
}

// ButterKnifeContext holds pre-expanded tweakey for multiple ButterKnife evaluations
type ButterKnifeContext struct {
	rtk *DeoxysRoundTweakeys
}

// NewButterKnifeContext creates a context with pre-expanded tweakey
func NewButterKnifeContext(tweakey *Tweakey256) *ButterKnifeContext {
	return &ButterKnifeContext{
		rtk: DeoxysExpandTweakey256(tweakey),
	}
}

// Eval evaluates ButterKnife with the pre-expanded tweakey
func (ctx *ButterKnifeContext) Eval(input *Block) *ButterKnifeOutput {
	var output ButterKnifeOutput

	// Initialize state with input
	forkState := *input

	// P^0: 7 rounds before branching
	for i := 0; i < 7; i++ {
		DeoxysRound(&forkState, ctx.rtk, i, 0)
	}

	// Fork into 8 branches
	for j := 0; j < 8; j++ {
		branchState := forkState
		domain := byte(j + 1)

		// 8 rounds in this branch
		for i := 0; i < 8; i++ {
			DeoxysRound(&branchState, ctx.rtk, 7+i, domain)
		}

		// Final tweakey addition
		DeoxysAddRoundTweakey(&branchState, ctx.rtk, 15, domain)

		// Feed-forward
		for k := 0; k < 16; k++ {
			output[j][k] = branchState[k] ^ forkState[k]
		}
	}

	return &output
}
