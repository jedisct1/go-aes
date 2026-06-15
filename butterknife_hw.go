package aes

// NewButterKnifeContextHW creates a context with pre-computed subtweakeys for
// hardware-accelerated ButterKnife evaluation.
func NewButterKnifeContextHW(tweakey *Tweakey256) *ButterKnifeContextHW {
	ctx := &ButterKnifeContextHW{}
	ctx.Reset(tweakey)
	return ctx
}

// Reset re-derives the context's subtweakeys from tweakey in place, without
// allocating. A single context can be reused across many keys, which is what
// makes frequent rekeying (as in fast-key-erasure constructions) cheap: the
// caller pays for one allocation up front and only the key schedule afterwards.
func (ctx *ButterKnifeContextHW) Reset(tweakey *Tweakey256) {
	var rtk DeoxysRoundTweakeys
	deoxysExpandTweakey256Into(tweakey, &rtk)

	// TK1 ^ TK2 is shared by every branch at a given round, so fold it once per
	// round instead of recomputing it eight times in the branch loop below.
	var tkSum [16]Block
	for r := range tkSum {
		tkSum[r] = rtk.TK1[r]
		xorBlocks(&tkSum[r], &rtk.TK2[r])
	}

	for i := 0; i < 7; i++ {
		rc := DeoxysRoundConstant(0, i)
		ctx.preForkSTK[i] = tkSum[i]
		xorBlocks(&ctx.preForkSTK[i], &rc)
	}

	for branch := 0; branch < 8; branch++ {
		domain := byte(branch + 1)
		for r := 0; r < 9; r++ {
			roundNum := 7 + r
			rc := DeoxysRoundConstant(domain, roundNum)
			ctx.branchSTK[branch][r] = tkSum[roundNum]
			xorBlocks(&ctx.branchSTK[branch][r], &rc)
		}
	}
}

// Zero wipes the derived subtweakey material held by the context. The context
// must be re-keyed with Reset before it can be evaluated again. This is the
// secret that lets an attacker recompute every branch, so a forward-secret
// caller should Zero it as soon as a key is retired.
func (ctx *ButterKnifeContextHW) Zero() {
	clear(ctx.preForkSTK[:])
	clear(ctx.branchSTK[:])
}

// EvalHW evaluates ButterKnife and returns a freshly allocated output. Hot
// paths that want to avoid the allocation should use EvalHWInto.
func (ctx *ButterKnifeContextHW) EvalHW(input *Block) *ButterKnifeOutput {
	var output ButterKnifeOutput
	ctx.EvalHWInto(input, &output)
	return &output
}
