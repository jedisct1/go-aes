// Deoxys-BC-256 and ButterKnife assembly optimizations for amd64
// Uses Intel AES-NI instructions for hardware acceleration
#include "textflag.h"

// func deoxysBC256EncryptASM(state *Block, stk *[15]Block)
// Encrypts a block using Deoxys-BC-256 with precomputed subtweakeys.
// Structure: XOR STK[0], then 13 AESENC rounds, then AESENCLAST
TEXT ·deoxysBC256EncryptASM(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX
	MOVQ stk+8(FP), BX

	// Load state into XMM0
	MOVOU (AX), X0

	// Initial whitening: XOR with STK[0]
	MOVOU (BX), X1
	PXOR X1, X0

	// Rounds 1-13: full AES rounds with STK[1-13]
	MOVOU 16(BX), X1
	AESENC X1, X0

	MOVOU 32(BX), X1
	AESENC X1, X0

	MOVOU 48(BX), X1
	AESENC X1, X0

	MOVOU 64(BX), X1
	AESENC X1, X0

	MOVOU 80(BX), X1
	AESENC X1, X0

	MOVOU 96(BX), X1
	AESENC X1, X0

	MOVOU 112(BX), X1
	AESENC X1, X0

	MOVOU 128(BX), X1
	AESENC X1, X0

	MOVOU 144(BX), X1
	AESENC X1, X0

	MOVOU 160(BX), X1
	AESENC X1, X0

	MOVOU 176(BX), X1
	AESENC X1, X0

	MOVOU 192(BX), X1
	AESENC X1, X0

	MOVOU 208(BX), X1
	AESENC X1, X0

	// Final round: SubBytes, ShiftRows, XOR STK[14] (no MixColumns)
	MOVOU 224(BX), X1
	AESENCLAST X1, X0

	// Store result
	MOVOU X0, (AX)
	RET

// func deoxysBC256DecryptASM(state *Block, stk *[15]Block)
// Decrypts a block using Deoxys-BC-256.
// Note: This requires the STK to have InvMixColumns applied to middle keys.
// We use the inverse round keys stored at offset 240 (after the 15 STK blocks).
TEXT ·deoxysBC256DecryptASM(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX
	MOVQ stk+8(FP), BX

	// Load state into XMM0
	MOVOU (AX), X0

	// XOR with STK[14]
	MOVOU 224(BX), X1
	PXOR X1, X0

	// Rounds 13-1: inverse AES rounds with InvMixColumns(STK[13-1])
	// The inverse keys are stored at offset 240+16*i
	MOVOU 448(BX), X1  // InvSTK[13] at 240 + 13*16 = 448
	AESDEC X1, X0

	MOVOU 432(BX), X1  // InvSTK[12]
	AESDEC X1, X0

	MOVOU 416(BX), X1  // InvSTK[11]
	AESDEC X1, X0

	MOVOU 400(BX), X1  // InvSTK[10]
	AESDEC X1, X0

	MOVOU 384(BX), X1  // InvSTK[9]
	AESDEC X1, X0

	MOVOU 368(BX), X1  // InvSTK[8]
	AESDEC X1, X0

	MOVOU 352(BX), X1  // InvSTK[7]
	AESDEC X1, X0

	MOVOU 336(BX), X1  // InvSTK[6]
	AESDEC X1, X0

	MOVOU 320(BX), X1  // InvSTK[5]
	AESDEC X1, X0

	MOVOU 304(BX), X1  // InvSTK[4]
	AESDEC X1, X0

	MOVOU 288(BX), X1  // InvSTK[3]
	AESDEC X1, X0

	MOVOU 272(BX), X1  // InvSTK[2]
	AESDEC X1, X0

	MOVOU 256(BX), X1  // InvSTK[1]
	AESDEC X1, X0

	// Final round: InvSubBytes, InvShiftRows, XOR STK[0]
	MOVOU (BX), X1
	AESDECLAST X1, X0

	// Store result
	MOVOU X0, (AX)
	RET

// func butterKnifePreForkASM(state *Block, stk *[16]Block)
// Performs the 7 pre-fork rounds of ButterKnife.
// Each round: XOR subtweakey, SubBytes, ShiftRows, MixColumns
TEXT ·butterKnifePreForkASM(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX
	MOVQ stk+8(FP), BX

	// Load state
	MOVOU (AX), X0

	// Round 0: XOR STK[0], then SubBytes, ShiftRows, MixColumns
	MOVOU (BX), X1
	PXOR X1, X0
	// Use AESENC with zero key for SubBytes+ShiftRows+MixColumns, then XOR will be done next round
	// Actually, ButterKnife does: AddRoundTweakey first, then SubBytes, ShiftRows, MixColumns
	// So: XOR key, SubBytes, ShiftRows, MixColumns
	// AESENC does: SubBytes, ShiftRows, MixColumns, XOR key
	// These are different! We need to do the XOR first.

	// For ButterKnife round structure (KeyFirst):
	// We can use: PXOR key, then AESENC with zero
	PXOR X1, X1  // Zero X1
	AESENC X1, X0

	// Round 1
	MOVOU 16(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 2
	MOVOU 32(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 3
	MOVOU 48(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 4
	MOVOU 64(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 5
	MOVOU 80(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 6
	MOVOU 96(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Store result
	MOVOU X0, (AX)
	RET

// func butterKnifeBranchASM(state *Block, forkState *Block, stk *[9]Block)
// Performs one branch of ButterKnife: 8 rounds + final AddRoundTweakey + feed-forward.
// stk contains subtweakeys for rounds 7-14 (indices 0-7) and round 15 (index 8).
TEXT ·butterKnifeBranchASM(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX
	MOVQ forkState+8(FP), CX
	MOVQ stk+16(FP), BX

	// Load state and fork state
	MOVOU (AX), X0
	MOVOU (CX), X2  // Keep fork state for feed-forward

	// Rounds 7-14 (8 rounds): XOR key, SubBytes, ShiftRows, MixColumns
	// Round 7 (index 0)
	MOVOU (BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 8 (index 1)
	MOVOU 16(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 9 (index 2)
	MOVOU 32(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 10 (index 3)
	MOVOU 48(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 11 (index 4)
	MOVOU 64(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 12 (index 5)
	MOVOU 80(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 13 (index 6)
	MOVOU 96(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Round 14 (index 7)
	MOVOU 112(BX), X1
	PXOR X1, X0
	PXOR X1, X1
	AESENC X1, X0

	// Final AddRoundTweakey (round 15, index 8)
	MOVOU 128(BX), X1
	PXOR X1, X0

	// Feed-forward: XOR with fork state
	PXOR X2, X0

	// Store result
	MOVOU X0, (AX)
	RET

// func butterKnife4BranchesASM(branches *Block4, forkState *Block, stk *[4][9]Block)
// Processes 4 ButterKnife branches in parallel using AVX registers.
// branches: 4 x 16-byte blocks to process
// forkState: the fork state to XOR at the end
// stk: 4 sets of 9 subtweakeys (rounds 7-15 for each branch)
TEXT ·butterKnife4BranchesASM(SB),NOSPLIT,$0
	MOVQ branches+0(FP), AX
	MOVQ forkState+8(FP), CX
	MOVQ stk+16(FP), BX

	// Load 4 branch states
	MOVOU (AX), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVOU 48(AX), X3

	// Load fork state (same for all branches)
	MOVOU (CX), X8

	// Round 7 (index 0 in each branch's STK)
	// Branch 0: offset 0, Branch 1: offset 144, Branch 2: offset 288, Branch 3: offset 432
	MOVOU (BX), X4
	PXOR X4, X0
	MOVOU 144(BX), X4
	PXOR X4, X1
	MOVOU 288(BX), X4
	PXOR X4, X2
	MOVOU 432(BX), X4
	PXOR X4, X3
	PXOR X4, X4  // Zero
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 8 (index 1)
	MOVOU 16(BX), X4
	PXOR X4, X0
	MOVOU 160(BX), X4
	PXOR X4, X1
	MOVOU 304(BX), X4
	PXOR X4, X2
	MOVOU 448(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 9 (index 2)
	MOVOU 32(BX), X4
	PXOR X4, X0
	MOVOU 176(BX), X4
	PXOR X4, X1
	MOVOU 320(BX), X4
	PXOR X4, X2
	MOVOU 464(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 10 (index 3)
	MOVOU 48(BX), X4
	PXOR X4, X0
	MOVOU 192(BX), X4
	PXOR X4, X1
	MOVOU 336(BX), X4
	PXOR X4, X2
	MOVOU 480(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 11 (index 4)
	MOVOU 64(BX), X4
	PXOR X4, X0
	MOVOU 208(BX), X4
	PXOR X4, X1
	MOVOU 352(BX), X4
	PXOR X4, X2
	MOVOU 496(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 12 (index 5)
	MOVOU 80(BX), X4
	PXOR X4, X0
	MOVOU 224(BX), X4
	PXOR X4, X1
	MOVOU 368(BX), X4
	PXOR X4, X2
	MOVOU 512(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 13 (index 6)
	MOVOU 96(BX), X4
	PXOR X4, X0
	MOVOU 240(BX), X4
	PXOR X4, X1
	MOVOU 384(BX), X4
	PXOR X4, X2
	MOVOU 528(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Round 14 (index 7)
	MOVOU 112(BX), X4
	PXOR X4, X0
	MOVOU 256(BX), X4
	PXOR X4, X1
	MOVOU 400(BX), X4
	PXOR X4, X2
	MOVOU 544(BX), X4
	PXOR X4, X3
	PXOR X4, X4
	AESENC X4, X0
	AESENC X4, X1
	AESENC X4, X2
	AESENC X4, X3

	// Final AddRoundTweakey (round 15, index 8) and feed-forward
	MOVOU 128(BX), X4
	PXOR X4, X0
	PXOR X8, X0
	MOVOU 272(BX), X4
	PXOR X4, X1
	PXOR X8, X1
	MOVOU 416(BX), X4
	PXOR X4, X2
	PXOR X8, X2
	MOVOU 560(BX), X4
	PXOR X4, X3
	PXOR X8, X3

	// Store results
	MOVOU X0, (AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	RET
