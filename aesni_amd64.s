// AES-NI hardware acceleration for AMD64 (Intel/AMD x86-64)
#include "textflag.h"

// func aesniRound(block *Block, roundKey *Block)
TEXT ·aesniRound(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKey+8(FP), BX

	// Load the block into XMM0
	MOVOU (AX), X0

	// Load the round key into XMM1
	MOVOU (BX), X1

	// Perform AES round (AESENC = ShiftRows + SubBytes + MixColumns + XOR with key)
	AESENC X1, X0

	// Store result back to block
	MOVOU X0, (AX)
	RET

// func aesniFinalRound(block *Block, roundKey *Block)
TEXT ·aesniFinalRound(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKey+8(FP), BX

	// Load the block into XMM0
	MOVOU (AX), X0

	// Load the round key into XMM1
	MOVOU (BX), X1

	// Perform final AES round (AESENCLAST = ShiftRows + SubBytes + XOR with key, no MixColumns)
	AESENCLAST X1, X0

	// Store result back to block
	MOVOU X0, (AX)
	RET

// func aesniInvRound(block *Block, roundKey *Block)
TEXT ·aesniInvRound(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKey+8(FP), BX

	// Load the block into XMM0
	MOVOU (AX), X0

	// Load the round key into XMM1
	MOVOU (BX), X1

	// Perform inverse AES round (AESDEC = InvShiftRows + InvSubBytes + InvMixColumns + XOR with key)
	AESDEC X1, X0

	// Store result back to block
	MOVOU X0, (AX)
	RET

// func aesniInvFinalRound(block *Block, roundKey *Block)
TEXT ·aesniInvFinalRound(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKey+8(FP), BX

	// Load the block into XMM0
	MOVOU (AX), X0

	// Load the round key into XMM1
	MOVOU (BX), X1

	// Perform final inverse AES round (AESDECLAST = InvShiftRows + InvSubBytes + XOR with key, no InvMixColumns)
	AESDECLAST X1, X0

	// Store result back to block
	MOVOU X0, (AX)
	RET

// func aesniInvMixColumns(block *Block)
TEXT ·aesniInvMixColumns(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	// Load the block into XMM0
	MOVOU (AX), X0

	// Perform InvMixColumns transformation
	AESIMC X0, X0

	// Store result back to block
	MOVOU X0, (AX)
	RET
