// ARM Crypto Extensions parallel operations for ARM64
// Process multiple AES blocks to reduce Go/Assembly boundary crossings

#include "textflag.h"

// func armRound2(blocks *Block2, roundKeys *Key2)
TEXT ·armRound2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks into V0, V1
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys into V4, V5
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Create zero vector for AESE
	VEOR V2.B16, V2.B16, V2.B16

	// Process block 0: AESE with zero, AESMC, XOR key 0
	AESE V2.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	// Process block 1: AESE with zero, AESMC, XOR key 1
	AESE V2.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	// Store results back
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armFinalRound2(blocks *Block2, roundKeys *Key2)
TEXT ·armFinalRound2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Create zero vector
	VEOR V2.B16, V2.B16, V2.B16

	// Process block 0: AESE with zero (no AESMC for final round), XOR key 0
	AESE V2.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	// Process block 1: XOR key 1
	AESE V2.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	// Store results
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armInvRound2(blocks *Block2, roundKeys *Key2)
TEXT ·armInvRound2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Create zero vector
	VEOR V2.B16, V2.B16, V2.B16

	// Process block 0: AESD with zero, AESIMC, XOR key 0
	AESD V2.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	// Process block 1: XOR key 1
	AESD V2.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	// Store results
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armInvFinalRound2(blocks *Block2, roundKeys *Key2)
TEXT ·armInvFinalRound2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Create zero vector
	VEOR V2.B16, V2.B16, V2.B16

	// Process block 0: AESD with zero (no AESIMC for final round), XOR key 0
	AESD V2.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	// Process block 1: XOR key 1
	AESD V2.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	// Store results
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armRound4(blocks *Block4, roundKeys *Key4)
TEXT ·armRound4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks into V0-V3
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys into V4-V7
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Create zero vector
	VEOR V16.B16, V16.B16, V16.B16

	// Process all 4 blocks with individual keys
	AESE V16.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	AESE V16.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	AESE V16.B16, V2.B16
	AESMC V2.B16, V2.B16
	VEOR V6.B16, V2.B16, V2.B16

	AESE V16.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V7.B16, V3.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// func armFinalRound4(blocks *Block4, roundKeys *Key4)
TEXT ·armFinalRound4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Create zero vector
	VEOR V16.B16, V16.B16, V16.B16

	// Process all 4 blocks (no AESMC for final round)
	AESE V16.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	AESE V16.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	AESE V16.B16, V2.B16
	VEOR V6.B16, V2.B16, V2.B16

	AESE V16.B16, V3.B16
	VEOR V7.B16, V3.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// func armInvRound4(blocks *Block4, roundKeys *Key4)
TEXT ·armInvRound4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Create zero vector
	VEOR V16.B16, V16.B16, V16.B16

	// Process all 4 blocks
	AESD V16.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	AESD V16.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	AESD V16.B16, V2.B16
	AESIMC V2.B16, V2.B16
	VEOR V6.B16, V2.B16, V2.B16

	AESD V16.B16, V3.B16
	AESIMC V3.B16, V3.B16
	VEOR V7.B16, V3.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// func armInvFinalRound4(blocks *Block4, roundKeys *Key4)
TEXT ·armInvFinalRound4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Create zero vector
	VEOR V16.B16, V16.B16, V16.B16

	// Process all 4 blocks (no AESIMC for final round)
	AESD V16.B16, V0.B16
	VEOR V4.B16, V0.B16, V0.B16

	AESD V16.B16, V1.B16
	VEOR V5.B16, V1.B16, V1.B16

	AESD V16.B16, V2.B16
	VEOR V6.B16, V2.B16, V2.B16

	AESD V16.B16, V3.B16
	VEOR V7.B16, V3.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// KeyFirst variants - can use AESE/AESD directly (more efficient on ARM)

// func armRoundKeyFirst2(blocks *Block2, roundKeys *Key2)
TEXT ·armRoundKeyFirst2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Process directly with AESE (key XOR is built-in)
	AESE V4.B16, V0.B16
	AESMC V0.B16, V0.B16

	AESE V5.B16, V1.B16
	AESMC V1.B16, V1.B16

	// Store results
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armFinalRoundKeyFirst2(blocks *Block2, roundKeys *Key2)
TEXT ·armFinalRoundKeyFirst2(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 2 blocks
	VLD1 (R0), [V0.B16]
	ADD $16, R0
	VLD1 (R0), [V1.B16]
	SUB $16, R0

	// Load 2 round keys
	VLD1 (R1), [V4.B16]
	ADD $16, R1
	VLD1 (R1), [V5.B16]

	// Process directly with AESE (no AESMC for final round)
	AESE V4.B16, V0.B16
	AESE V5.B16, V1.B16

	// Store results
	VST1 [V0.B16], (R0)
	ADD $16, R0
	VST1 [V1.B16], (R0)
	RET

// func armRoundKeyFirst4(blocks *Block4, roundKeys *Key4)
TEXT ·armRoundKeyFirst4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Process all 4 blocks directly with AESE
	AESE V4.B16, V0.B16
	AESMC V0.B16, V0.B16

	AESE V5.B16, V1.B16
	AESMC V1.B16, V1.B16

	AESE V6.B16, V2.B16
	AESMC V2.B16, V2.B16

	AESE V7.B16, V3.B16
	AESMC V3.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// func armFinalRoundKeyFirst4(blocks *Block4, roundKeys *Key4)
TEXT ·armFinalRoundKeyFirst4(SB),NOSPLIT,$0
	MOVD blocks+0(FP), R0
	MOVD roundKeys+8(FP), R1

	// Load 4 blocks
	VLD1.P 16(R0), [V0.B16]
	VLD1.P 16(R0), [V1.B16]
	VLD1.P 16(R0), [V2.B16]
	VLD1 (R0), [V3.B16]
	SUB $48, R0

	// Load 4 round keys
	VLD1.P 16(R1), [V4.B16]
	VLD1.P 16(R1), [V5.B16]
	VLD1.P 16(R1), [V6.B16]
	VLD1 (R1), [V7.B16]

	// Process all 4 blocks directly with AESE (no AESMC)
	AESE V4.B16, V0.B16
	AESE V5.B16, V1.B16
	AESE V6.B16, V2.B16
	AESE V7.B16, V3.B16

	// Store results
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET
