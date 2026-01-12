// ARM Crypto extensions hardware acceleration for ARM64
#include "textflag.h"

// ARM AESE does: XOR key first, THEN ShiftRows + SubBytes
// Intel AESENC does: ShiftRows + SubBytes + MixColumns, THEN XOR key
// To match standard AES round (and Intel semantics), we need to compensate

// func armRound(block *Block, roundKey *Block)
TEXT ·armRound(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// Create a zero vector in V2 for AESE
	VEOR V2.B16, V2.B16, V2.B16

	// AESE with zero key: just ShiftRows + SubBytes (no XOR)
	AESE V2.B16, V0.B16
	// AESMC: MixColumns
	AESMC V0.B16, V0.B16
	// Now XOR the round key at the end (AddRoundKey)
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armFinalRound(block *Block, roundKey *Block)
TEXT ·armFinalRound(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESE with zero key: ShiftRows + SubBytes (no MixColumns, no XOR)
	AESE V2.B16, V0.B16
	// Now XOR the round key at the end
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvRound(block *Block, roundKey *Block)
TEXT ·armInvRound(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: just InvShiftRows + InvSubBytes (no XOR)
	AESD V2.B16, V0.B16
	// AESIMC: InvMixColumns
	AESIMC V0.B16, V0.B16
	// Now XOR the round key at the end
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvFinalRound(block *Block, roundKey *Block)
TEXT ·armInvFinalRound(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: InvShiftRows + InvSubBytes (no XOR)
	AESD V2.B16, V0.B16
	// Now XOR the round key at the end
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvMixColumns(block *Block)
TEXT ·armInvMixColumns(SB),NOSPLIT,$0
	MOVD block+0(FP), R0

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Perform InvMixColumns transformation
	AESIMC V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// KeyFirst variants: these use ARM Crypto instructions naturally (key XOR first)
// without the zero-key workaround. This matches ARM instruction semantics directly.

// func armRoundKeyFirst(block *Block, roundKey *Block)
TEXT ·armRoundKeyFirst(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// AESE: XOR key, then ShiftRows + SubBytes
	AESE V1.B16, V0.B16
	// AESMC: MixColumns
	AESMC V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armFinalRoundKeyFirst(block *Block, roundKey *Block)
TEXT ·armFinalRoundKeyFirst(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// AESE: XOR key, then ShiftRows + SubBytes (no MixColumns for final round)
	AESE V1.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvRoundKeyFirst(block *Block, roundKey *Block)
// Inverse of RoundKeyFirst: InvMixColumns, InvShiftRows, InvSubBytes, AddRoundKey
TEXT ·armInvRoundKeyFirst(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// InvMixColumns first
	AESIMC V0.B16, V0.B16

	// Create zero vector for AESD without key XOR
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: just InvShiftRows + InvSubBytes (no XOR)
	AESD V2.B16, V0.B16

	// Finally XOR the round key
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvFinalRoundKeyFirst(block *Block, roundKey *Block)
// Inverse of FinalRoundKeyFirst: InvShiftRows, InvSubBytes, AddRoundKey
TEXT ·armInvFinalRoundKeyFirst(SB),NOSPLIT,$0
	MOVD block+0(FP), R0
	MOVD roundKey+8(FP), R1

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Load the round key into V1
	VLD1 (R1), [V1.B16]

	// Create zero vector for AESD without key XOR
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: InvShiftRows + InvSubBytes (no XOR, no InvMixColumns for final)
	AESD V2.B16, V0.B16

	// Finally XOR the round key
	VEOR V1.B16, V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// NoKey variants: these perform round operations without AddRoundKey
// Useful for custom cryptographic constructions

// func armRoundNoKey(block *Block)
TEXT ·armRoundNoKey(SB),NOSPLIT,$0
	MOVD block+0(FP), R0

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESE with zero key: just ShiftRows + SubBytes (no XOR)
	AESE V2.B16, V0.B16
	// AESMC: MixColumns
	AESMC V0.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armFinalRoundNoKey(block *Block)
TEXT ·armFinalRoundNoKey(SB),NOSPLIT,$0
	MOVD block+0(FP), R0

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESE with zero key: ShiftRows + SubBytes (no XOR, no MixColumns)
	AESE V2.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvRoundNoKey(block *Block)
// Inverse of RoundNoKey: InvMixColumns, InvShiftRows, InvSubBytes
TEXT ·armInvRoundNoKey(SB),NOSPLIT,$0
	MOVD block+0(FP), R0

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// InvMixColumns first
	AESIMC V0.B16, V0.B16

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: InvShiftRows + InvSubBytes (no XOR)
	AESD V2.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET

// func armInvFinalRoundNoKey(block *Block)
TEXT ·armInvFinalRoundNoKey(SB),NOSPLIT,$0
	MOVD block+0(FP), R0

	// Load the block into V0
	VLD1 (R0), [V0.B16]

	// Create a zero vector in V2
	VEOR V2.B16, V2.B16, V2.B16

	// AESD with zero key: InvShiftRows + InvSubBytes (no XOR, no InvMixColumns)
	AESD V2.B16, V0.B16

	// Store result back to block
	VST1 [V0.B16], (R0)
	RET
