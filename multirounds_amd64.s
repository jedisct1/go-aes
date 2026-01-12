// Multi-round AES operations using Intel AES-NI
// Optimized to keep block in register across multiple rounds
#include "textflag.h"

// func aesniRounds4(block *Block, roundKeys *RoundKeys4)
// Performs 4 AES encryption rounds, keeping block in XMM0
TEXT ·aesniRounds4(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load block into XMM0
	MOVOU (AX), X0

	// Round 1
	MOVOU (BX), X1
	AESENC X1, X0

	// Round 2
	MOVOU 16(BX), X1
	AESENC X1, X0

	// Round 3
	MOVOU 32(BX), X1
	AESENC X1, X0

	// Round 4
	MOVOU 48(BX), X1
	AESENC X1, X0

	// Store result
	MOVOU X0, (AX)
	RET

// func aesniInvRounds4(block *Block, roundKeys *RoundKeys4)
TEXT ·aesniInvRounds4(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds6(block *Block, roundKeys *RoundKeys6)
TEXT ·aesniRounds6(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESENC X1, X0

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

	MOVOU X0, (AX)
	RET

// func aesniInvRounds6(block *Block, roundKeys *RoundKeys6)
TEXT ·aesniInvRounds6(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU 64(BX), X1
	AESDEC X1, X0

	MOVOU 80(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds7(block *Block, roundKeys *RoundKeys7)
TEXT ·aesniRounds7(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESENC X1, X0

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

	MOVOU X0, (AX)
	RET

// func aesniInvRounds7(block *Block, roundKeys *RoundKeys7)
TEXT ·aesniInvRounds7(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU 64(BX), X1
	AESDEC X1, X0

	MOVOU 80(BX), X1
	AESDEC X1, X0

	MOVOU 96(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds10(block *Block, roundKeys *RoundKeys10)
TEXT ·aesniRounds10(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESENC X1, X0

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

	MOVOU X0, (AX)
	RET

// func aesniInvRounds10(block *Block, roundKeys *RoundKeys10)
TEXT ·aesniInvRounds10(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU 64(BX), X1
	AESDEC X1, X0

	MOVOU 80(BX), X1
	AESDEC X1, X0

	MOVOU 96(BX), X1
	AESDEC X1, X0

	MOVOU 112(BX), X1
	AESDEC X1, X0

	MOVOU 128(BX), X1
	AESDEC X1, X0

	MOVOU 144(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds12(block *Block, roundKeys *RoundKeys12)
TEXT ·aesniRounds12(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESENC X1, X0

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

	MOVOU X0, (AX)
	RET

// func aesniInvRounds12(block *Block, roundKeys *RoundKeys12)
TEXT ·aesniInvRounds12(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU 64(BX), X1
	AESDEC X1, X0

	MOVOU 80(BX), X1
	AESDEC X1, X0

	MOVOU 96(BX), X1
	AESDEC X1, X0

	MOVOU 112(BX), X1
	AESDEC X1, X0

	MOVOU 128(BX), X1
	AESDEC X1, X0

	MOVOU 144(BX), X1
	AESDEC X1, X0

	MOVOU 160(BX), X1
	AESDEC X1, X0

	MOVOU 176(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds14(block *Block, roundKeys *RoundKeys14)
TEXT ·aesniRounds14(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESENC X1, X0

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

	MOVOU X0, (AX)
	RET

// func aesniInvRounds14(block *Block, roundKeys *RoundKeys14)
TEXT ·aesniInvRounds14(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	MOVOU (BX), X1
	AESDEC X1, X0

	MOVOU 16(BX), X1
	AESDEC X1, X0

	MOVOU 32(BX), X1
	AESDEC X1, X0

	MOVOU 48(BX), X1
	AESDEC X1, X0

	MOVOU 64(BX), X1
	AESDEC X1, X0

	MOVOU 80(BX), X1
	AESDEC X1, X0

	MOVOU 96(BX), X1
	AESDEC X1, X0

	MOVOU 112(BX), X1
	AESDEC X1, X0

	MOVOU 128(BX), X1
	AESDEC X1, X0

	MOVOU 144(BX), X1
	AESDEC X1, X0

	MOVOU 160(BX), X1
	AESDEC X1, X0

	MOVOU 176(BX), X1
	AESDEC X1, X0

	MOVOU 192(BX), X1
	AESDEC X1, X0

	MOVOU 208(BX), X1
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// NoKey variants - perform rounds without key XOR
// These use a zero key with AESENC, but since AESENC XORs the key at the end,
// we need a different approach. We use the fact that SubBytes+ShiftRows+MixColumns
// is the same as AESENC with zero key, then we don't XOR anything.
// Actually, for Intel we'll implement these as loops using the existing single-round.
// The hardware implementation is provided for completeness but falls back to loops.

// For NoKey variants on Intel, we use the zero-register approach similar to ARM
// This works because AESENC does: ShiftRows, SubBytes, MixColumns, XOR key
// With a zero key, the XOR is a no-op

// func aesniRounds4NoKey(block *Block)
TEXT ·aesniRounds4NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1  // Zero key

	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds4NoKey(block *Block)
TEXT ·aesniInvRounds4NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1  // Zero key

	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds7NoKey(block *Block)
TEXT ·aesniRounds7NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds7NoKey(block *Block)
TEXT ·aesniInvRounds7NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds10NoKey(block *Block)
TEXT ·aesniRounds10NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds10NoKey(block *Block)
TEXT ·aesniInvRounds10NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds12NoKey(block *Block)
TEXT ·aesniRounds12NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds12NoKey(block *Block)
TEXT ·aesniInvRounds12NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds14NoKey(block *Block)
TEXT ·aesniRounds14NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0
	AESENC X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds14NoKey(block *Block)
TEXT ·aesniInvRounds14NoKey(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX

	MOVOU (AX), X0
	PXOR X1, X1

	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0
	AESDEC X1, X0

	MOVOU X0, (AX)
	RET

// =============================================================================
// WithFinal functions (N-1 full rounds + 1 final round)
// Standard AES structure for complete encryption
// =============================================================================

// func aesniRounds10WithFinal(block *Block, roundKeys *RoundKeys10)
TEXT ·aesniRounds6WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 5 full rounds (AESENC)
	MOVOU (BX), X1
	AESENC X1, X0
	MOVOU 16(BX), X1
	AESENC X1, X0
	MOVOU 32(BX), X1
	AESENC X1, X0
	MOVOU 48(BX), X1
	AESENC X1, X0
	MOVOU 64(BX), X1
	AESENC X1, X0

	// Final round (AESENCLAST - no MixColumns)
	MOVOU 80(BX), X1
	AESENCLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds10WithFinal(block *Block, roundKeys *RoundKeys10)
TEXT ·aesniRounds10WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 9 full rounds (AESENC)
	MOVOU (BX), X1
	AESENC X1, X0
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

	// Final round (AESENCLAST - no MixColumns)
	MOVOU 144(BX), X1
	AESENCLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds12WithFinal(block *Block, roundKeys *RoundKeys12)
TEXT ·aesniRounds12WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 11 full rounds (AESENC)
	MOVOU (BX), X1
	AESENC X1, X0
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

	// Final round (AESENCLAST - no MixColumns)
	MOVOU 176(BX), X1
	AESENCLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniRounds14WithFinal(block *Block, roundKeys *RoundKeys14)
TEXT ·aesniRounds14WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 13 full rounds (AESENC)
	MOVOU (BX), X1
	AESENC X1, X0
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

	// Final round (AESENCLAST - no MixColumns)
	MOVOU 208(BX), X1
	AESENCLAST X1, X0

	MOVOU X0, (AX)
	RET

// =============================================================================
// InvWithFinal functions (N-1 full decryption rounds + 1 final decryption round)
// Standard AES structure for complete decryption
// =============================================================================

// func aesniInvRounds4WithFinal(block *Block, roundKeys *RoundKeys4)
TEXT ·aesniInvRounds4WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 3 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 48(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds6WithFinal(block *Block, roundKeys *RoundKeys6)
TEXT ·aesniInvRounds6WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 5 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0
	MOVOU 48(BX), X1
	AESDEC X1, X0
	MOVOU 64(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 80(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds7WithFinal(block *Block, roundKeys *RoundKeys7)
TEXT ·aesniInvRounds7WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 6 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0
	MOVOU 48(BX), X1
	AESDEC X1, X0
	MOVOU 64(BX), X1
	AESDEC X1, X0
	MOVOU 80(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 96(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds10WithFinal(block *Block, roundKeys *RoundKeys10)
TEXT ·aesniInvRounds10WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 9 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0
	MOVOU 48(BX), X1
	AESDEC X1, X0
	MOVOU 64(BX), X1
	AESDEC X1, X0
	MOVOU 80(BX), X1
	AESDEC X1, X0
	MOVOU 96(BX), X1
	AESDEC X1, X0
	MOVOU 112(BX), X1
	AESDEC X1, X0
	MOVOU 128(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 144(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds12WithFinal(block *Block, roundKeys *RoundKeys12)
TEXT ·aesniInvRounds12WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 11 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0
	MOVOU 48(BX), X1
	AESDEC X1, X0
	MOVOU 64(BX), X1
	AESDEC X1, X0
	MOVOU 80(BX), X1
	AESDEC X1, X0
	MOVOU 96(BX), X1
	AESDEC X1, X0
	MOVOU 112(BX), X1
	AESDEC X1, X0
	MOVOU 128(BX), X1
	AESDEC X1, X0
	MOVOU 144(BX), X1
	AESDEC X1, X0
	MOVOU 160(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 176(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET

// func aesniInvRounds14WithFinal(block *Block, roundKeys *RoundKeys14)
TEXT ·aesniInvRounds14WithFinal(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	MOVOU (AX), X0

	// 13 full rounds (AESDEC)
	MOVOU (BX), X1
	AESDEC X1, X0
	MOVOU 16(BX), X1
	AESDEC X1, X0
	MOVOU 32(BX), X1
	AESDEC X1, X0
	MOVOU 48(BX), X1
	AESDEC X1, X0
	MOVOU 64(BX), X1
	AESDEC X1, X0
	MOVOU 80(BX), X1
	AESDEC X1, X0
	MOVOU 96(BX), X1
	AESDEC X1, X0
	MOVOU 112(BX), X1
	AESDEC X1, X0
	MOVOU 128(BX), X1
	AESDEC X1, X0
	MOVOU 144(BX), X1
	AESDEC X1, X0
	MOVOU 160(BX), X1
	AESDEC X1, X0
	MOVOU 176(BX), X1
	AESDEC X1, X0
	MOVOU 192(BX), X1
	AESDEC X1, X0

	// Final round (AESDECLAST - no InvMixColumns)
	MOVOU 208(BX), X1
	AESDECLAST X1, X0

	MOVOU X0, (AX)
	RET
