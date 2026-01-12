// VAES hardware acceleration for AMD64 (Intel/AMD x86-64 with AVX2/AVX512)
// Requires VAES + AVX2 for 2-block operations
// Requires VAES + AVX512 for 4-block operations
#include "textflag.h"

// func vaesRound2(blocks *Block2, roundKeys *Key2)
TEXT ·vaesRound2(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 2 blocks into YMM0 (256-bit)
	VMOVDQU (AX), Y0

	// Load 2 round keys into YMM1 (each block gets its own key)
	VMOVDQU (BX), Y1

	// Perform VAES round (VAESENC = ShiftRows + SubBytes + MixColumns + XOR with key)
	// This operates on both 128-bit lanes in parallel, each with its own key
	VAESENC Y1, Y0, Y0

	// Store result back to blocks
	VMOVDQU Y0, (AX)
	VZEROUPPER
	RET

// func vaesFinalRound2(blocks *Block2, roundKeys *Key2)
TEXT ·vaesFinalRound2(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 2 blocks into YMM0
	VMOVDQU (AX), Y0

	// Load 2 round keys into YMM1
	VMOVDQU (BX), Y1

	// Perform final VAES round (VAESENCLAST = ShiftRows + SubBytes + XOR with key)
	VAESENCLAST Y1, Y0, Y0

	// Store result back to blocks
	VMOVDQU Y0, (AX)
	VZEROUPPER
	RET

// func vaesInvRound2(blocks *Block2, roundKeys *Key2)
TEXT ·vaesInvRound2(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 2 blocks into YMM0
	VMOVDQU (AX), Y0

	// Load 2 round keys into YMM1
	VMOVDQU (BX), Y1

	// Perform inverse VAES round
	VAESDEC Y1, Y0, Y0

	// Store result back to blocks
	VMOVDQU Y0, (AX)
	VZEROUPPER
	RET

// func vaesInvFinalRound2(blocks *Block2, roundKeys *Key2)
TEXT ·vaesInvFinalRound2(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 2 blocks into YMM0
	VMOVDQU (AX), Y0

	// Load 2 round keys into YMM1
	VMOVDQU (BX), Y1

	// Perform final inverse VAES round
	VAESDECLAST Y1, Y0, Y0

	// Store result back to blocks
	VMOVDQU Y0, (AX)
	VZEROUPPER
	RET

// func vaesRound4(blocks *Block4, roundKeys *Key4)
TEXT ·vaesRound4(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 4 blocks into ZMM0 (512-bit)
	VMOVDQU64 (AX), Z0

	// Load 4 round keys into ZMM1 (each block gets its own key)
	VMOVDQU64 (BX), Z1

	// Perform VAES round on all 4 blocks in parallel, each with its own key
	VAESENC Z1, Z0, Z0

	// Store result back to blocks
	VMOVDQU64 Z0, (AX)
	VZEROUPPER
	RET

// func vaesFinalRound4(blocks *Block4, roundKeys *Key4)
TEXT ·vaesFinalRound4(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 4 blocks into ZMM0
	VMOVDQU64 (AX), Z0

	// Load 4 round keys into ZMM1
	VMOVDQU64 (BX), Z1

	// Perform final VAES round
	VAESENCLAST Z1, Z0, Z0

	// Store result back to blocks
	VMOVDQU64 Z0, (AX)
	VZEROUPPER
	RET

// func vaesInvRound4(blocks *Block4, roundKeys *Key4)
TEXT ·vaesInvRound4(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 4 blocks into ZMM0
	VMOVDQU64 (AX), Z0

	// Load 4 round keys into ZMM1
	VMOVDQU64 (BX), Z1

	// Perform inverse VAES round
	VAESDEC Z1, Z0, Z0

	// Store result back to blocks
	VMOVDQU64 Z0, (AX)
	VZEROUPPER
	RET

// func vaesInvFinalRound4(blocks *Block4, roundKeys *Key4)
TEXT ·vaesInvFinalRound4(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX
	MOVQ roundKeys+8(FP), BX

	// Load 4 blocks into ZMM0
	VMOVDQU64 (AX), Z0

	// Load 4 round keys into ZMM1
	VMOVDQU64 (BX), Z1

	// Perform final inverse VAES round
	VAESDECLAST Z1, Z0, Z0

	// Store result back to blocks
	VMOVDQU64 Z0, (AX)
	VZEROUPPER
	RET

// func vaesInvMixColumns2(blocks *Block2)
TEXT ·vaesInvMixColumns2(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX

	// Load 2 blocks - AESIMC only works on 128-bit XMM registers
	// so we process each lane separately
	VMOVDQU (AX), X0         // Load first block
	VMOVDQU 16(AX), X1       // Load second block

	// Perform InvMixColumns on each block
	AESIMC X0, X0
	AESIMC X1, X1

	// Store results back
	VMOVDQU X0, (AX)
	VMOVDQU X1, 16(AX)
	RET

// func vaesInvMixColumns4(blocks *Block4)
TEXT ·vaesInvMixColumns4(SB),NOSPLIT,$0
	MOVQ blocks+0(FP), AX

	// Load 4 blocks - AESIMC only works on 128-bit XMM registers
	// so we process each lane separately
	VMOVDQU (AX), X0         // Load first block
	VMOVDQU 16(AX), X1       // Load second block
	VMOVDQU 32(AX), X2       // Load third block
	VMOVDQU 48(AX), X3       // Load fourth block

	// Perform InvMixColumns on each block
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3

	// Store results back
	VMOVDQU X0, (AX)
	VMOVDQU X1, 16(AX)
	VMOVDQU X2, 32(AX)
	VMOVDQU X3, 48(AX)
	RET
