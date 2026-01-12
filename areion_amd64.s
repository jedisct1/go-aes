//go:build !purego

#include "textflag.h"

// Areion256 permutation using AES-NI instructions
// func areion256PermuteAsm(state *Areion256)
TEXT ·areion256PermuteAsm(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX

	// Load the two blocks
	MOVOU 0(AX), X0   // x0
	MOVOU 16(AX), X1  // x1

	// Load round constants
	LEAQ ·areionRoundConstants(SB), BX
	PXOR X15, X15  // X15 = zero block

	MOVQ $10, CX  // round counter

round_loop:
	// Get round index (10 - CX)
	MOVQ $10, DX
	SUBQ CX, DX

	// Load round constant
	SHLQ $4, DX  // multiply by 16
	MOVOU (BX)(DX*1), X2  // X2 = rc

	// Check if round is even or odd
	MOVQ $10, DX
	SUBQ CX, DX
	TESTQ $1, DX
	JNZ odd_round

even_round:
	// new_x1 = x0.encrypt(rc).encrypt(x1)
	MOVOA X0, X3
	AESENC X2, X3     // X3 = AESENC(x0, rc)
	AESENC X1, X3     // X3 = AESENC(X3, x1)

	// new_x0 = x0.encryptLast(zero)
	AESENCLAST X15, X0  // x0 = AESENCLAST(x0, 0)

	// Update: x1 = X3
	MOVOA X3, X1
	JMP next_round

odd_round:
	// new_x0 = x1.encrypt(rc).encrypt(x0)
	MOVOA X1, X3
	AESENC X2, X3     // X3 = AESENC(x1, rc)
	AESENC X0, X3     // X3 = AESENC(X3, x0)

	// new_x1 = x1.encryptLast(zero)
	AESENCLAST X15, X1  // x1 = AESENCLAST(x1, 0)

	// Update: x0 = X3
	MOVOA X3, X0

next_round:
	DECQ CX
	JNZ round_loop

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	RET

// Areion256 inverse permutation using AES-NI instructions
// func areion256InversePermuteAsm(state *Areion256)
TEXT ·areion256InversePermuteAsm(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX

	// Load the two blocks
	MOVOU 0(AX), X0   // x0
	MOVOU 16(AX), X1  // x1

	// Load round constants
	LEAQ ·areionRoundConstants(SB), BX
	PXOR X15, X15  // X15 = zero block

	MOVQ $0, CX  // i counter (0 to 9, step 2)

inv_loop:
	// First inverse round (odd round in reverse): rc[9-i]
	MOVQ $9, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X2  // X2 = rc[9-i]

	// x1 = x1.decryptLast(zero)
	AESDECLAST X15, X1

	// x0 = x1.encrypt(rc).encrypt(x0)
	MOVOA X1, X3
	AESENC X2, X3
	AESENC X0, X3
	MOVOA X3, X0

	// Second inverse round (even round in reverse): rc[8-i]
	MOVQ $8, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X2  // X2 = rc[8-i]

	// x0 = x0.decryptLast(zero)
	AESDECLAST X15, X0

	// x1 = x0.encrypt(rc).encrypt(x1)
	MOVOA X0, X3
	AESENC X2, X3
	AESENC X1, X3
	MOVOA X3, X1

	ADDQ $2, CX
	CMPQ CX, $10
	JL inv_loop

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	RET

// Areion512 permutation using AES-NI instructions
// func areion512PermuteAsm(state *Areion512)
TEXT ·areion512PermuteAsm(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX

	// Load the four blocks
	MOVOU 0(AX), X0   // x0
	MOVOU 16(AX), X1  // x1
	MOVOU 32(AX), X2  // x2
	MOVOU 48(AX), X3  // x3

	// Load round constants address
	LEAQ ·areionRoundConstants(SB), BX
	PXOR X15, X15  // X15 = zero block

	// Main 12 rounds (i=0 to 11, step 4)
	MOVQ $0, CX
main_rounds_loop:
	// Round i+0: round(x0, x1, x2, x3, rc[i+0])
	MOVQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_round<>(SB)

	// Rotate: x0, x1, x2, x3 -> x1, x2, x3, x0
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	// Round i+1
	MOVQ CX, DX
	ADDQ $1, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_round<>(SB)

	// Rotate
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	// Round i+2
	MOVQ CX, DX
	ADDQ $2, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_round<>(SB)

	// Rotate
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	// Round i+3
	MOVQ CX, DX
	ADDQ $3, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_round<>(SB)

	// Rotate
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	ADDQ $4, CX
	CMPQ CX, $12
	JL main_rounds_loop

	// Final 3 rounds (12, 13, 14)
	MOVOU 12*16(BX), X4
	CALL areion512_round<>(SB)
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	MOVOU 13*16(BX), X4
	CALL areion512_round<>(SB)
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	MOVOU 14*16(BX), X4
	CALL areion512_round<>(SB)
	// After round 14, rotate one more time to match software's final state
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	// No additional final rotation needed - the 15 per-round rotations
	// already produce the correct final positions [3,0,1,2]

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	RET

// areion512_round: Execute one Areion512 round
// Input: X0=x0, X1=x1, X2=x2, X3=x3, X4=rc, X15=zero
// Output: X0=new_x0, X1=new_x1, X2=new_x2, X3=new_x3
// Clobbers: X5, X6
TEXT areion512_round<>(SB),NOSPLIT,$0
	// x1 = x0.encrypt(x1)
	MOVOA X0, X5
	AESENC X1, X5
	MOVOA X5, X1

	// x3 = x2.encrypt(x3)
	MOVOA X2, X5
	AESENC X3, X5
	MOVOA X5, X3

	// x0 = x0.encryptLast(zero)
	AESENCLAST X15, X0

	// x2 = x2.encryptLast(rc).encrypt(zero)
	AESENCLAST X4, X2
	AESENC X15, X2

	RET

// Areion512 inverse permutation using AES-NI instructions
// func areion512InversePermuteAsm(state *Areion512)
TEXT ·areion512InversePermuteAsm(SB),NOSPLIT,$0
	MOVQ state+0(FP), AX

	// Load the four blocks
	MOVOU 0(AX), X0   // x0
	MOVOU 16(AX), X1  // x1
	MOVOU 32(AX), X2  // x2
	MOVOU 48(AX), X3  // x3

	// Initial rotation: x0,x1,x2,x3 -> x3,x0,x1,x2 (rotate left by 3 = rotate right by 1)
	// This aligns with software's initial rotation + first round's argument order
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	// Load round constants address
	LEAQ ·areionRoundConstants(SB), BX
	PXOR X15, X15  // X15 = zero block

	// Last 3 inverse rounds (14, 13, 12)
	MOVOU 14*16(BX), X4
	CALL areion512_inv_round<>(SB)
	// Reverse rotate: x0, x1, x2, x3 -> x3, x0, x1, x2
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	MOVOU 13*16(BX), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	MOVOU 12*16(BX), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	// Main 12 inverse rounds (i=0 to 11, step 4)
	MOVQ $0, CX
inv_main_loop:
	// Round 11-i
	MOVQ $11, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	// Round 10-i
	MOVQ $10, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	// Round 9-i
	MOVQ $9, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	// Round 8-i
	MOVQ $8, DX
	SUBQ CX, DX
	SHLQ $4, DX
	MOVOU (BX)(DX*1), X4
	CALL areion512_inv_round<>(SB)
	MOVOA X3, X14
	MOVOA X2, X3
	MOVOA X1, X2
	MOVOA X0, X1
	MOVOA X14, X0

	ADDQ $4, CX
	CMPQ CX, $12
	JL inv_main_loop

	// Final correction: rotate left by 1 to match software output
	// (compensates for the extra rotation in the assembly approach)
	MOVOA X0, X14
	MOVOA X1, X0
	MOVOA X2, X1
	MOVOA X3, X2
	MOVOA X14, X3

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	RET

// areion512_inv_round: Execute one Areion512 inverse round
// Input: X0=x0, X1=x1, X2=x2, X3=x3, X4=rc, X15=zero
// Output: X0=new_x0, X1=new_x1, X2=new_x2, X3=new_x3
// Clobbers: X5, X6
TEXT areion512_inv_round<>(SB),NOSPLIT,$0
	// x0 = x0.decryptLast(zero)
	AESDECLAST X15, X0

	// x2 = x2.invMixColumns().decryptLast(rc).decryptLast(zero)
	AESIMC X2, X2
	AESDECLAST X4, X2
	AESDECLAST X15, X2

	// x1 = x0.encrypt(x1)
	MOVOA X0, X5
	AESENC X1, X5
	MOVOA X5, X1

	// x3 = x2.encrypt(x3)
	MOVOA X2, X5
	AESENC X3, X5
	MOVOA X5, X3

	RET
