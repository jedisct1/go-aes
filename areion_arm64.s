//go:build !purego

#include "textflag.h"

// Areion256 permutation using ARM Crypto extensions
// func areion256PermuteAsm(state *Areion256)
TEXT ·areion256PermuteAsm(SB),NOSPLIT,$0
	MOVD state+0(FP), R0

	// Load the two blocks
	VLD1 (R0), [V0.B16]       // x0
	ADD $16, R0, R1
	VLD1 (R1), [V1.B16]       // x1

	// Load round constants address
	MOVD $·areionRoundConstants(SB), R2
	VEOR V15.B16, V15.B16, V15.B16  // V15 = zero block

	MOVD $10, R3  // round counter

areion256_round_loop:
	// Get round index (10 - R3)
	MOVD $10, R4
	SUB R3, R4, R4

	// Load round constant
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V2.B16]  // V2 = rc

	// Check if round is even or odd
	MOVD $10, R4
	SUB R3, R4, R4
	TSTW $1, R4
	BNE areion256_odd_round

areion256_even_round:
	// new_x1 = x0.encrypt(rc).encrypt(x1)
	VMOV V0.B16, V3.B16
	// V3 = AESENC(V3, rc) = encrypt(V3, rc)
	AESE V2.B16, V3.B16
	AESMC V3.B16, V3.B16
	// V3 = AESENC(V3, x1)
	AESE V1.B16, V3.B16
	AESMC V3.B16, V3.B16

	// new_x0 = x0.encryptLast(zero) = AESENCLAST(x0, 0)
	AESE V15.B16, V0.B16
	// No AESMC for final round

	// Update: x1 = V3
	VMOV V3.B16, V1.B16
	B areion256_next_round

areion256_odd_round:
	// new_x0 = x1.encrypt(rc).encrypt(x0)
	VMOV V1.B16, V3.B16
	// V3 = AESENC(V3, rc)
	AESE V2.B16, V3.B16
	AESMC V3.B16, V3.B16
	// V3 = AESENC(V3, x0)
	AESE V0.B16, V3.B16
	AESMC V3.B16, V3.B16

	// new_x1 = x1.encryptLast(zero)
	AESE V15.B16, V1.B16

	// Update: x0 = V3
	VMOV V3.B16, V0.B16

areion256_next_round:
	SUB $1, R3, R3
	CBNZ R3, areion256_round_loop

	// Store result
	MOVD state+0(FP), R0
	VST1 [V0.B16], (R0)
	ADD $16, R0, R1
	VST1 [V1.B16], (R1)
	RET

// Areion256 inverse permutation using ARM Crypto extensions
// func areion256InversePermuteAsm(state *Areion256)
TEXT ·areion256InversePermuteAsm(SB),NOSPLIT,$0
	MOVD state+0(FP), R0

	// Load the two blocks
	VLD1 (R0), [V0.B16]       // x0
	ADD $16, R0, R1
	VLD1 (R1), [V1.B16]       // x1

	// Load round constants address
	MOVD $·areionRoundConstants(SB), R2
	VEOR V15.B16, V15.B16, V15.B16  // V15 = zero block

	MOVD $0, R3  // i counter (0 to 9, step 2)

areion256_inv_loop:
	// First inverse round (odd round in reverse): rc[9-i]
	MOVD $9, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V2.B16]  // V2 = rc[9-i]

	// x1 = x1.decryptLast(zero) = AESDECLAST(x1, 0)
	AESD V15.B16, V1.B16

	// x0 = x1.encrypt(rc).encrypt(x0)
	VMOV V1.B16, V3.B16
	AESE V2.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V0.B16, V3.B16
	AESMC V3.B16, V3.B16
	VMOV V3.B16, V0.B16

	// Second inverse round (even round in reverse): rc[8-i]
	MOVD $8, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V2.B16]  // V2 = rc[8-i]

	// x0 = x0.decryptLast(zero)
	AESD V15.B16, V0.B16

	// x1 = x0.encrypt(rc).encrypt(x1)
	VMOV V0.B16, V3.B16
	AESE V2.B16, V3.B16
	AESMC V3.B16, V3.B16
	AESE V1.B16, V3.B16
	AESMC V3.B16, V3.B16
	VMOV V3.B16, V1.B16

	ADD $2, R3, R3
	CMP $10, R3
	BLT areion256_inv_loop

	// Store result
	MOVD state+0(FP), R0
	VST1 [V0.B16], (R0)
	ADD $16, R0, R1
	VST1 [V1.B16], (R1)
	RET

// Areion512 permutation using ARM Crypto extensions
// func areion512PermuteAsm(state *Areion512)
TEXT ·areion512PermuteAsm(SB),NOSPLIT,$0
	MOVD state+0(FP), R0

	// Load the four blocks
	VLD1.P 16(R0), [V0.B16]   // x0
	VLD1.P 16(R0), [V1.B16]   // x1
	VLD1.P 16(R0), [V2.B16]   // x2
	VLD1 (R0), [V3.B16]       // x3

	// Load round constants address
	MOVD $·areionRoundConstants(SB), R2
	VEOR V15.B16, V15.B16, V15.B16  // V15 = zero block

	// Main 12 rounds (i=0 to 11, step 4)
	MOVD $0, R3
areion512_main_rounds_loop:
	// Round i+0
	LSL $4, R3, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	// Rotate: x0, x1, x2, x3 -> x1, x2, x3, x0
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Round i+1
	ADD $1, R3, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Round i+2
	ADD $2, R3, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Round i+3
	ADD $3, R3, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	ADD $4, R3, R3
	CMP $12, R3
	BLT areion512_main_rounds_loop

	// Final 3 rounds (12, 13, 14)
	ADD $192, R2, R5  // 12*16
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	ADD $208, R2, R5  // 13*16
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	ADD $224, R2, R5  // 14*16
	VLD1 (R5), [V4.B16]
	CALL areion512_round<>(SB)
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Final rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	VMOV V0.B16, V14.B16
	VMOV V3.B16, V0.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V14.B16, V1.B16

	// Store result
	MOVD state+0(FP), R0
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// areion512_round: Execute one Areion512 round
// Input: V0=x0, V1=x1, V2=x2, V3=x3, V4=rc, V15=zero
// Output: V0=new_x0, V1=new_x1, V2=new_x2, V3=new_x3
// Clobbers: V5, V6
TEXT areion512_round<>(SB),NOSPLIT,$0
	// x1 = x0.encrypt(x1) = AESENC(x0, x1)
	VMOV V0.B16, V5.B16
	AESE V1.B16, V5.B16
	AESMC V5.B16, V5.B16
	VMOV V5.B16, V1.B16

	// x3 = x2.encrypt(x3) = AESENC(x2, x3)
	VMOV V2.B16, V5.B16
	AESE V3.B16, V5.B16
	AESMC V5.B16, V5.B16
	VMOV V5.B16, V3.B16

	// x0 = x0.encryptLast(zero) = AESENCLAST(x0, 0)
	AESE V15.B16, V0.B16

	// x2 = x2.encryptLast(rc).encrypt(zero) = AESENCLAST(x2, rc) then AESENC(result, 0)
	AESE V4.B16, V2.B16
	// No AESMC for encryptLast
	AESE V15.B16, V2.B16
	AESMC V2.B16, V2.B16

	RET

// Areion512 inverse permutation using ARM Crypto extensions
// func areion512InversePermuteAsm(state *Areion512)
TEXT ·areion512InversePermuteAsm(SB),NOSPLIT,$0
	MOVD state+0(FP), R0

	// Load the four blocks
	VLD1.P 16(R0), [V0.B16]   // x0
	VLD1.P 16(R0), [V1.B16]   // x1
	VLD1.P 16(R0), [V2.B16]   // x2
	VLD1 (R0), [V3.B16]       // x3

	// Reverse the final rotation: temp=x0; x0=x1; x1=x2; x2=x3; x3=temp
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Load round constants address
	MOVD $·areionRoundConstants(SB), R2
	VEOR V15.B16, V15.B16, V15.B16  // V15 = zero block

	// Last 3 inverse rounds (14, 13, 12)
	ADD $224, R2, R5  // 14*16
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	// Reverse rotate: x0, x1, x2, x3 -> x3, x0, x1, x2
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	ADD $208, R2, R5  // 13*16
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	ADD $192, R2, R5  // 12*16
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	// Main 12 inverse rounds (i=0 to 11, step 4)
	MOVD $0, R3
areion512_inv_main_loop:
	// Round 11-i
	MOVD $11, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	// Round 10-i
	MOVD $10, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	// Round 9-i
	MOVD $9, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	// Round 8-i
	MOVD $8, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16

	ADD $4, R3, R3
	CMP $12, R3
	BLT areion512_inv_main_loop

	// Store result
	MOVD state+0(FP), R0
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// areion512_inv_round: Execute one Areion512 inverse round
// Input: V0=x0, V1=x1, V2=x2, V3=x3, V4=rc, V15=zero
// Output: V0=new_x0, V1=new_x1, V2=new_x2, V3=new_x3
// Clobbers: V5, V6
TEXT areion512_inv_round<>(SB),NOSPLIT,$0
	// x0 = x0.decryptLast(zero) = AESDECLAST(x0, 0)
	AESD V15.B16, V0.B16

	// x2 = x2.invMixColumns().decryptLast(rc).decryptLast(zero)
	// Apply inverse MixColumns using AESIMC
	AESIMC V2.B16, V2.B16
	// Then AESDECLAST(x2, rc) = InvShiftRows + InvSubBytes + XOR rc
	AESD V4.B16, V2.B16
	// Then AESDECLAST(x2, zero) = InvShiftRows + InvSubBytes + XOR 0
	AESD V15.B16, V2.B16

	// x1 = x0.encrypt(x1)
	VMOV V0.B16, V5.B16
	AESE V1.B16, V5.B16
	AESMC V5.B16, V5.B16
	VMOV V5.B16, V1.B16

	// x3 = x2.encrypt(x3)
	VMOV V2.B16, V5.B16
	AESE V3.B16, V5.B16
	AESMC V5.B16, V5.B16
	VMOV V5.B16, V3.B16

	RET
