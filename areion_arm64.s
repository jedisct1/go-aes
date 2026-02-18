//go:build !purego

#include "textflag.h"

// Areion256 permutation using ARM Crypto extensions
// func areion256PermuteAsm(state *Areion256)
//
// ARM AESE does: XOR key → ShiftRows → SubBytes (key XOR FIRST)
// For RoundNoKey, we need: ShiftRows → SubBytes → MixColumns (no key XOR)
// Solution: Use AESE with zero, then AESMC, then manually XOR keys with VEOR
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
	// Software: temp=x0; RoundNoKey(temp); temp^=rc; RoundNoKey(temp); temp^=x1; FinalRoundNoKey(x0); x1=temp
	VMOV V0.B16, V3.B16           // temp = x0
	AESE V15.B16, V3.B16          // temp = SB(SR(temp))
	AESMC V3.B16, V3.B16          // temp = MC(temp) = RoundNoKey
	VEOR V3.B16, V2.B16, V3.B16   // temp ^= rc
	AESE V15.B16, V3.B16          // temp = SB(SR(temp))
	AESMC V3.B16, V3.B16          // temp = MC(temp) = RoundNoKey
	VEOR V3.B16, V1.B16, V3.B16   // temp ^= x1
	AESE V15.B16, V0.B16          // x0 = SB(SR(x0)) = FinalRoundNoKey
	VMOV V3.B16, V1.B16           // x1 = temp
	B areion256_next_round

areion256_odd_round:
	// Software: temp=x1; RoundNoKey(temp); temp^=rc; RoundNoKey(temp); temp^=x0; FinalRoundNoKey(x1); x0=temp
	VMOV V1.B16, V3.B16           // temp = x1
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V3.B16, V2.B16, V3.B16   // temp ^= rc
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V3.B16, V0.B16, V3.B16   // temp ^= x0
	AESE V15.B16, V1.B16          // x1 = FinalRoundNoKey(x1)
	VMOV V3.B16, V0.B16           // x0 = temp

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
	// First inverse round: rc[9-i]
	// Software: InvFinalRoundNoKey(x1); temp=x1; RoundNoKey(temp); temp^=rc; RoundNoKey(temp); x0^=temp
	MOVD $9, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V2.B16]  // V2 = rc[9-i]

	AESD V15.B16, V1.B16          // x1 = InvFinalRoundNoKey(x1)
	VMOV V1.B16, V3.B16           // temp = x1
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V3.B16, V2.B16, V3.B16   // temp ^= rc
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V0.B16, V3.B16, V0.B16   // x0 ^= temp

	// Second inverse round: rc[8-i]
	// Software: InvFinalRoundNoKey(x0); temp=x0; RoundNoKey(temp); temp^=rc; RoundNoKey(temp); x1^=temp
	MOVD $8, R4
	SUB R3, R4, R4
	LSL $4, R4, R4
	ADD R2, R4, R5
	VLD1 (R5), [V2.B16]  // V2 = rc[8-i]

	AESD V15.B16, V0.B16          // x0 = InvFinalRoundNoKey(x0)
	VMOV V0.B16, V3.B16
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V3.B16, V2.B16, V3.B16
	AESE V15.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V1.B16, V3.B16, V1.B16   // x1 ^= temp

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
	// Rotate: V0,V1,V2,V3 -> V1,V2,V3,V0
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
	// Final rotation to complete 15
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16
	// After 15 left-rotations: V0=s3, V1=s0, V2=s1, V3=s2
	// Software outputs: x3, x0, x1, x2 (after final rotation)
	// Our state matches, store directly

	// Store result
	MOVD state+0(FP), R0
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// areion512_round: Execute one Areion512 round
// Input: V0=a, V1=b, V2=c, V3=d, V4=rc, V15=zero
// Output: Modified V0,V1,V2,V3
// Clobbers: V5, V6
//
// Software does:
// temp1 = a; RoundNoKey(temp1); b ^= temp1
// temp2 = c; RoundNoKey(temp2); d ^= temp2
// FinalRoundNoKey(a)
// FinalRoundNoKey(c); c ^= rc; RoundNoKey(c)
TEXT areion512_round<>(SB),NOSPLIT,$0
	// temp1 = V0; RoundNoKey(temp1); V1 ^= temp1
	VMOV V0.B16, V5.B16
	AESE V15.B16, V5.B16
	AESMC V5.B16, V5.B16
	VEOR V1.B16, V5.B16, V1.B16

	// temp2 = V2; RoundNoKey(temp2); V3 ^= temp2
	VMOV V2.B16, V5.B16
	AESE V15.B16, V5.B16
	AESMC V5.B16, V5.B16
	VEOR V3.B16, V5.B16, V3.B16

	// FinalRoundNoKey(V0)
	AESE V15.B16, V0.B16

	// FinalRoundNoKey(V2); V2 ^= rc; RoundNoKey(V2)
	AESE V15.B16, V2.B16
	VEOR V2.B16, V4.B16, V2.B16
	AESE V15.B16, V2.B16
	AESMC V2.B16, V2.B16

	RET

// Areion512 inverse permutation using ARM Crypto extensions
// func areion512InversePermuteAsm(state *Areion512)
//
// Software calls inverse rounds with rotating argument patterns:
// (x2,x3,x0,x1), (x1,x2,x3,x0), (x0,x1,x2,x3), (x3,x0,x1,x2), ...
// After reverse rotation and before first inv round, we need V0=x2, V1=x3, V2=x0, V3=x1
TEXT ·areion512InversePermuteAsm(SB),NOSPLIT,$0
	MOVD state+0(FP), R0

	// Load the four blocks
	VLD1.P 16(R0), [V0.B16]   // x0
	VLD1.P 16(R0), [V1.B16]   // x1
	VLD1.P 16(R0), [V2.B16]   // x2
	VLD1 (R0), [V3.B16]       // x3

	// The combined effect of software's reverse rotation + first inv round arg pattern
	// (x2,x3,x0,x1) gives us (a,b,c,d) = (orig_x3, orig_x0, orig_x1, orig_x2)
	// From input V0=x0,V1=x1,V2=x2,V3=x3, we need V0=x3,V1=x0,V2=x1,V3=x2
	// This is right rotation by 1: V0=V3, V1=V0, V2=V1, V3=V2
	VMOV V3.B16, V14.B16
	VMOV V2.B16, V3.B16
	VMOV V1.B16, V2.B16
	VMOV V0.B16, V1.B16
	VMOV V14.B16, V0.B16
	// After this: V0=orig_x3, V1=orig_x0, V2=orig_x1, V3=orig_x2
	// Total rotations so far: 1

	// Load round constants address
	MOVD $·areionRoundConstants(SB), R2
	VEOR V15.B16, V15.B16, V15.B16  // V15 = zero block

	// Last 3 inverse rounds (14, 13, 12)
	// Software pattern: (2,3,0,1), (1,2,3,0), (0,1,2,3) -> 'a' index -1 each time
	// Use RIGHT rotation to match (-1 mod 4)
	ADD $224, R2, R5  // 14*16
	VLD1 (R5), [V4.B16]
	CALL areion512_inv_round<>(SB)
	// Rotate right: V0,V1,V2,V3 -> V3,V0,V1,V2
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

	// After 1 initial + 15 per-round = 16 right rotations
	// 16 mod 4 = 0, so V0 should be back at x0
	// Test showed off-by-1, need to compensate with 1 left rotation
	// Left rotation: V0,V1,V2,V3 -> V1,V2,V3,V0
	VMOV V0.B16, V14.B16
	VMOV V1.B16, V0.B16
	VMOV V2.B16, V1.B16
	VMOV V3.B16, V2.B16
	VMOV V14.B16, V3.B16

	// Store result
	MOVD state+0(FP), R0
	VST1.P [V0.B16], 16(R0)
	VST1.P [V1.B16], 16(R0)
	VST1.P [V2.B16], 16(R0)
	VST1 [V3.B16], (R0)
	RET

// areion512_inv_round: Execute one Areion512 inverse round
// Input: V0=a, V1=b, V2=c, V3=d, V4=rc, V15=zero
// Output: Modified V0,V1,V2,V3
// Clobbers: V5, V6
//
// Software does:
// InvFinalRoundNoKey(a)
// InvMixColumns(c); InvFinalRoundNoKey(c); c ^= rc; InvFinalRoundNoKey(c)
// temp1 = a; RoundNoKey(temp1); b ^= temp1
// temp2 = c; RoundNoKey(temp2); d ^= temp2
TEXT areion512_inv_round<>(SB),NOSPLIT,$0
	// InvFinalRoundNoKey(V0)
	AESD V15.B16, V0.B16

	// InvMixColumns(V2); InvFinalRoundNoKey(V2); V2 ^= rc; InvFinalRoundNoKey(V2)
	AESIMC V2.B16, V2.B16
	AESD V15.B16, V2.B16
	VEOR V2.B16, V4.B16, V2.B16
	AESD V15.B16, V2.B16

	// temp1 = V0; RoundNoKey(temp1); V1 ^= temp1
	VMOV V0.B16, V5.B16
	AESE V15.B16, V5.B16
	AESMC V5.B16, V5.B16
	VEOR V1.B16, V5.B16, V1.B16

	// temp2 = V2; RoundNoKey(temp2); V3 ^= temp2
	VMOV V2.B16, V5.B16
	AESE V15.B16, V5.B16
	AESMC V5.B16, V5.B16
	VEOR V3.B16, V5.B16, V3.B16

	RET
