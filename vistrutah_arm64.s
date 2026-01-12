// Vistrutah hardware acceleration for ARM64 (ARM Crypto Extensions + NEON)
#include "textflag.h"

// func vistrutah256EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, p4, p5 *byte)
TEXT ·vistrutah256EncryptAsm(SB), NOSPLIT, $80-64
	MOVD plaintext+0(FP), R0
	MOVD ciphertext+8(FP), R1
	MOVD key+16(FP), R2
	MOVD keySize+24(FP), R3
	MOVD rounds+32(FP), R4
	MOVD roundConstants+40(FP), R5
	MOVD p4+48(FP), R6
	MOVD p5+56(FP), R7

	// Load plaintext into V0, V1 (s0, s1)
	VLD1 (R0), [V0.B16, V1.B16]

	// Create zero vector
	VEOR V31.B16, V31.B16, V31.B16

	// Prepare fixed_key[32] on stack (SP+0 to SP+31)
	// If key_size == 16, duplicate key
	CMP $16, R3
	BNE key32_arm
	VLD1 (R2), [V16.B16]
	VST1 [V16.B16], (RSP)
	ADD $16, RSP, R8
	VST1 [V16.B16], (R8)
	B key_done_arm
key32_arm:
	VLD1 (R2), [V16.B16, V17.B16]
	VST1 [V16.B16, V17.B16], (RSP)
key_done_arm:

	// Load fixed_key from stack
	VLD1 (RSP), [V16.B16, V17.B16]  // V16=fk0, V17=fk1

	// round_key = {fixed_key[16:32], fixed_key[0:16]}
	// V18=rk0 (from fk1), V19=rk1 (from fk0)
	VMOV V17.B16, V18.B16    // rk0 = fk1
	VMOV V16.B16, V19.B16    // rk1 = fk0

	// Store round_key to stack (SP+32 to SP+63)
	ADD $32, RSP, R8
	VST1 [V18.B16, V19.B16], (R8)

	// Load P4, P5 permutation tables
	VLD1 (R6), [V28.B16]     // P4
	VLD1 (R7), [V29.B16]     // P5

	// steps = rounds / 2
	LSR $1, R4, R9           // R9 = steps

	// Initial: s0 ^= rk0, s1 ^= rk1
	VEOR V18.B16, V0.B16, V0.B16
	VEOR V19.B16, V1.B16, V1.B16

	// s0 = AES_ENC(s0, fk0) = AESMC(AESE(0, s0)) ^ fk0
	// ARM: AESE does XOR first then SubBytes+ShiftRows
	// We use zero key to disable XOR, do AESE+AESMC, then XOR fk at end
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V16.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V17.B16, V1.B16, V1.B16

	// Loop counter: i = 1
	MOVD $1, R10
loop_arm:
	CMP R9, R10
	BGE loop_end_arm

	// AES round with zero key
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16

	// Mixing layer 256 using VUZP1/VUZP2:
	// s0, s1 = vuzp1(s0, s1), vuzp2(s0, s1)
	VMOV V0.B16, V2.B16      // save s0
	VUZP1 V1.B8, V0.B8, V0.B8   // s0 = evens interleaved
	VUZP2 V1.B8, V2.B8, V1.B8   // s1 = odds interleaved

	// Apply permutations to round_key
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V28.B16, [V18.B16], V18.B16   // P4 permutation
	VTBL V29.B16, [V19.B16], V19.B16   // P5 permutation
	VST1 [V18.B16, V19.B16], (R8)

	// s0 ^= rk0, s1 ^= rk1
	VEOR V18.B16, V0.B16, V0.B16
	VEOR V19.B16, V1.B16, V1.B16

	// s0 ^= round_constant[i-1]
	SUB $1, R10, R11
	LSL $4, R11              // (i-1) * 16
	ADD R5, R11, R11
	VLD1 (R11), [V20.B16]
	VEOR V20.B16, V0.B16, V0.B16

	// AES round with fixed key
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V16.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V17.B16, V1.B16, V1.B16

	ADD $1, R10, R10
	B loop_arm

loop_end_arm:
	// Final permutations
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V28.B16, [V18.B16], V18.B16
	VTBL V29.B16, [V19.B16], V19.B16

	// Final round (no MixColumns): AESE + XOR key
	AESE V31.B16, V0.B16
	VEOR V18.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	VEOR V19.B16, V1.B16, V1.B16

	// Store ciphertext
	VST1 [V0.B16, V1.B16], (R1)
	RET

// func vistrutah256DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, p4inv, p5inv *byte)
TEXT ·vistrutah256DecryptAsm(SB), NOSPLIT, $80-64
	MOVD ciphertext+0(FP), R0
	MOVD plaintext+8(FP), R1
	MOVD key+16(FP), R2
	MOVD keySize+24(FP), R3
	MOVD rounds+32(FP), R4
	MOVD roundConstants+40(FP), R5
	MOVD p4inv+48(FP), R6
	MOVD p5inv+56(FP), R7

	// Load ciphertext into V0, V1
	VLD1 (R0), [V0.B16, V1.B16]

	// Create zero vector
	VEOR V31.B16, V31.B16, V31.B16

	// Prepare fixed_key[32]
	CMP $16, R3
	BNE dec_key32_arm
	VLD1 (R2), [V16.B16]
	VST1 [V16.B16], (RSP)
	ADD $16, RSP, R8
	VST1 [V16.B16], (R8)
	B dec_key_done_arm
dec_key32_arm:
	VLD1 (R2), [V16.B16, V17.B16]
	VST1 [V16.B16, V17.B16], (RSP)
dec_key_done_arm:

	// Load fixed_key
	VLD1 (RSP), [V16.B16, V17.B16]

	// round_key = {fk1, fk0}
	VMOV V17.B16, V18.B16
	VMOV V16.B16, V19.B16

	// Store round_key to stack
	ADD $32, RSP, R8
	VST1 [V18.B16, V19.B16], (R8)

	// Load inverse permutation tables
	VLD1 (R6), [V28.B16]     // P4_INV
	VLD1 (R7), [V29.B16]     // P5_INV

	// steps = rounds / 2
	LSR $1, R4, R9

	// Load forward P4/P5 from global symbols for key schedule advancement
	MOVD $·vistrutahP4(SB), R11
	VLD1 (R11), [V26.B16]    // Forward P4
	MOVD $·vistrutahP5(SB), R11
	VLD1 (R11), [V27.B16]    // Forward P5

	// Advance round_key forward 'steps' times
	MOVD R9, R10             // R10 = steps counter
advance_loop:
	CBZ R10, advance_done
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V26.B16, [V18.B16], V18.B16   // Forward P4
	VTBL V27.B16, [V19.B16], V19.B16   // Forward P5
	VST1 [V18.B16, V19.B16], (R8)
	SUB $1, R10, R10
	B advance_loop
advance_done:

	// Now round_key is at final position
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]

	// fk0_imc = AESIMC(fk0), fk1_imc = AESIMC(fk1)
	AESIMC V16.B16, V20.B16  // V20 = fk0_imc
	AESIMC V17.B16, V21.B16  // V21 = fk1_imc

	// Initial: s0 ^= rk0, s1 ^= rk1
	VEOR V18.B16, V0.B16, V0.B16
	VEOR V19.B16, V1.B16, V1.B16

	// Inverse AES round: AESIMC(AESD(0, s)) ^ fk_imc
	AESD V31.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V20.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V21.B16, V1.B16, V1.B16

	// Loop: i = steps-1 downto 1
	SUB $1, R9, R10          // R10 = steps - 1

dec_loop_arm:
	CMP $1, R10
	BLT dec_loop_end_arm

	// Apply inverse permutation to round_key
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V28.B16, [V18.B16], V18.B16   // P4_INV
	VTBL V29.B16, [V19.B16], V19.B16   // P5_INV
	VST1 [V18.B16, V19.B16], (R8)

	// AESD last (no AESIMC)
	AESD V31.B16, V0.B16
	VEOR V18.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	VEOR V19.B16, V1.B16, V1.B16

	// XOR round constant
	SUB $1, R10, R11
	LSL $4, R11
	ADD R5, R11, R11
	VLD1 (R11), [V22.B16]
	VEOR V22.B16, V0.B16, V0.B16

	// Inverse mixing layer 256 using VZIP1/VZIP2:
	// s0, s1 = vzip1(s0, s1), vzip2(s0, s1)
	VMOV V0.B16, V2.B16
	VZIP1 V1.B8, V0.B8, V0.B8
	VZIP2 V1.B8, V2.B8, V1.B8

	// AESIMC on states
	AESIMC V0.B16, V0.B16
	AESIMC V1.B16, V1.B16

	// Inverse AES round
	AESD V31.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V20.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V21.B16, V1.B16, V1.B16

	SUB $1, R10, R10
	B dec_loop_arm

dec_loop_end_arm:
	// Final inverse permutation
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V28.B16, [V18.B16], V18.B16
	VTBL V29.B16, [V19.B16], V19.B16

	// Final AESD
	AESD V31.B16, V0.B16
	VEOR V18.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	VEOR V19.B16, V1.B16, V1.B16

	// Store plaintext
	VST1 [V0.B16, V1.B16], (R1)
	RET

// func vistrutah512EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)
TEXT ·vistrutah512EncryptAsm(SB), NOSPLIT, $160-56
	MOVD plaintext+0(FP), R0
	MOVD ciphertext+8(FP), R1
	MOVD key+16(FP), R2
	MOVD keySize+24(FP), R3
	MOVD rounds+32(FP), R4
	MOVD roundConstants+40(FP), R5
	MOVD kexpShuffle+48(FP), R6

	// Load plaintext into V0-V3 (s0-s3)
	VLD1.P 64(R0), [V0.B16, V1.B16, V2.B16, V3.B16]

	// Create zero vector
	VEOR V31.B16, V31.B16, V31.B16

	// Prepare fixed_key[64] on stack
	CMP $32, R3
	BNE enc512_key64_arm
	// 32-byte key: duplicate
	VLD1 (R2), [V16.B16, V17.B16]
	VST1 [V16.B16, V17.B16], (RSP)
	ADD $32, RSP, R8
	VST1 [V16.B16, V17.B16], (R8)
	B enc512_key_done_arm
enc512_key64_arm:
	VLD1.P 64(R2), [V16.B16, V17.B16, V18.B16, V19.B16]
	VST1 [V16.B16, V17.B16], (RSP)
	ADD $32, RSP, R8
	VST1 [V18.B16, V19.B16], (R8)
enc512_key_done_arm:

	// Apply KEXP_SHUFFLE to fixed_key[32:64]
	// Load shuffle table (32 bytes)
	VLD1 (R6), [V24.B16, V25.B16]

	// Load fixed_key[32:64] into V18, V19
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]

	// Apply shuffle: this requires TBL4 across both vectors
	// KEXP_SHUFFLE references indices 0-31, spanning both V18 and V19
	// We need VTBL with 4 register table lookup

	// Store V18, V19 as the table base
	// Create table from V18, V19 (concatenated as 32-byte table)
	// ARM VTBL can use up to 4 consecutive registers

	// For 32-byte shuffle, we need indices 0-31
	// VTBL4 uses indices 0-63 across 4 registers
	// We'll use V18, V19 as source (32 bytes) and V24, V25 as indices

	// Apply TBL2 for first 16 indices
	VTBL V24.B16, [V18.B16, V19.B16], V20.B16

	// Apply TBL2 for second 16 indices
	VTBL V25.B16, [V18.B16, V19.B16], V21.B16

	// Store shuffled result back to fixed_key[32:64]
	VST1 [V20.B16, V21.B16], (R8)

	// Load full fixed_key
	VLD1 (RSP), [V16.B16, V17.B16]
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]

	// round_key arrangement:
	// rk0 = fk[16:32], rk1 = fk[0:16], rk2 = fk[48:64], rk3 = fk[32:48]
	VMOV V17.B16, V20.B16    // rk0 = fk1
	VMOV V16.B16, V21.B16    // rk1 = fk0
	VMOV V19.B16, V22.B16    // rk2 = fk3
	VMOV V18.B16, V23.B16    // rk3 = fk2

	// Store round_key to stack (SP+64 to SP+127)
	ADD $64, RSP, R8
	VST1 [V20.B16, V21.B16, V22.B16, V23.B16], (R8)

	// fk0-fk3 in V16-V19 (already loaded)

	// steps = rounds / 2
	LSR $1, R4, R9

	// Initial XOR
	VEOR V20.B16, V0.B16, V0.B16
	VEOR V21.B16, V1.B16, V1.B16
	VEOR V22.B16, V2.B16, V2.B16
	VEOR V23.B16, V3.B16, V3.B16

	// Initial AES round
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V16.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V17.B16, V1.B16, V1.B16

	AESE V31.B16, V2.B16
	AESMC V2.B16, V2.B16
	VEOR V18.B16, V2.B16, V2.B16

	AESE V31.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V19.B16, V3.B16, V3.B16

	// Loop counter
	MOVD $1, R10

enc512_loop_arm:
	CMP R9, R10
	BGE enc512_loop_end_arm

	// AES round with zero key
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16
	AESE V31.B16, V2.B16
	AESMC V2.B16, V2.B16
	AESE V31.B16, V3.B16
	AESMC V3.B16, V3.B16

	// Mixing layer 512 using TBL4
	// The mixing layer performs a 4x4 byte transpose
	// We use precomputed index tables

	// Index tables for mixing layer (hard-coded)
	// idx0: {0,16,32,48, 1,17,33,49, 2,18,34,50, 3,19,35,51}
	// idx1: {8,24,40,56, 9,25,41,57, 10,26,42,58, 11,27,43,59}
	// idx2: {4,20,36,52, 5,21,37,53, 6,22,38,54, 7,23,39,55}
	// idx3: {12,28,44,60, 13,29,45,61, 14,30,46,62, 15,31,47,63}

	// Load mixing indices (we'll hard-code them with VMOV or use stack)
	// For efficiency, store on stack once at function start
	// For now, we'll use Go global data

	// Access mixing layer index tables from Go globals
	MOVD $·vistrutah512MixIdx0(SB), R11
	VLD1 (R11), [V24.B16]
	MOVD $·vistrutah512MixIdx1(SB), R11
	VLD1 (R11), [V25.B16]
	MOVD $·vistrutah512MixIdx2(SB), R11
	VLD1 (R11), [V26.B16]
	MOVD $·vistrutah512MixIdx3(SB), R11
	VLD1 (R11), [V27.B16]

	// Apply TBL4 with V0-V3 as source table
	VTBL V24.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V4.B16   // new s0
	VTBL V25.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V5.B16   // new s1
	VTBL V26.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V6.B16   // new s2
	VTBL V27.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V7.B16   // new s3

	VMOV V4.B16, V0.B16
	VMOV V5.B16, V1.B16
	VMOV V6.B16, V2.B16
	VMOV V7.B16, V3.B16

	// Rotate round_key bytes
	// rk0, rk2: rotate left by 5
	// rk1, rk3: rotate left by 10
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]

	// VEXT(a, b, n) = (b:a)[n:n+16] (byte extract)
	// Rotate left by 5: VEXT(v, v, 5)
	VEXT $5, V20.B16, V20.B16, V20.B16
	VEXT $10, V21.B16, V21.B16, V21.B16
	VEXT $5, V22.B16, V22.B16, V22.B16
	VEXT $10, V23.B16, V23.B16, V23.B16

	VST1 [V20.B16, V21.B16, V22.B16, V23.B16], (R8)

	// XOR round_key
	VEOR V20.B16, V0.B16, V0.B16
	VEOR V21.B16, V1.B16, V1.B16
	VEOR V22.B16, V2.B16, V2.B16
	VEOR V23.B16, V3.B16, V3.B16

	// XOR round constant to s0
	SUB $1, R10, R11
	LSL $4, R11
	ADD R5, R11, R11
	VLD1 (R11), [V24.B16]
	VEOR V24.B16, V0.B16, V0.B16

	// AES round with fixed key
	AESE V31.B16, V0.B16
	AESMC V0.B16, V0.B16
	VEOR V16.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	AESMC V1.B16, V1.B16
	VEOR V17.B16, V1.B16, V1.B16

	AESE V31.B16, V2.B16
	AESMC V2.B16, V2.B16
	VEOR V18.B16, V2.B16, V2.B16

	AESE V31.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR V19.B16, V3.B16, V3.B16

	ADD $1, R10, R10
	B enc512_loop_arm

enc512_loop_end_arm:
	// Final key rotation
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]

	VEXT $5, V20.B16, V20.B16, V20.B16
	VEXT $10, V21.B16, V21.B16, V21.B16
	VEXT $5, V22.B16, V22.B16, V22.B16
	VEXT $10, V23.B16, V23.B16, V23.B16

	// Final round (no AESMC)
	AESE V31.B16, V0.B16
	VEOR V20.B16, V0.B16, V0.B16

	AESE V31.B16, V1.B16
	VEOR V21.B16, V1.B16, V1.B16

	AESE V31.B16, V2.B16
	VEOR V22.B16, V2.B16, V2.B16

	AESE V31.B16, V3.B16
	VEOR V23.B16, V3.B16, V3.B16

	// Store ciphertext
	VST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R1)
	RET

// func vistrutah512DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)
TEXT ·vistrutah512DecryptAsm(SB), NOSPLIT, $160-56
	MOVD ciphertext+0(FP), R0
	MOVD plaintext+8(FP), R1
	MOVD key+16(FP), R2
	MOVD keySize+24(FP), R3
	MOVD rounds+32(FP), R4
	MOVD roundConstants+40(FP), R5
	MOVD kexpShuffle+48(FP), R6

	// Load ciphertext into V0-V3
	VLD1.P 64(R0), [V0.B16, V1.B16, V2.B16, V3.B16]

	// Create zero vector
	VEOR V31.B16, V31.B16, V31.B16

	// Prepare fixed_key[64]
	CMP $32, R3
	BNE dec512_key64_arm
	VLD1 (R2), [V16.B16, V17.B16]
	VST1 [V16.B16, V17.B16], (RSP)
	ADD $32, RSP, R8
	VST1 [V16.B16, V17.B16], (R8)
	B dec512_key_done_arm
dec512_key64_arm:
	VLD1.P 64(R2), [V16.B16, V17.B16, V18.B16, V19.B16]
	VST1 [V16.B16, V17.B16], (RSP)
	ADD $32, RSP, R8
	VST1 [V18.B16, V19.B16], (R8)
dec512_key_done_arm:

	// Apply KEXP_SHUFFLE
	VLD1 (R6), [V24.B16, V25.B16]
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]
	VTBL V24.B16, [V18.B16, V19.B16], V20.B16
	VTBL V25.B16, [V18.B16, V19.B16], V21.B16
	VST1 [V20.B16, V21.B16], (R8)

	// Load fixed_key
	VLD1 (RSP), [V16.B16, V17.B16]
	ADD $32, RSP, R8
	VLD1 (R8), [V18.B16, V19.B16]

	// round_key arrangement
	VMOV V17.B16, V20.B16
	VMOV V16.B16, V21.B16
	VMOV V19.B16, V22.B16
	VMOV V18.B16, V23.B16

	ADD $64, RSP, R8
	VST1 [V20.B16, V21.B16, V22.B16, V23.B16], (R8)

	// steps = rounds / 2
	LSR $1, R4, R9

	// Advance round_key to final position
	MOVD R9, R10
dec512_advance_arm:
	CBZ R10, dec512_advance_done_arm
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]
	VEXT $5, V20.B16, V20.B16, V20.B16
	VEXT $10, V21.B16, V21.B16, V21.B16
	VEXT $5, V22.B16, V22.B16, V22.B16
	VEXT $10, V23.B16, V23.B16, V23.B16
	VST1 [V20.B16, V21.B16, V22.B16, V23.B16], (R8)
	SUB $1, R10, R10
	B dec512_advance_arm
dec512_advance_done_arm:

	// fk_imc
	AESIMC V16.B16, V12.B16
	AESIMC V17.B16, V13.B16
	AESIMC V18.B16, V14.B16
	AESIMC V19.B16, V15.B16

	// Load final round_key
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]

	// Initial XOR and inverse round
	VEOR V20.B16, V0.B16, V0.B16
	VEOR V21.B16, V1.B16, V1.B16
	VEOR V22.B16, V2.B16, V2.B16
	VEOR V23.B16, V3.B16, V3.B16

	AESD V31.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V12.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V13.B16, V1.B16, V1.B16

	AESD V31.B16, V2.B16
	AESIMC V2.B16, V2.B16
	VEOR V14.B16, V2.B16, V2.B16

	AESD V31.B16, V3.B16
	AESIMC V3.B16, V3.B16
	VEOR V15.B16, V3.B16, V3.B16

	// Load inverse mixing indices
	MOVD $·vistrutah512InvMixIdx0(SB), R11
	VLD1 (R11), [V24.B16]
	MOVD $·vistrutah512InvMixIdx1(SB), R11
	VLD1 (R11), [V25.B16]
	MOVD $·vistrutah512InvMixIdx2(SB), R11
	VLD1 (R11), [V26.B16]
	MOVD $·vistrutah512InvMixIdx3(SB), R11
	VLD1 (R11), [V27.B16]

	// Loop
	SUB $1, R9, R10

dec512_loop_arm:
	CMP $1, R10
	BLT dec512_loop_end_arm

	// Rotate backward (by 11 and 6)
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]
	VEXT $11, V20.B16, V20.B16, V20.B16
	VEXT $6, V21.B16, V21.B16, V21.B16
	VEXT $11, V22.B16, V22.B16, V22.B16
	VEXT $6, V23.B16, V23.B16, V23.B16
	VST1 [V20.B16, V21.B16, V22.B16, V23.B16], (R8)

	// AESD last
	AESD V31.B16, V0.B16
	VEOR V20.B16, V0.B16, V0.B16
	AESD V31.B16, V1.B16
	VEOR V21.B16, V1.B16, V1.B16
	AESD V31.B16, V2.B16
	VEOR V22.B16, V2.B16, V2.B16
	AESD V31.B16, V3.B16
	VEOR V23.B16, V3.B16, V3.B16

	// XOR round constant
	SUB $1, R10, R11
	LSL $4, R11
	ADD R5, R11, R11
	VLD1 (R11), [V28.B16]
	VEOR V28.B16, V0.B16, V0.B16

	// Inverse mixing layer
	VTBL V24.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V4.B16
	VTBL V25.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V5.B16
	VTBL V26.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V6.B16
	VTBL V27.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V7.B16

	VMOV V4.B16, V0.B16
	VMOV V5.B16, V1.B16
	VMOV V6.B16, V2.B16
	VMOV V7.B16, V3.B16

	// AESIMC
	AESIMC V0.B16, V0.B16
	AESIMC V1.B16, V1.B16
	AESIMC V2.B16, V2.B16
	AESIMC V3.B16, V3.B16

	// AESD + AESIMC + XOR fk_imc
	AESD V31.B16, V0.B16
	AESIMC V0.B16, V0.B16
	VEOR V12.B16, V0.B16, V0.B16

	AESD V31.B16, V1.B16
	AESIMC V1.B16, V1.B16
	VEOR V13.B16, V1.B16, V1.B16

	AESD V31.B16, V2.B16
	AESIMC V2.B16, V2.B16
	VEOR V14.B16, V2.B16, V2.B16

	AESD V31.B16, V3.B16
	AESIMC V3.B16, V3.B16
	VEOR V15.B16, V3.B16, V3.B16

	SUB $1, R10, R10
	B dec512_loop_arm

dec512_loop_end_arm:
	// Final backward rotation
	ADD $64, RSP, R8
	VLD1 (R8), [V20.B16, V21.B16, V22.B16, V23.B16]
	VEXT $11, V20.B16, V20.B16, V20.B16
	VEXT $6, V21.B16, V21.B16, V21.B16
	VEXT $11, V22.B16, V22.B16, V22.B16
	VEXT $6, V23.B16, V23.B16, V23.B16

	// Final AESD
	AESD V31.B16, V0.B16
	VEOR V20.B16, V0.B16, V0.B16
	AESD V31.B16, V1.B16
	VEOR V21.B16, V1.B16, V1.B16
	AESD V31.B16, V2.B16
	VEOR V22.B16, V2.B16, V2.B16
	AESD V31.B16, V3.B16
	VEOR V23.B16, V3.B16, V3.B16

	// Store plaintext
	VST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R1)
	RET
