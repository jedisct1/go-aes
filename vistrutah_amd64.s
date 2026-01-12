// Vistrutah hardware acceleration for AMD64 (Intel AES-NI + SSE)
#include "textflag.h"

// Shuffle masks stored in DATA section
DATA reorg_mask<>+0x00(SB)/8, $0x0e0c0a0806040200
DATA reorg_mask<>+0x08(SB)/8, $0x0f0d0b0907050301
GLOBL reorg_mask<>(SB), RODATA|NOPTR, $16

DATA inv_reorg_mask<>+0x00(SB)/8, $0x0b030a0209010800
DATA inv_reorg_mask<>+0x08(SB)/8, $0x0f070e060d050c04
GLOBL inv_reorg_mask<>(SB), RODATA|NOPTR, $16

// extract_mask for inverse mixing layer 512
// _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0)
// Bytes: [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
DATA extract_mask_512<>+0x00(SB)/8, $0x0d0905010c080400
DATA extract_mask_512<>+0x08(SB)/8, $0x0f0b07030e0a0602
GLOBL extract_mask_512<>(SB), RODATA|NOPTR, $16

// KEXP_SHUFFLE masks for 32-byte cross-lane shuffle
// out0 = PSHUFB(lo, mask_A) | PSHUFB(hi, mask_B)
// out1 = PSHUFB(lo, mask_B) | PSHUFB(hi, mask_A)
DATA kexp_mask_A<>+0x00(SB)/8, $0x0380090a80088080
DATA kexp_mask_A<>+0x08(SB)/8, $0x0b80010280008080
GLOBL kexp_mask_A<>(SB), RODATA|NOPTR, $16

DATA kexp_mask_B<>+0x00(SB)/8, $0x8004808007800d0e
DATA kexp_mask_B<>+0x08(SB)/8, $0x800c80800f800506
GLOBL kexp_mask_B<>(SB), RODATA|NOPTR, $16

// Forward permutation P4 = {9, 7, 13, 14, 0, 10, 3, 5, 1, 2, 15, 4, 6, 12, 11, 8}
// As bytes: 09 07 0d 0e 00 0a 03 05 01 02 0f 04 06 0c 0b 08
DATA p4_fwd<>+0x00(SB)/8, $0x05030a000e0d0709
DATA p4_fwd<>+0x08(SB)/8, $0x080b0c06040f0201
GLOBL p4_fwd<>(SB), RODATA|NOPTR, $16

// Forward permutation P5 = {12, 8, 1, 9, 15, 4, 0, 3, 14, 10, 6, 7, 2, 5, 13, 11}
// As bytes: 0c 08 01 09 0f 04 00 03 0e 0a 06 07 02 05 0d 0b
DATA p5_fwd<>+0x00(SB)/8, $0x0300040f0901080c
DATA p5_fwd<>+0x08(SB)/8, $0x0b0d050207060a0e
GLOBL p5_fwd<>(SB), RODATA|NOPTR, $16

// func vistrutah256EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, p4, p5 *byte)
TEXT ·vistrutah256EncryptAsm(SB), NOSPLIT, $64-64
	MOVQ plaintext+0(FP), AX
	MOVQ ciphertext+8(FP), BX
	MOVQ key+16(FP), CX
	MOVQ keySize+24(FP), DX
	MOVQ rounds+32(FP), R8
	MOVQ roundConstants+40(FP), R9
	MOVQ p4+48(FP), R10
	MOVQ p5+56(FP), R11

	// Load plaintext into X0, X1 (s0, s1)
	MOVOU (AX), X0
	MOVOU 16(AX), X1

	// Prepare fixed_key[32] on stack
	// If key_size == 16, duplicate key
	CMPQ DX, $16
	JNE key32
	MOVOU (CX), X8
	MOVOU X8, 0(SP)     // fixed_key[0:16]
	MOVOU X8, 16(SP)    // fixed_key[16:32]
	JMP key_done
key32:
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
key_done:

	// round_key = {fixed_key[16:32], fixed_key[0:16]}
	MOVOU 16(SP), X10   // round_key[0:16] = fixed_key[16:32]
	MOVOU 0(SP), X11    // round_key[16:32] = fixed_key[0:16]
	MOVOU X10, 32(SP)   // Store round_key for permutations
	MOVOU X11, 48(SP)

	// fk0 = fixed_key[0:16], fk1 = fixed_key[16:32]
	MOVOU 0(SP), X2     // fk0
	MOVOU 16(SP), X3    // fk1

	// steps = rounds / 2
	MOVQ R8, R12
	SHRQ $1, R12        // R12 = steps

	// Initial: s0 ^= rk0, s1 ^= rk1
	PXOR X10, X0
	PXOR X11, X1

	// s0 = AESENC(s0, fk0), s1 = AESENC(s1, fk1)
	AESENC X2, X0
	AESENC X3, X1

	// Zero vector for AES rounds without key
	PXOR X14, X14

	// Load shuffle masks
	MOVOU reorg_mask<>(SB), X12
	MOVOU inv_reorg_mask<>(SB), X13

	// Load P4, P5 permutations
	MOVOU (R10), X4     // P4
	MOVOU (R11), X5     // P5

	// Loop counter: i = 1 to steps-1
	MOVQ $1, R13
loop:
	CMPQ R13, R12
	JGE loop_end

	// s0 = AESENC(s0, zero), s1 = AESENC(s1, zero)
	AESENC X14, X0
	AESENC X14, X1

	// Mixing layer 256:
	// Step 1: Reorganize each block to [evens, odds]
	PSHUFB X12, X0
	PSHUFB X12, X1
	// Step 2: Swap halves: s0 = [s0_evens, s1_evens], s1 = [s0_odds, s1_odds]
	MOVOA X0, X6
	PUNPCKLQDQ X1, X0   // s0 = unpacklo64(t0, t1)
	PUNPCKHQDQ X1, X6   // X6 = unpackhi64(t0, t1)
	MOVOA X6, X1

	// Apply permutations to round_key
	MOVOU 32(SP), X6    // rk0
	MOVOU 48(SP), X7    // rk1
	PSHUFB X4, X6       // P4 permutation
	PSHUFB X5, X7       // P5 permutation
	MOVOU X6, 32(SP)
	MOVOU X7, 48(SP)

	// s0 ^= rk0, s1 ^= rk1
	PXOR X6, X0
	PXOR X7, X1

	// s0 ^= round_constant[i-1]
	MOVQ R13, R14
	DECQ R14
	SHLQ $4, R14        // (i-1) * 16
	ADDQ R9, R14
	MOVOU (R14), X6
	PXOR X6, X0

	// s0 = AESENC(s0, fk0), s1 = AESENC(s1, fk1)
	AESENC X2, X0
	AESENC X3, X1

	INCQ R13
	JMP loop

loop_end:
	// Final permutations
	MOVOU 32(SP), X6
	MOVOU 48(SP), X7
	PSHUFB X4, X6
	PSHUFB X5, X7

	// Final round (no MixColumns)
	AESENCLAST X6, X0
	AESENCLAST X7, X1

	// Store ciphertext
	MOVOU X0, (BX)
	MOVOU X1, 16(BX)
	RET

// func vistrutah256DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, p4inv, p5inv *byte)
TEXT ·vistrutah256DecryptAsm(SB), NOSPLIT, $64-64
	MOVQ ciphertext+0(FP), AX
	MOVQ plaintext+8(FP), BX
	MOVQ key+16(FP), CX
	MOVQ keySize+24(FP), DX
	MOVQ rounds+32(FP), R8
	MOVQ roundConstants+40(FP), R9
	MOVQ p4inv+48(FP), R10
	MOVQ p5inv+56(FP), R11

	// Load ciphertext into X0, X1
	MOVOU (AX), X0
	MOVOU 16(AX), X1

	// Prepare fixed_key
	CMPQ DX, $16
	JNE dec_key32
	MOVOU (CX), X8
	MOVOU X8, 0(SP)
	MOVOU X8, 16(SP)
	JMP dec_key_done
dec_key32:
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
dec_key_done:

	// round_key = {fixed_key[16:32], fixed_key[0:16]}
	MOVOU 16(SP), X10
	MOVOU 0(SP), X11
	MOVOU X10, 32(SP)
	MOVOU X11, 48(SP)

	// steps = rounds / 2
	MOVQ R8, R12
	SHRQ $1, R12

	// fk0, fk1 from fixed_key
	MOVOU 0(SP), X2     // fk0
	MOVOU 16(SP), X3    // fk1

	// Load P4_INV and P5_INV for the main decryption loop
	MOVOU (R10), X6     // P4_INV
	MOVOU (R11), X7     // P5_INV

	// Advance round_key to final position using forward permutations
	MOVOU p4_fwd<>(SB), X8
	MOVOU p5_fwd<>(SB), X9

	// Loop: apply P4/P5 'steps' times
	MOVQ R12, R13
dec256_advance:
	CMPQ R13, $0
	JE dec256_advance_done

	MOVOU 32(SP), X10   // rk0
	MOVOU 48(SP), X11   // rk1
	PSHUFB X8, X10      // P4 permutation
	PSHUFB X9, X11      // P5 permutation
	MOVOU X10, 32(SP)
	MOVOU X11, 48(SP)

	DECQ R13
	JMP dec256_advance
dec256_advance_done:

	// fk0_imc = AESIMC(fk0), fk1_imc = AESIMC(fk1)
	AESIMC X2, X4
	AESIMC X3, X5

	// Load shuffle masks for inverse mixing layer
	MOVOU inv_reorg_mask<>(SB), X12

	// Load round_key at final position
	MOVOU 32(SP), X10   // rk0
	MOVOU 48(SP), X11   // rk1

	// s0 ^= rk0, s1 ^= rk1
	PXOR X10, X0
	PXOR X11, X1

	// s0 = AESDEC(s0, fk0_imc), s1 = AESDEC(s1, fk1_imc)
	AESDEC X4, X0
	AESDEC X5, X1

	// Loop: i = steps-1 downto 1
	MOVQ R12, R13
	DECQ R13            // i = steps - 1

dec_loop:
	CMPQ R13, $1
	JL dec_loop_end

	// Apply inverse permutation to round_key
	MOVOU 32(SP), X10
	MOVOU 48(SP), X11
	PSHUFB X6, X10      // P4_INV
	PSHUFB X7, X11      // P5_INV
	MOVOU X10, 32(SP)
	MOVOU X11, 48(SP)

	// s0 = AESDECLAST(s0, rk0), s1 = AESDECLAST(s1, rk1)
	AESDECLAST X10, X0
	AESDECLAST X11, X1

	// s0 ^= round_constant[i-1]
	MOVQ R13, R14
	DECQ R14
	SHLQ $4, R14
	ADDQ R9, R14
	MOVOU (R14), X8
	PXOR X8, X0

	// Inverse mixing layer 256:
	// Step 1: unpacklo64/unpackhi64 to reconstruct [evens, odds] per slice
	MOVOA X0, X8
	PUNPCKLQDQ X1, X0   // slice0 = [s0_evens, s0_odds]
	PUNPCKHQDQ X1, X8   // slice1 = [s1_evens, s1_odds]
	MOVOA X8, X1

	// Step 2: Apply inverse reorganization
	PSHUFB X12, X0
	PSHUFB X12, X1

	// s0 = AESIMC(s0), s1 = AESIMC(s1)
	AESIMC X0, X0
	AESIMC X1, X1

	// s0 = AESDEC(s0, fk0_imc), s1 = AESDEC(s1, fk1_imc)
	AESDEC X4, X0
	AESDEC X5, X1

	DECQ R13
	JMP dec_loop

dec_loop_end:
	// Final inverse permutation
	MOVOU 32(SP), X10
	MOVOU 48(SP), X11
	PSHUFB X6, X10
	PSHUFB X7, X11

	// Final round
	AESDECLAST X10, X0
	AESDECLAST X11, X1

	// Store plaintext
	MOVOU X0, (BX)
	MOVOU X1, 16(BX)
	RET

// func vistrutah512EncryptAsm(plaintext, ciphertext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)
TEXT ·vistrutah512EncryptAsm(SB), NOSPLIT, $128-56
	MOVQ plaintext+0(FP), AX
	MOVQ ciphertext+8(FP), BX
	MOVQ key+16(FP), CX
	MOVQ keySize+24(FP), DX
	MOVQ rounds+32(FP), R8
	MOVQ roundConstants+40(FP), R9
	MOVQ kexpShuffle+48(FP), R10

	// Load plaintext into X0-X3 (s0-s3)
	MOVOU (AX), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVOU 48(AX), X3

	// Prepare fixed_key[64] on stack
	CMPQ DX, $32
	JNE enc512_key64
	// 32-byte key: duplicate
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
	MOVOU X8, 32(SP)
	MOVOU X9, 48(SP)
	JMP enc512_key_done
enc512_key64:
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU 32(CX), X10
	MOVOU 48(CX), X11
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
	MOVOU X10, 32(SP)
	MOVOU X11, 48(SP)
enc512_key_done:

	// Apply KEXP_SHUFFLE to fixed_key[32:64]
	// KEXP_SHUFFLE is a 32-byte permutation: output[i] = input[KEXP_SHUFFLE[i]]
	// We use pre-computed masks for cross-lane shuffle with PSHUFB:
	//   out0 = PSHUFB(lo, mask_A) | PSHUFB(hi, mask_B)
	//   out1 = PSHUFB(lo, mask_B) | PSHUFB(hi, mask_A)
	MOVOU 32(SP), X8      // lo = fixed_key[32:48]
	MOVOU 48(SP), X9      // hi = fixed_key[48:64]
	MOVOU kexp_mask_A<>(SB), X10
	MOVOU kexp_mask_B<>(SB), X11

	// Compute shuffled output
	MOVOA X8, X12
	MOVOA X9, X13
	PSHUFB X10, X12       // PSHUFB(lo, mask_A)
	PSHUFB X11, X13       // PSHUFB(hi, mask_B)
	POR X13, X12          // out0 = PSHUFB(lo, mask_A) | PSHUFB(hi, mask_B)

	MOVOA X8, X14
	MOVOA X9, X15
	PSHUFB X11, X14       // PSHUFB(lo, mask_B)
	PSHUFB X10, X15       // PSHUFB(hi, mask_A)
	POR X15, X14          // out1 = PSHUFB(lo, mask_B) | PSHUFB(hi, mask_A)

	// Store shuffled result back to fixed_key[32:64]
	MOVOU X12, 32(SP)     // fixed_key[32:48] = out0
	MOVOU X14, 48(SP)     // fixed_key[48:64] = out1

	// Set up round_key from shuffled fixed_key:
	// round_key = {fk[16:32], fk[0:16], fk[48:64], fk[32:48]}
	MOVOU 16(SP), X10     // round_key[0:16] = fixed_key[16:32]
	MOVOU 0(SP), X11      // round_key[16:32] = fixed_key[0:16]
	MOVOU 48(SP), X12     // round_key[32:48] = fixed_key[48:64] (shuffled)
	MOVOU 32(SP), X13     // round_key[48:64] = fixed_key[32:48] (shuffled)
	MOVOU X10, 64(SP)
	MOVOU X11, 80(SP)
	MOVOU X12, 96(SP)
	MOVOU X13, 112(SP)

	// fk0-fk3 from fixed_key
	MOVOU 0(SP), X4       // fk0
	MOVOU 16(SP), X5      // fk1
	MOVOU 32(SP), X6      // fk2
	MOVOU 48(SP), X7      // fk3

	// steps = rounds / 2
	MOVQ R8, R12
	SHRQ $1, R12

	// Load round_keys
	MOVOU 64(SP), X10     // rk0
	MOVOU 80(SP), X11     // rk1
	MOVOU 96(SP), X12     // rk2
	MOVOU 112(SP), X13    // rk3

	// Initial XOR
	PXOR X10, X0
	PXOR X11, X1
	PXOR X12, X2
	PXOR X13, X3

	// Initial AES round
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3

	// Zero vector
	PXOR X14, X14

	// Loop counter
	MOVQ $1, R13

enc512_loop:
	CMPQ R13, R12
	JGE enc512_loop_end

	// AES round with zero key
	AESENC X14, X0
	AESENC X14, X1
	AESENC X14, X2
	AESENC X14, X3

	// Mixing layer 512:
	// lo01 = unpacklo8(s0, s1), hi01 = unpackhi8(s0, s1)
	// lo23 = unpacklo8(s2, s3), hi23 = unpackhi8(s2, s3)
	MOVOA X0, X8
	MOVOA X2, X9
	PUNPCKLBW X1, X0      // lo01
	PUNPCKHBW X1, X8      // hi01
	PUNPCKLBW X3, X2      // lo23
	PUNPCKHBW X3, X9      // hi23

	// s0 = unpacklo16(lo01, lo23)
	// s2 = unpackhi16(lo01, lo23)
	// s1 = unpacklo16(hi01, hi23)
	// s3 = unpackhi16(hi01, hi23)
	MOVOA X0, X10
	MOVOA X8, X11
	PUNPCKLWL X2, X0      // s0 = unpacklo16(lo01, lo23)
	PUNPCKHWL X2, X10     // X10 = unpackhi16(lo01, lo23) -> s2
	PUNPCKLWL X9, X8      // X8 = unpacklo16(hi01, hi23) -> s1
	PUNPCKHWL X9, X11     // X11 = unpackhi16(hi01, hi23) -> s3

	MOVOA X8, X1
	MOVOA X10, X2
	MOVOA X11, X3

	// Rotate round_key bytes
	// rk0: rotate left by 5, rk1: rotate left by 10
	// rk2: rotate left by 5, rk3: rotate left by 10
	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	// PALIGNR(a, b, n) = (a << 128 | b) >> (n*8)
	// To rotate left by 5: PALIGNR(v, v, 5)
	MOVOA X10, X8
	PALIGNR $5, X8, X10
	MOVOA X11, X8
	PALIGNR $10, X8, X11
	MOVOA X12, X8
	PALIGNR $5, X8, X12
	MOVOA X13, X8
	PALIGNR $10, X8, X13

	MOVOU X10, 64(SP)
	MOVOU X11, 80(SP)
	MOVOU X12, 96(SP)
	MOVOU X13, 112(SP)

	// XOR round_key
	PXOR X10, X0
	PXOR X11, X1
	PXOR X12, X2
	PXOR X13, X3

	// XOR round constant to s0
	MOVQ R13, R14
	DECQ R14
	SHLQ $4, R14
	ADDQ R9, R14
	MOVOU (R14), X8
	PXOR X8, X0

	// AES round with fixed key
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3

	INCQ R13
	JMP enc512_loop

enc512_loop_end:
	// Final key rotation
	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	MOVOA X10, X8
	PALIGNR $5, X8, X10
	MOVOA X11, X8
	PALIGNR $10, X8, X11
	MOVOA X12, X8
	PALIGNR $5, X8, X12
	MOVOA X13, X8
	PALIGNR $10, X8, X13

	// Final round
	AESENCLAST X10, X0
	AESENCLAST X11, X1
	AESENCLAST X12, X2
	AESENCLAST X13, X3

	// Store ciphertext
	MOVOU X0, (BX)
	MOVOU X1, 16(BX)
	MOVOU X2, 32(BX)
	MOVOU X3, 48(BX)
	RET

// func vistrutah512DecryptAsm(ciphertext, plaintext, key *byte, keySize, rounds int, roundConstants, kexpShuffle *byte)
TEXT ·vistrutah512DecryptAsm(SB), NOSPLIT, $128-56
	MOVQ ciphertext+0(FP), AX
	MOVQ plaintext+8(FP), BX
	MOVQ key+16(FP), CX
	MOVQ keySize+24(FP), DX
	MOVQ rounds+32(FP), R8
	MOVQ roundConstants+40(FP), R9
	MOVQ kexpShuffle+48(FP), R10

	// Load ciphertext into X0-X3
	MOVOU (AX), X0
	MOVOU 16(AX), X1
	MOVOU 32(AX), X2
	MOVOU 48(AX), X3

	// Prepare fixed_key[64]
	CMPQ DX, $32
	JNE dec512_key64
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
	MOVOU X8, 32(SP)
	MOVOU X9, 48(SP)
	JMP dec512_key_done
dec512_key64:
	MOVOU (CX), X8
	MOVOU 16(CX), X9
	MOVOU 32(CX), X10
	MOVOU 48(CX), X11
	MOVOU X8, 0(SP)
	MOVOU X9, 16(SP)
	MOVOU X10, 32(SP)
	MOVOU X11, 48(SP)
dec512_key_done:

	// Apply KEXP_SHUFFLE to fixed_key[32:64] (same as encryption)
	MOVOU 32(SP), X8      // lo = fixed_key[32:48]
	MOVOU 48(SP), X9      // hi = fixed_key[48:64]
	MOVOU kexp_mask_A<>(SB), X10
	MOVOU kexp_mask_B<>(SB), X11

	MOVOA X8, X12
	MOVOA X9, X13
	PSHUFB X10, X12       // PSHUFB(lo, mask_A)
	PSHUFB X11, X13       // PSHUFB(hi, mask_B)
	POR X13, X12          // out0

	MOVOA X8, X14
	MOVOA X9, X15
	PSHUFB X11, X14       // PSHUFB(lo, mask_B)
	PSHUFB X10, X15       // PSHUFB(hi, mask_A)
	POR X15, X14          // out1

	MOVOU X12, 32(SP)     // fixed_key[32:48] = out0
	MOVOU X14, 48(SP)     // fixed_key[48:64] = out1

	// Set up round_key from shuffled fixed_key
	MOVOU 16(SP), X10     // round_key[0:16] = fixed_key[16:32]
	MOVOU 0(SP), X11      // round_key[16:32] = fixed_key[0:16]
	MOVOU 48(SP), X12     // round_key[32:48] = fixed_key[48:64] (shuffled)
	MOVOU 32(SP), X13     // round_key[48:64] = fixed_key[32:48] (shuffled)
	MOVOU X10, 64(SP)
	MOVOU X11, 80(SP)
	MOVOU X12, 96(SP)
	MOVOU X13, 112(SP)

	// steps = rounds / 2
	MOVQ R8, R12
	SHRQ $1, R12

	// Advance round_key to final position (rotate 'steps' times)
	MOVQ R12, R13
dec512_advance:
	CMPQ R13, $0
	JE dec512_advance_done

	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	MOVOA X10, X8
	PALIGNR $5, X8, X10
	MOVOA X11, X8
	PALIGNR $10, X8, X11
	MOVOA X12, X8
	PALIGNR $5, X8, X12
	MOVOA X13, X8
	PALIGNR $10, X8, X13

	MOVOU X10, 64(SP)
	MOVOU X11, 80(SP)
	MOVOU X12, 96(SP)
	MOVOU X13, 112(SP)

	DECQ R13
	JMP dec512_advance
dec512_advance_done:

	// fk0-fk3 and their AESIMC versions
	MOVOU 0(SP), X4
	MOVOU 16(SP), X5
	MOVOU 32(SP), X6
	MOVOU 48(SP), X7

	AESIMC X4, X4
	AESIMC X5, X5
	AESIMC X6, X6
	AESIMC X7, X7

	// Load round_key at final position
	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	// Initial XOR and inverse round
	PXOR X10, X0
	PXOR X11, X1
	PXOR X12, X2
	PXOR X13, X3

	AESDEC X4, X0
	AESDEC X5, X1
	AESDEC X6, X2
	AESDEC X7, X3

	// Load extract mask for inverse mixing
	MOVOU extract_mask_512<>(SB), X14

	// Loop: i = steps-1 downto 1
	MOVQ R12, R13
	DECQ R13

dec512_loop:
	CMPQ R13, $1
	JL dec512_loop_end

	// Rotate round_key backward (rotate by 16-5=11 and 16-10=6)
	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	MOVOA X10, X8
	PALIGNR $11, X8, X10
	MOVOA X11, X8
	PALIGNR $6, X8, X11
	MOVOA X12, X8
	PALIGNR $11, X8, X12
	MOVOA X13, X8
	PALIGNR $6, X8, X13

	MOVOU X10, 64(SP)
	MOVOU X11, 80(SP)
	MOVOU X12, 96(SP)
	MOVOU X13, 112(SP)

	// AESDECLAST with round_key
	AESDECLAST X10, X0
	AESDECLAST X11, X1
	AESDECLAST X12, X2
	AESDECLAST X13, X3

	// XOR round constant
	MOVQ R13, R14
	DECQ R14
	SHLQ $4, R14
	ADDQ R9, R14
	MOVOU (R14), X8
	PXOR X8, X0

	// Inverse mixing layer 512:
	// Step 1: Apply extract_mask to each block
	PSHUFB X14, X0
	PSHUFB X14, X1
	PSHUFB X14, X2
	PSHUFB X14, X3

	// Step 2: unpack32 pairs
	MOVOA X0, X8
	MOVOA X1, X9
	PUNPCKLLQ X2, X0      // t0 = unpacklo32(e0, e2)
	PUNPCKHLQ X2, X8      // t1 = unpackhi32(e0, e2)
	PUNPCKLLQ X3, X1      // t2 = unpacklo32(e1, e3)
	PUNPCKHLQ X3, X9      // t3 = unpackhi32(e1, e3)

	// Step 3: unpack64 to get final state
	MOVOA X0, X10
	MOVOA X8, X11
	PUNPCKLQDQ X1, X0     // s0 = unpacklo64(t0, t2)
	PUNPCKHQDQ X1, X10    // s1 = unpackhi64(t0, t2)
	PUNPCKLQDQ X9, X8     // s2 = unpacklo64(t1, t3)
	PUNPCKHQDQ X9, X11    // s3 = unpackhi64(t1, t3)

	MOVOA X10, X1
	MOVOA X8, X2
	MOVOA X11, X3

	// AESIMC and AESDEC
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3

	AESDEC X4, X0
	AESDEC X5, X1
	AESDEC X6, X2
	AESDEC X7, X3

	DECQ R13
	JMP dec512_loop

dec512_loop_end:
	// Final backward rotation
	MOVOU 64(SP), X10
	MOVOU 80(SP), X11
	MOVOU 96(SP), X12
	MOVOU 112(SP), X13

	MOVOA X10, X8
	PALIGNR $11, X8, X10
	MOVOA X11, X8
	PALIGNR $6, X8, X11
	MOVOA X12, X8
	PALIGNR $11, X8, X12
	MOVOA X13, X8
	PALIGNR $6, X8, X13

	// Final AESDECLAST
	AESDECLAST X10, X0
	AESDECLAST X11, X1
	AESDECLAST X12, X2
	AESDECLAST X13, X3

	// Store plaintext
	MOVOU X0, (BX)
	MOVOU X1, 16(BX)
	MOVOU X2, 32(BX)
	MOVOU X3, 48(BX)
	RET
