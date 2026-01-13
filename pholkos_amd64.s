//go:build !purego

#include "textflag.h"

// Pholkos-256 encryption using AES-NI
// func pholkos256EncryptAsm(block *Pholkos256Block, rtk *[17][2]Block)
TEXT ·pholkos256EncryptAsm(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ rtk+8(FP), BX

	// Load state blocks
	MOVOU 0(AX), X0    // s0
	MOVOU 16(AX), X1   // s1

	// Initial round tweakey addition (RTK[0])
	MOVOU 0(BX), X2
	MOVOU 16(BX), X3
	PXOR X2, X0
	PXOR X3, X1

	// Pholkos-256: 8 steps, 2 rounds per step = 16 rounds
	// RTK[1] through RTK[16], final round uses RTK[16]

	// Step 0: rounds 1-2
	MOVOU 32(BX), X2   // RTK[1]
	MOVOU 48(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 64(BX), X2   // RTK[2]
	MOVOU 80(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation π256 (swap odd 32-bit words between s0 and s1)
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0   // s0 gets words 1,3 from s1
	PBLENDW $0xCC, X4, X1   // s1 gets words 1,3 from old s0

	// Step 1: rounds 3-4
	MOVOU 96(BX), X2   // RTK[3]
	MOVOU 112(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 128(BX), X2  // RTK[4]
	MOVOU 144(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 2: rounds 5-6
	MOVOU 160(BX), X2  // RTK[5]
	MOVOU 176(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 192(BX), X2  // RTK[6]
	MOVOU 208(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 3: rounds 7-8
	MOVOU 224(BX), X2  // RTK[7]
	MOVOU 240(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 256(BX), X2  // RTK[8]
	MOVOU 272(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 4: rounds 9-10
	MOVOU 288(BX), X2  // RTK[9]
	MOVOU 304(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 320(BX), X2  // RTK[10]
	MOVOU 336(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 5: rounds 11-12
	MOVOU 352(BX), X2  // RTK[11]
	MOVOU 368(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 384(BX), X2  // RTK[12]
	MOVOU 400(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 6: rounds 13-14
	MOVOU 416(BX), X2  // RTK[13]
	MOVOU 432(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 448(BX), X2  // RTK[14]
	MOVOU 464(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	// Word permutation
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1

	// Step 7 (final): rounds 15-16, no permutation after
	MOVOU 480(BX), X2  // RTK[15]
	MOVOU 496(BX), X3
	AESENC X2, X0
	AESENC X3, X1
	MOVOU 512(BX), X2  // RTK[16] - final round
	MOVOU 528(BX), X3
	AESENCLAST X2, X0
	AESENCLAST X3, X1

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	RET


// Pholkos-256 decryption using AES-NI
// func pholkos256DecryptAsm(block *Pholkos256Block, rtk *[17][2]Block)
TEXT ·pholkos256DecryptAsm(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ rtk+8(FP), BX

	// Load state blocks
	MOVOU 0(AX), X0    // s0
	MOVOU 16(AX), X1   // s1

	// Step 7 (first in reverse): undo rounds 16, 15
	// Round 16 was final round: inverse is XOR key, then InvShiftRows+InvSubBytes
	MOVOU 512(BX), X2  // RTK[16]
	MOVOU 528(BX), X3
	PXOR X2, X0
	PXOR X3, X1

	PXOR X15, X15      // zero register for AESDECLAST with zero key

	// For final round (round 16): we already XORed key above
	// Now do InvShiftRows + InvSubBytes via AESDECLAST with zero
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Round 15: XOR key, InvMC, InvSR, InvSB
	MOVOU 480(BX), X2
	MOVOU 496(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0       // InvMixColumns
	AESIMC X1, X1
	AESDECLAST X15, X0  // InvShiftRows + InvSubBytes
	AESDECLAST X15, X1

	// Step 6 inverse: undo permutation, then rounds 14, 13
	// Inverse permutation is same as forward (swap odd words)
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	// Round 14
	MOVOU 448(BX), X2
	MOVOU 464(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	// Round 13
	MOVOU 416(BX), X2
	MOVOU 432(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 5 inverse
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 384(BX), X2
	MOVOU 400(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 352(BX), X2
	MOVOU 368(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 4 inverse
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 320(BX), X2
	MOVOU 336(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 288(BX), X2
	MOVOU 304(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 3 inverse
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 256(BX), X2
	MOVOU 272(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 224(BX), X2
	MOVOU 240(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 2 inverse
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 192(BX), X2
	MOVOU 208(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 160(BX), X2
	MOVOU 176(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 1 inverse
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 128(BX), X2
	MOVOU 144(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 96(BX), X2
	MOVOU 112(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Step 0 inverse (with permutation to undo)
	MOVOA X0, X4
	PBLENDW $0xCC, X1, X0
	PBLENDW $0xCC, X4, X1
	MOVOU 64(BX), X2
	MOVOU 80(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	MOVOU 32(BX), X2
	MOVOU 48(BX), X3
	PXOR X2, X0
	PXOR X3, X1
	AESIMC X0, X0
	AESIMC X1, X1
	AESDECLAST X15, X0
	AESDECLAST X15, X1

	// Initial round key (RTK[0]) - just XOR
	MOVOU 0(BX), X2
	MOVOU 16(BX), X3
	PXOR X2, X0
	PXOR X3, X1

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	RET


// π512 word permutation for Pholkos-512
// π512 = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
// Input: X0=s0, X1=s1, X2=s2, X3=s3 (each contains 4 32-bit words)
// Output: Permuted state in X0-X3
// Clobbers: X8-X13
//
// Word layout before:
//   X0 = [w0,  w1,  w2,  w3]
//   X1 = [w4,  w5,  w6,  w7]
//   X2 = [w8,  w9,  w10, w11]
//   X3 = [w12, w13, w14, w15]
//
// After permutation:
//   new_X0 = [w0,  w5,  w10, w15]
//   new_X1 = [w4,  w9,  w14, w3]
//   new_X2 = [w8,  w13, w2,  w7]
//   new_X3 = [w12, w1,  w6,  w11]
TEXT pholkos512_permute<>(SB),NOSPLIT,$0
	// Save originals
	MOVOA X0, X8    // X8 = [w0, w1, w2, w3]
	MOVOA X1, X9    // X9 = [w4, w5, w6, w7]
	MOVOA X2, X10   // X10 = [w8, w9, w10, w11]
	MOVOA X3, X11   // X11 = [w12, w13, w14, w15]

	// Build new_X0 = [w0, w5, w10, w15]
	// Create [w0, w1, w10, w11] from X8 and X10
	MOVOA X8, X12
	SHUFPS $0xE4, X10, X12   // X12 = [X8[0], X8[1], X10[2], X10[3]] = [w0, w1, w10, w11]
	// Create [w4, w5, w14, w15] from X9 and X11
	MOVOA X9, X13
	SHUFPS $0xE4, X11, X13   // X13 = [X9[0], X9[1], X11[2], X11[3]] = [w4, w5, w14, w15]
	// Blend to get [w0, w5, w10, w15]: dwords 0,2 from X12, dwords 1,3 from X13
	PBLENDW $0xCC, X13, X12  // X12 = [w0, w5, w10, w15]
	MOVOA X12, X0

	// Build new_X1 = [w4, w9, w14, w3]
	// Create [w4, w5, w2, w3] from X9 and X8
	MOVOA X9, X12
	SHUFPS $0xE4, X8, X12    // X12 = [X9[0], X9[1], X8[2], X8[3]] = [w4, w5, w2, w3]
	// Create [w8, w9, w14, w15] from X10 and X11
	MOVOA X10, X13
	SHUFPS $0xE4, X11, X13   // X13 = [X10[0], X10[1], X11[2], X11[3]] = [w8, w9, w14, w15]
	// Blend to get [w4, w9, w14, w3]: dwords 0,3 from X12, dwords 1,2 from X13
	PBLENDW $0x3C, X13, X12  // X12 = [w4, w9, w14, w3]
	MOVOA X12, X1

	// Build new_X2 = [w8, w13, w2, w7]
	// Create [w8, w9, w6, w7] from X10 and X9
	MOVOA X10, X12
	SHUFPS $0xE4, X9, X12    // X12 = [X10[0], X10[1], X9[2], X9[3]] = [w8, w9, w6, w7]
	// Create [w12, w13, w2, w3] from X11 and X8
	MOVOA X11, X13
	SHUFPS $0xE4, X8, X13    // X13 = [X11[0], X11[1], X8[2], X8[3]] = [w12, w13, w2, w3]
	// Blend to get [w8, w13, w2, w7]: dwords 0,3 from X12, dwords 1,2 from X13
	PBLENDW $0x3C, X13, X12  // X12 = [w8, w13, w2, w7]
	MOVOA X12, X2

	// Build new_X3 = [w12, w1, w6, w11]
	// Create [w12, w13, w10, w11] from X11 and X10
	MOVOA X11, X12
	SHUFPS $0xE4, X10, X12   // X12 = [X11[0], X11[1], X10[2], X10[3]] = [w12, w13, w10, w11]
	// Create [w0, w1, w6, w7] from X8 and X9
	MOVOA X8, X13
	SHUFPS $0xE4, X9, X13    // X13 = [X8[0], X8[1], X9[2], X9[3]] = [w0, w1, w6, w7]
	// Blend to get [w12, w1, w6, w11]: dwords 0,3 from X12, dwords 1,2 from X13
	PBLENDW $0x3C, X13, X12  // X12 = [w12, w1, w6, w11]
	MOVOA X12, X3

	RET


// π512 inverse permutation for Pholkos-512 decryption
// π512^{-1} = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
// Input: X0=s0, X1=s1, X2=s2, X3=s3
// Output: Inverse permuted state in X0-X3
// Clobbers: X8-X13
//
// After inverse permutation:
//   new_X0 = [w0,  w13, w10, w7]
//   new_X1 = [w4,  w1,  w14, w11]
//   new_X2 = [w8,  w5,  w2,  w15]
//   new_X3 = [w12, w9,  w6,  w3]
TEXT pholkos512_inv_permute<>(SB),NOSPLIT,$0
	// Save originals
	MOVOA X0, X8    // X8 = [w0, w1, w2, w3]
	MOVOA X1, X9    // X9 = [w4, w5, w6, w7]
	MOVOA X2, X10   // X10 = [w8, w9, w10, w11]
	MOVOA X3, X11   // X11 = [w12, w13, w14, w15]

	// Build new_X0 = [w0, w13, w10, w7]
	// Create [w0, w1, w10, w11] from X8 and X10
	MOVOA X8, X12
	SHUFPS $0xE4, X10, X12   // X12 = [w0, w1, w10, w11]
	// Create [w12, w13, w6, w7] from X11 and X9
	MOVOA X11, X13
	SHUFPS $0xE4, X9, X13    // X13 = [w12, w13, w6, w7]
	// Blend: dwords 0,2 from X12, dwords 1,3 from X13
	PBLENDW $0xCC, X13, X12  // X12 = [w0, w13, w10, w7]
	MOVOA X12, X0

	// Build new_X1 = [w4, w1, w14, w11]
	// Create [w4, w5, w14, w15] from X9 and X11
	MOVOA X9, X12
	SHUFPS $0xE4, X11, X12   // X12 = [w4, w5, w14, w15]
	// Create [w0, w1, w10, w11] from X8 and X10
	MOVOA X8, X13
	SHUFPS $0xE4, X10, X13   // X13 = [w0, w1, w10, w11]
	// Blend: dwords 0,2 from X12, dwords 1,3 from X13
	PBLENDW $0xCC, X13, X12  // X12 = [w4, w1, w14, w11]
	MOVOA X12, X1

	// Build new_X2 = [w8, w5, w2, w15]
	// Create [w8, w9, w2, w3] from X10 and X8
	MOVOA X10, X12
	SHUFPS $0xE4, X8, X12    // X12 = [w8, w9, w2, w3]
	// Create [w4, w5, w14, w15] from X9 and X11
	MOVOA X9, X13
	SHUFPS $0xE4, X11, X13   // X13 = [w4, w5, w14, w15]
	// Blend: dwords 0,2 from X12, dwords 1,3 from X13
	PBLENDW $0xCC, X13, X12  // X12 = [w8, w5, w2, w15]
	MOVOA X12, X2

	// Build new_X3 = [w12, w9, w6, w3]
	// Create [w12, w13, w6, w7] from X11 and X9
	MOVOA X11, X12
	SHUFPS $0xE4, X9, X12    // X12 = [w12, w13, w6, w7]
	// Create [w8, w9, w2, w3] from X10 and X8
	MOVOA X10, X13
	SHUFPS $0xE4, X8, X13    // X13 = [w8, w9, w2, w3]
	// Blend: dwords 0,2 from X12, dwords 1,3 from X13
	PBLENDW $0xCC, X13, X12  // X12 = [w12, w9, w6, w3]
	MOVOA X12, X3

	RET


// Pholkos-512 encryption using AES-NI
// func pholkos512EncryptAsm(block *Pholkos512Block, rtk *[21][4]Block)
TEXT ·pholkos512EncryptAsm(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ rtk+8(FP), BX

	// Load state blocks
	MOVOU 0(AX), X0    // s0
	MOVOU 16(AX), X1   // s1
	MOVOU 32(AX), X2   // s2
	MOVOU 48(AX), X3   // s3

	// Initial round tweakey addition (RTK[0])
	MOVOU 0(BX), X4
	MOVOU 16(BX), X5
	MOVOU 32(BX), X6
	MOVOU 48(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3

	// Pholkos-512: 10 steps, 2 rounds per step = 20 rounds
	// Each RTK is 64 bytes (4 blocks)
	// RTK offset = rtk_index * 64

	// Step 0: rounds 1-2
	MOVOU 64(BX), X4   // RTK[1]
	MOVOU 80(BX), X5
	MOVOU 96(BX), X6
	MOVOU 112(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 128(BX), X4  // RTK[2]
	MOVOU 144(BX), X5
	MOVOU 160(BX), X6
	MOVOU 176(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	// Word permutation π512
	CALL pholkos512_permute<>(SB)

	// Step 1: rounds 3-4
	MOVOU 192(BX), X4  // RTK[3]
	MOVOU 208(BX), X5
	MOVOU 224(BX), X6
	MOVOU 240(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 256(BX), X4  // RTK[4]
	MOVOU 272(BX), X5
	MOVOU 288(BX), X6
	MOVOU 304(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 2: rounds 5-6
	MOVOU 320(BX), X4  // RTK[5]
	MOVOU 336(BX), X5
	MOVOU 352(BX), X6
	MOVOU 368(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 384(BX), X4  // RTK[6]
	MOVOU 400(BX), X5
	MOVOU 416(BX), X6
	MOVOU 432(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 3: rounds 7-8
	MOVOU 448(BX), X4  // RTK[7]
	MOVOU 464(BX), X5
	MOVOU 480(BX), X6
	MOVOU 496(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 512(BX), X4  // RTK[8]
	MOVOU 528(BX), X5
	MOVOU 544(BX), X6
	MOVOU 560(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 4: rounds 9-10
	MOVOU 576(BX), X4  // RTK[9]
	MOVOU 592(BX), X5
	MOVOU 608(BX), X6
	MOVOU 624(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 640(BX), X4  // RTK[10]
	MOVOU 656(BX), X5
	MOVOU 672(BX), X6
	MOVOU 688(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 5: rounds 11-12
	MOVOU 704(BX), X4  // RTK[11]
	MOVOU 720(BX), X5
	MOVOU 736(BX), X6
	MOVOU 752(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 768(BX), X4  // RTK[12]
	MOVOU 784(BX), X5
	MOVOU 800(BX), X6
	MOVOU 816(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 6: rounds 13-14
	MOVOU 832(BX), X4  // RTK[13]
	MOVOU 848(BX), X5
	MOVOU 864(BX), X6
	MOVOU 880(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 896(BX), X4  // RTK[14]
	MOVOU 912(BX), X5
	MOVOU 928(BX), X6
	MOVOU 944(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 7: rounds 15-16
	MOVOU 960(BX), X4  // RTK[15]
	MOVOU 976(BX), X5
	MOVOU 992(BX), X6
	MOVOU 1008(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 1024(BX), X4 // RTK[16]
	MOVOU 1040(BX), X5
	MOVOU 1056(BX), X6
	MOVOU 1072(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 8: rounds 17-18
	MOVOU 1088(BX), X4 // RTK[17]
	MOVOU 1104(BX), X5
	MOVOU 1120(BX), X6
	MOVOU 1136(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 1152(BX), X4 // RTK[18]
	MOVOU 1168(BX), X5
	MOVOU 1184(BX), X6
	MOVOU 1200(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	CALL pholkos512_permute<>(SB)

	// Step 9 (final): rounds 19-20, no permutation after
	MOVOU 1216(BX), X4 // RTK[19]
	MOVOU 1232(BX), X5
	MOVOU 1248(BX), X6
	MOVOU 1264(BX), X7
	AESENC X4, X0
	AESENC X5, X1
	AESENC X6, X2
	AESENC X7, X3
	MOVOU 1280(BX), X4 // RTK[20] - final round
	MOVOU 1296(BX), X5
	MOVOU 1312(BX), X6
	MOVOU 1328(BX), X7
	AESENCLAST X4, X0
	AESENCLAST X5, X1
	AESENCLAST X6, X2
	AESENCLAST X7, X3

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	RET


// Pholkos-512 decryption using AES-NI
// func pholkos512DecryptAsm(block *Pholkos512Block, rtk *[21][4]Block)
TEXT ·pholkos512DecryptAsm(SB),NOSPLIT,$0
	MOVQ block+0(FP), AX
	MOVQ rtk+8(FP), BX

	// Load state blocks
	MOVOU 0(AX), X0    // s0
	MOVOU 16(AX), X1   // s1
	MOVOU 32(AX), X2   // s2
	MOVOU 48(AX), X3   // s3

	PXOR X15, X15      // zero register

	// Step 9 (first in reverse): undo rounds 20, 19
	// Round 20 final: XOR key, InvSR+InvSB
	MOVOU 1280(BX), X4
	MOVOU 1296(BX), X5
	MOVOU 1312(BX), X6
	MOVOU 1328(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	// Round 19: XOR key, InvMC, InvSR+InvSB
	MOVOU 1216(BX), X4
	MOVOU 1232(BX), X5
	MOVOU 1248(BX), X6
	MOVOU 1264(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 8 inverse: undo permutation, then rounds 18, 17
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 1152(BX), X4
	MOVOU 1168(BX), X5
	MOVOU 1184(BX), X6
	MOVOU 1200(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 1088(BX), X4
	MOVOU 1104(BX), X5
	MOVOU 1120(BX), X6
	MOVOU 1136(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 7 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 1024(BX), X4
	MOVOU 1040(BX), X5
	MOVOU 1056(BX), X6
	MOVOU 1072(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 960(BX), X4
	MOVOU 976(BX), X5
	MOVOU 992(BX), X6
	MOVOU 1008(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 6 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 896(BX), X4
	MOVOU 912(BX), X5
	MOVOU 928(BX), X6
	MOVOU 944(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 832(BX), X4
	MOVOU 848(BX), X5
	MOVOU 864(BX), X6
	MOVOU 880(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 5 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 768(BX), X4
	MOVOU 784(BX), X5
	MOVOU 800(BX), X6
	MOVOU 816(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 704(BX), X4
	MOVOU 720(BX), X5
	MOVOU 736(BX), X6
	MOVOU 752(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 4 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 640(BX), X4
	MOVOU 656(BX), X5
	MOVOU 672(BX), X6
	MOVOU 688(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 576(BX), X4
	MOVOU 592(BX), X5
	MOVOU 608(BX), X6
	MOVOU 624(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 3 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 512(BX), X4
	MOVOU 528(BX), X5
	MOVOU 544(BX), X6
	MOVOU 560(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 448(BX), X4
	MOVOU 464(BX), X5
	MOVOU 480(BX), X6
	MOVOU 496(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 2 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 384(BX), X4
	MOVOU 400(BX), X5
	MOVOU 416(BX), X6
	MOVOU 432(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 320(BX), X4
	MOVOU 336(BX), X5
	MOVOU 352(BX), X6
	MOVOU 368(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 1 inverse
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 256(BX), X4
	MOVOU 272(BX), X5
	MOVOU 288(BX), X6
	MOVOU 304(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 192(BX), X4
	MOVOU 208(BX), X5
	MOVOU 224(BX), X6
	MOVOU 240(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Step 0 inverse (with permutation to undo)
	CALL pholkos512_inv_permute<>(SB)
	MOVOU 128(BX), X4
	MOVOU 144(BX), X5
	MOVOU 160(BX), X6
	MOVOU 176(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3
	MOVOU 64(BX), X4
	MOVOU 80(BX), X5
	MOVOU 96(BX), X6
	MOVOU 112(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3
	AESIMC X0, X0
	AESIMC X1, X1
	AESIMC X2, X2
	AESIMC X3, X3
	AESDECLAST X15, X0
	AESDECLAST X15, X1
	AESDECLAST X15, X2
	AESDECLAST X15, X3

	// Initial round key (RTK[0]) - just XOR
	MOVOU 0(BX), X4
	MOVOU 16(BX), X5
	MOVOU 32(BX), X6
	MOVOU 48(BX), X7
	PXOR X4, X0
	PXOR X5, X1
	PXOR X6, X2
	PXOR X7, X3

	// Store result
	MOVOU X0, 0(AX)
	MOVOU X1, 16(AX)
	MOVOU X2, 32(AX)
	MOVOU X3, 48(AX)
	RET
