package aes

// Vistrutah is a large-block cipher family providing 256-bit and 512-bit block sizes.
// It uses the Generalized Even-Mansour construction based on AES round functions.
// Reference: https://eprint.iacr.org/2024/1534

const (
	Vistrutah256BlockSize = 32
	Vistrutah512BlockSize = 64

	RoundsPerStep = 2

	Vistrutah256RoundsShort       = 10 // 5 steps, for HCTR2/ForkCipher
	Vistrutah256RoundsLong        = 14 // 7 steps, full security
	Vistrutah512RoundsShort256Key = 10 // 256-bit key, 5 steps
	Vistrutah512RoundsShort512Key = 12 // 512-bit key, 6 steps
	Vistrutah512RoundsLong256Key  = 14 // 256-bit key, 7 steps
	Vistrutah512RoundsLong512Key  = 18 // 512-bit key, 9 steps
)

// Round constants for Vistrutah (48 blocks of 16 bytes each, 768 bytes total)
// Derived from digits of pi
var vistrutahRoundConstants = [48]Block{
	{0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44},
	{0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89},
	{0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C},
	{0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17},
	{0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC},
	{0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E, 0x96},
	{0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C, 0xF7},
	{0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E, 0x69},
	{0xA4, 0x58, 0xFE, 0xA3, 0xF4, 0x93, 0x3D, 0x7E, 0x0D, 0x95, 0x74, 0x8F, 0x72, 0x8E, 0xB6, 0x58},
	{0x71, 0x8B, 0xCD, 0x58, 0x82, 0x15, 0x4A, 0xEE, 0x7B, 0x54, 0xA4, 0x1D, 0xC2, 0x5A, 0x59, 0xB5},
	{0x9C, 0x30, 0xD5, 0x39, 0x2A, 0xF2, 0x60, 0x13, 0xC5, 0xD1, 0xB0, 0x23, 0x28, 0x60, 0x85, 0xF0},
	{0xCA, 0x41, 0x79, 0x18, 0xB8, 0xDB, 0x38, 0xEF, 0x8E, 0x79, 0xDC, 0xB0, 0x60, 0x3A, 0x18, 0x0E},
	{0x6C, 0x9E, 0x0E, 0x8B, 0xB0, 0x1E, 0x8A, 0x3E, 0xD7, 0x15, 0x77, 0xC1, 0xBD, 0x31, 0x4B, 0x27},
	{0x78, 0xAF, 0x2F, 0xDA, 0x55, 0x60, 0x5C, 0x60, 0xE6, 0x55, 0x25, 0xF3, 0xAA, 0x55, 0xAB, 0x94},
	{0x57, 0x48, 0x98, 0x62, 0x63, 0xE8, 0x14, 0x40, 0x55, 0xCA, 0x39, 0x6A, 0x2A, 0xAB, 0x10, 0xB6},
	{0xB4, 0xCC, 0x5C, 0x34, 0x11, 0x41, 0xE8, 0xCE, 0xA1, 0x54, 0x86, 0xAF, 0x7C, 0x72, 0xE9, 0x93},
	{0xB3, 0xEE, 0x14, 0x11, 0x63, 0x6F, 0xBC, 0x2A, 0x2B, 0xA9, 0xC5, 0x5D, 0x74, 0x18, 0x31, 0xF6},
	{0xCE, 0x5C, 0x3E, 0x16, 0x9B, 0x87, 0x93, 0x1E, 0xAF, 0xD6, 0xBA, 0x33, 0x6C, 0x24, 0xCF, 0x5C},
	{0x7A, 0x32, 0x53, 0x81, 0x28, 0x95, 0x86, 0x77, 0x3B, 0x8F, 0x48, 0x98, 0x6B, 0x4B, 0xB9, 0xAF},
	{0xC4, 0xBF, 0xE8, 0x1B, 0x66, 0x28, 0x21, 0x93, 0x61, 0xD8, 0x09, 0xCC, 0xFB, 0x21, 0xA9, 0x91},
	{0x48, 0x7C, 0xAC, 0x60, 0x5D, 0xEC, 0x80, 0x32, 0xEF, 0x84, 0x5D, 0x5D, 0xE9, 0x85, 0x75, 0xB1},
	{0xDC, 0x26, 0x23, 0x02, 0xEB, 0x65, 0x1B, 0x88, 0x23, 0x89, 0x3E, 0x81, 0xD3, 0x96, 0xAC, 0xC5},
	{0x0F, 0x6D, 0x6F, 0xF3, 0x83, 0xF4, 0x42, 0x39, 0x2E, 0x0B, 0x44, 0x82, 0xA4, 0x84, 0x20, 0x04},
	{0x69, 0xC8, 0xF0, 0x4A, 0x9E, 0x1F, 0x9B, 0x5E, 0x21, 0xC6, 0x68, 0x42, 0xF6, 0xE9, 0x6C, 0x9A},
	{0x67, 0x0C, 0x9C, 0x61, 0xAB, 0xD3, 0x88, 0xF0, 0x6A, 0x51, 0xA0, 0xD2, 0xD8, 0x54, 0x2F, 0x68},
	{0x96, 0x0F, 0xA7, 0x28, 0xAB, 0x51, 0x33, 0xA3, 0x6E, 0xEF, 0x0B, 0x6C, 0x13, 0x7A, 0x3B, 0xE4},
	{0xBA, 0x3B, 0xF0, 0x50, 0x7E, 0xFB, 0x2A, 0x98, 0xA1, 0xF1, 0x65, 0x1D, 0x39, 0xAF, 0x01, 0x76},
	{0x66, 0xCA, 0x59, 0x3E, 0x82, 0x43, 0x0E, 0x88, 0x8C, 0xEE, 0x86, 0x19, 0x45, 0x6F, 0x9F, 0xB4},
	{0x7D, 0x84, 0xA5, 0xC3, 0x3B, 0x8B, 0x5E, 0xBE, 0xE0, 0x6F, 0x75, 0xD8, 0x85, 0xC1, 0x20, 0x73},
	{0x40, 0x1A, 0x44, 0x9F, 0x56, 0xC1, 0x6A, 0xA6, 0x4E, 0xD3, 0xAA, 0x62, 0x36, 0x3F, 0x77, 0x06},
	{0x1B, 0xFE, 0xDF, 0x72, 0x42, 0x9B, 0x02, 0x3D, 0x37, 0xD0, 0xD7, 0x24, 0xD0, 0x0A, 0x12, 0x48},
	{0xDB, 0x0F, 0xEA, 0xD3, 0x49, 0xF1, 0xC0, 0x9B, 0x07, 0x53, 0x72, 0xC9, 0x80, 0x99, 0x1B, 0x7B},
	{0x25, 0xD4, 0x79, 0xD8, 0xF6, 0xE8, 0xDE, 0xF7, 0xE3, 0xFE, 0x50, 0x1A, 0xB6, 0x79, 0x4C, 0x3B},
	{0x97, 0x6C, 0xE0, 0xBD, 0x04, 0xC0, 0x06, 0xBA, 0xC1, 0xA9, 0x4F, 0xB6, 0x40, 0x9F, 0x60, 0xC4},
	{0x5E, 0x5C, 0x9E, 0xC2, 0x19, 0x6A, 0x24, 0x63, 0x68, 0xFB, 0x6F, 0xAF, 0x3E, 0x6C, 0x53, 0xB5},
	{0x13, 0x39, 0xB2, 0xEB, 0x3B, 0x52, 0xEC, 0x6F, 0x6D, 0xFC, 0x51, 0x1F, 0x9B, 0x30, 0x95, 0x2C},
	{0xCC, 0x81, 0x45, 0x44, 0xAF, 0x5E, 0xBD, 0x09, 0xBE, 0xE3, 0xD0, 0x04, 0xDE, 0x33, 0x4A, 0xFD},
	{0x66, 0x0F, 0x28, 0x07, 0x19, 0x2E, 0x4B, 0xB3, 0xC0, 0xCB, 0xA8, 0x57, 0x45, 0xC8, 0x74, 0x0F},
	{0xD2, 0x0B, 0x5F, 0x39, 0xB9, 0xD3, 0xFB, 0xDB, 0x55, 0x79, 0xC0, 0xBD, 0x1A, 0x60, 0x32, 0x0A},
	{0xD6, 0xA1, 0x00, 0xC6, 0x40, 0x2C, 0x72, 0x79, 0x67, 0x9F, 0x25, 0xFE, 0xFB, 0x1F, 0xA3, 0xCC},
	{0x8E, 0xA5, 0xE9, 0xF8, 0xDB, 0x32, 0x22, 0xF8, 0x3C, 0x75, 0x16, 0xDF, 0xFD, 0x61, 0x6B, 0x15},
	{0x2F, 0x50, 0x1E, 0xC8, 0xAD, 0x05, 0x52, 0xAB, 0x32, 0x3D, 0xB5, 0xFA, 0xFD, 0x23, 0x87, 0x60},
	{0x53, 0x31, 0x7B, 0x48, 0x3E, 0x00, 0xDF, 0x82, 0x9E, 0x5C, 0x57, 0xBB, 0xCA, 0x6F, 0x8C, 0xA0},
	{0x1A, 0x87, 0x56, 0x2E, 0xDF, 0x17, 0x69, 0xDB, 0xD5, 0x42, 0xA8, 0xF6, 0x28, 0x7E, 0xFF, 0xC3},
	{0xAC, 0x67, 0x32, 0xC6, 0x8C, 0x4F, 0x55, 0x73, 0x69, 0x5B, 0x27, 0xB0, 0xBB, 0xCA, 0x58, 0xC8},
	{0xE1, 0xFF, 0xA3, 0x5D, 0xB8, 0xF0, 0x11, 0xA0, 0x10, 0xFA, 0x3D, 0x98, 0xFD, 0x21, 0x83, 0xB8},
	{0x4A, 0xFC, 0xB5, 0x6C, 0x2D, 0xD1, 0xD3, 0x5B, 0x9A, 0x53, 0xE4, 0x79, 0xB6, 0xF8, 0x45, 0x65},
	{0xD2, 0x8E, 0x49, 0xBC, 0x4B, 0xFB, 0x97, 0x90, 0xE1, 0xDD, 0xF2, 0xDA, 0xA4, 0xCB, 0x7E, 0x33},
}

// Permutation tables for Vistrutah-256 key schedule
var (
	vistrutahP4 = [16]byte{9, 7, 13, 14, 0, 10, 3, 5, 1, 2, 15, 4, 6, 12, 11, 8}
	vistrutahP5 = [16]byte{12, 8, 1, 9, 15, 4, 0, 3, 14, 10, 6, 7, 2, 5, 13, 11}
)

// Inverse permutation tables for decryption
var (
	vistrutahP4Inv = [16]byte{4, 8, 9, 6, 11, 7, 12, 1, 15, 0, 5, 14, 13, 2, 3, 10}
	vistrutahP5Inv = [16]byte{6, 2, 12, 7, 5, 13, 10, 11, 1, 3, 9, 15, 0, 14, 8, 4}
)

// Key expansion shuffle permutation for Vistrutah-512
var vistrutahKexpShuffle = [32]byte{
	30, 29, 8, 23, 10, 9, 20, 3, 22, 21, 0,
	31, 2, 1, 28, 11, 14, 13, 24, 7, 26, 25,
	4, 19, 6, 5, 16, 15, 18, 17, 12, 27,
}

// Mixing layer index tables for Vistrutah-512 (for ARM64 TBL4 instruction)
var (
	vistrutah512MixIdx0 = [16]byte{0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51}
	vistrutah512MixIdx1 = [16]byte{8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59}
	vistrutah512MixIdx2 = [16]byte{4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55}
	vistrutah512MixIdx3 = [16]byte{12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63}
)

// Inverse mixing layer index tables for Vistrutah-512
var (
	vistrutah512InvMixIdx0 = [16]byte{0, 4, 8, 12, 32, 36, 40, 44, 16, 20, 24, 28, 48, 52, 56, 60}
	vistrutah512InvMixIdx1 = [16]byte{1, 5, 9, 13, 33, 37, 41, 45, 17, 21, 25, 29, 49, 53, 57, 61}
	vistrutah512InvMixIdx2 = [16]byte{2, 6, 10, 14, 34, 38, 42, 46, 18, 22, 26, 30, 50, 54, 58, 62}
	vistrutah512InvMixIdx3 = [16]byte{3, 7, 11, 15, 35, 39, 43, 47, 19, 23, 27, 31, 51, 55, 59, 63}
)

// vistrutahApplyPerm applies a 16-byte permutation to data
func vistrutahApplyPerm(perm *[16]byte, data *Block) {
	var result Block
	for i := 0; i < 16; i++ {
		result[i] = data[perm[i]]
	}
	*data = result
}

// vistrutahRotateBytes rotates a 16-byte array left by shift positions
func vistrutahRotateBytes(data *Block, shift int) {
	if shift == 0 || shift >= 16 {
		return
	}
	var result Block
	for i := 0; i < 16; i++ {
		result[i] = data[(i+shift)%16]
	}
	*data = result
}

// mixingLayer256 applies the ASURA permutation for Vistrutah-256
func mixingLayer256(s0, s1 *Block) {
	var t0, t1 Block

	// Reorganize each slice to [evens, odds]
	for i := 0; i < 8; i++ {
		t0[i] = s0[i*2]
		t0[i+8] = s0[i*2+1]
		t1[i] = s1[i*2]
		t1[i+8] = s1[i*2+1]
	}

	// Swap upper half of t0 with lower half of t1
	for i := 0; i < 8; i++ {
		s0[i] = t0[i]
		s0[i+8] = t1[i]
		s1[i] = t0[i+8]
		s1[i+8] = t1[i+8]
	}
}

// invMixingLayer256 applies the inverse ASURA permutation
func invMixingLayer256(s0, s1 *Block) {
	var slice0, slice1 Block

	// Reverse the unpack operations
	for i := 0; i < 8; i++ {
		slice0[i] = s0[i]
		slice0[i+8] = s1[i]
		slice1[i] = s0[i+8]
		slice1[i+8] = s1[i+8]
	}

	// Apply inverse of reorganization
	for i := 0; i < 8; i++ {
		s0[i*2] = slice0[i]
		s0[i*2+1] = slice0[i+8]
		s1[i*2] = slice1[i]
		s1[i*2+1] = slice1[i+8]
	}
}

// mixingLayer512 applies the 4x4 transpose mixing for Vistrutah-512
// This implements _mm_unpacklo/hi_epi8 followed by _mm_unpacklo/hi_epi16
func mixingLayer512(s0, s1, s2, s3 *Block) {
	var lo01, hi01, lo23, hi23 Block

	// Step 1: unpacklo/hi_epi8 - interleave bytes
	// lo01 = interleave low 8 bytes of s0 and s1
	// hi01 = interleave high 8 bytes of s0 and s1
	for i := 0; i < 8; i++ {
		lo01[i*2] = s0[i]
		lo01[i*2+1] = s1[i]
		hi01[i*2] = s0[i+8]
		hi01[i*2+1] = s1[i+8]
		lo23[i*2] = s2[i]
		lo23[i*2+1] = s3[i]
		hi23[i*2] = s2[i+8]
		hi23[i*2+1] = s3[i+8]
	}

	// Step 2: unpacklo/hi_epi16 - interleave 16-bit words
	// s0 = unpacklo_epi16(lo01, lo23) - interleave low 4 16-bit words
	// s2 = unpackhi_epi16(lo01, lo23) - interleave high 4 16-bit words
	// s1 = unpacklo_epi16(hi01, hi23)
	// s3 = unpackhi_epi16(hi01, hi23)
	for i := 0; i < 4; i++ {
		// unpacklo_epi16: takes 16-bit words 0,1,2,3 from each input
		s0[i*4] = lo01[i*2]
		s0[i*4+1] = lo01[i*2+1]
		s0[i*4+2] = lo23[i*2]
		s0[i*4+3] = lo23[i*2+1]

		// unpackhi_epi16: takes 16-bit words 4,5,6,7 from each input
		s2[i*4] = lo01[i*2+8]
		s2[i*4+1] = lo01[i*2+9]
		s2[i*4+2] = lo23[i*2+8]
		s2[i*4+3] = lo23[i*2+9]

		s1[i*4] = hi01[i*2]
		s1[i*4+1] = hi01[i*2+1]
		s1[i*4+2] = hi23[i*2]
		s1[i*4+3] = hi23[i*2+1]

		s3[i*4] = hi01[i*2+8]
		s3[i*4+1] = hi01[i*2+9]
		s3[i*4+2] = hi23[i*2+8]
		s3[i*4+3] = hi23[i*2+9]
	}
}

// invMixingLayer512 applies the inverse 512-bit mixing layer
// This implements the shuffle + unpack operations from the C code
func invMixingLayer512(s0, s1, s2, s3 *Block) {
	var e0, e1, e2, e3 Block

	// Extract: reorder bytes within each block using the extract_mask
	// _mm_set_epi8(15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0)
	// Note: _mm_set_epi8 sets bytes in reverse order, so:
	// extractMask = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
	extractMask := [16]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	for i := 0; i < 16; i++ {
		e0[i] = s0[extractMask[i]]
		e1[i] = s1[extractMask[i]]
		e2[i] = s2[extractMask[i]]
		e3[i] = s3[extractMask[i]]
	}

	// unpacklo/hi_epi32: interleave 32-bit words
	// t0 = unpacklo_epi32(e0, e2) - interleave low 2 32-bit dwords
	// t1 = unpackhi_epi32(e0, e2) - interleave high 2 32-bit dwords
	// t2 = unpacklo_epi32(e1, e3)
	// t3 = unpackhi_epi32(e1, e3)
	var t0, t1, t2, t3 Block
	for i := 0; i < 2; i++ {
		// unpacklo_epi32: takes 32-bit words 0,1 from each input
		t0[i*8] = e0[i*4]
		t0[i*8+1] = e0[i*4+1]
		t0[i*8+2] = e0[i*4+2]
		t0[i*8+3] = e0[i*4+3]
		t0[i*8+4] = e2[i*4]
		t0[i*8+5] = e2[i*4+1]
		t0[i*8+6] = e2[i*4+2]
		t0[i*8+7] = e2[i*4+3]

		// unpackhi_epi32: takes 32-bit words 2,3 from each input
		t1[i*8] = e0[i*4+8]
		t1[i*8+1] = e0[i*4+9]
		t1[i*8+2] = e0[i*4+10]
		t1[i*8+3] = e0[i*4+11]
		t1[i*8+4] = e2[i*4+8]
		t1[i*8+5] = e2[i*4+9]
		t1[i*8+6] = e2[i*4+10]
		t1[i*8+7] = e2[i*4+11]

		t2[i*8] = e1[i*4]
		t2[i*8+1] = e1[i*4+1]
		t2[i*8+2] = e1[i*4+2]
		t2[i*8+3] = e1[i*4+3]
		t2[i*8+4] = e3[i*4]
		t2[i*8+5] = e3[i*4+1]
		t2[i*8+6] = e3[i*4+2]
		t2[i*8+7] = e3[i*4+3]

		t3[i*8] = e1[i*4+8]
		t3[i*8+1] = e1[i*4+9]
		t3[i*8+2] = e1[i*4+10]
		t3[i*8+3] = e1[i*4+11]
		t3[i*8+4] = e3[i*4+8]
		t3[i*8+5] = e3[i*4+9]
		t3[i*8+6] = e3[i*4+10]
		t3[i*8+7] = e3[i*4+11]
	}

	// unpacklo/hi_epi64: interleave 64-bit quadwords
	// s0 = unpacklo_epi64(t0, t2)
	// s1 = unpackhi_epi64(t0, t2)
	// s2 = unpacklo_epi64(t1, t3)
	// s3 = unpackhi_epi64(t1, t3)
	for i := 0; i < 8; i++ {
		s0[i] = t0[i]
		s0[i+8] = t2[i]
		s1[i] = t0[i+8]
		s1[i+8] = t2[i+8]
		s2[i] = t1[i]
		s2[i+8] = t3[i]
		s3[i] = t1[i+8]
		s3[i+8] = t3[i+8]
	}
}

// Vistrutah256Encrypt encrypts a 32-byte plaintext block using Vistrutah-256.
// Key must be 16 or 32 bytes. Rounds should be Vistrutah256RoundsShort (10) or Vistrutah256RoundsLong (14).
func Vistrutah256Encrypt(plaintext, ciphertext, key []byte, rounds int) {
	if len(plaintext) != 32 || len(ciphertext) != 32 {
		panic("vistrutah256: plaintext and ciphertext must be 32 bytes")
	}
	if len(key) != 16 && len(key) != 32 {
		panic("vistrutah256: key must be 16 or 32 bytes")
	}
	if rounds%RoundsPerStep != 0 || rounds < 2 {
		panic("vistrutah256: rounds must be even and >= 2")
	}

	var fixedKey [32]byte
	var roundKey [32]byte
	steps := rounds / RoundsPerStep

	var s0, s1 Block
	copy(s0[:], plaintext[:16])
	copy(s1[:], plaintext[16:32])

	if len(key) == 16 {
		copy(fixedKey[:16], key)
		copy(fixedKey[16:], key)
	} else {
		copy(fixedKey[:], key)
	}

	// Initialize round key: swap halves
	copy(roundKey[:16], fixedKey[16:32])
	copy(roundKey[16:], fixedKey[:16])

	var fk0, fk1 Block
	copy(fk0[:], fixedKey[:16])
	copy(fk1[:], fixedKey[16:32])

	var rk0, rk1 Block
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])

	// Initial XOR and first AES round
	xorBlocks(&s0, &rk0)
	xorBlocks(&s1, &rk1)
	Round(&s0, &fk0)
	Round(&s1, &fk1)

	// Main loop
	var zero Block
	for i := 1; i < steps; i++ {
		// AES round with zero key
		Round(&s0, &zero)
		Round(&s1, &zero)

		// Mixing layer
		mixingLayer256(&s0, &s1)

		// Permute round keys
		copy(rk0[:], roundKey[:16])
		copy(rk1[:], roundKey[16:32])
		vistrutahApplyPerm(&vistrutahP4, &rk0)
		vistrutahApplyPerm(&vistrutahP5, &rk1)
		copy(roundKey[:16], rk0[:])
		copy(roundKey[16:], rk1[:])

		// XOR state with round keys
		xorBlocks(&s0, &rk0)
		xorBlocks(&s1, &rk1)

		// XOR round constant with s0
		xorBlocks(&s0, &vistrutahRoundConstants[i-1])

		// AES round with fixed key
		Round(&s0, &fk0)
		Round(&s1, &fk1)
	}

	// Final permutation
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	vistrutahApplyPerm(&vistrutahP4, &rk0)
	vistrutahApplyPerm(&vistrutahP5, &rk1)

	// Final AES round (no MixColumns)
	FinalRound(&s0, &rk0)
	FinalRound(&s1, &rk1)

	copy(ciphertext[:16], s0[:])
	copy(ciphertext[16:], s1[:])
}

// Vistrutah256Decrypt decrypts a 32-byte ciphertext block using Vistrutah-256.
func Vistrutah256Decrypt(ciphertext, plaintext, key []byte, rounds int) {
	if len(plaintext) != 32 || len(ciphertext) != 32 {
		panic("vistrutah256: plaintext and ciphertext must be 32 bytes")
	}
	if len(key) != 16 && len(key) != 32 {
		panic("vistrutah256: key must be 16 or 32 bytes")
	}
	if rounds%RoundsPerStep != 0 || rounds < 2 {
		panic("vistrutah256: rounds must be even and >= 2")
	}

	var fixedKey [32]byte
	var roundKey [32]byte
	steps := rounds / RoundsPerStep

	var s0, s1 Block
	copy(s0[:], ciphertext[:16])
	copy(s1[:], ciphertext[16:32])

	if len(key) == 16 {
		copy(fixedKey[:16], key)
		copy(fixedKey[16:], key)
	} else {
		copy(fixedKey[:], key)
	}

	// Initialize round key: swap halves
	copy(roundKey[:16], fixedKey[16:32])
	copy(roundKey[16:], fixedKey[:16])

	// Advance round keys to final state
	var rk0, rk1 Block
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	for i := 0; i < steps; i++ {
		vistrutahApplyPerm(&vistrutahP4, &rk0)
		vistrutahApplyPerm(&vistrutahP5, &rk1)
	}
	copy(roundKey[:16], rk0[:])
	copy(roundKey[16:], rk1[:])

	var fk0, fk1 Block
	copy(fk0[:], fixedKey[:16])
	copy(fk1[:], fixedKey[16:32])

	// Apply InvMixColumns to fixed keys for use with aesdec
	fk0Imc := fk0
	fk1Imc := fk1
	InvMixColumns(&fk0Imc)
	InvMixColumns(&fk1Imc)

	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])

	// Initial XOR and first inverse AES round
	xorBlocks(&s0, &rk0)
	xorBlocks(&s1, &rk1)
	InvRound(&s0, &fk0Imc)
	InvRound(&s1, &fk1Imc)

	// Main loop (backwards)
	for i := steps - 1; i >= 1; i-- {
		// Inverse permute round keys
		copy(rk0[:], roundKey[:16])
		copy(rk1[:], roundKey[16:32])
		vistrutahApplyPerm(&vistrutahP4Inv, &rk0)
		vistrutahApplyPerm(&vistrutahP5Inv, &rk1)
		copy(roundKey[:16], rk0[:])
		copy(roundKey[16:], rk1[:])

		// Inverse final round (SubBytes/ShiftRows only)
		InvFinalRound(&s0, &rk0)
		InvFinalRound(&s1, &rk1)

		// XOR round constant
		xorBlocks(&s0, &vistrutahRoundConstants[i-1])

		// Inverse mixing layer
		invMixingLayer256(&s0, &s1)

		// Apply InvMixColumns to state
		InvMixColumns(&s0)
		InvMixColumns(&s1)

		// Inverse AES round
		InvRound(&s0, &fk0Imc)
		InvRound(&s1, &fk1Imc)
	}

	// Final inverse permutation
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	vistrutahApplyPerm(&vistrutahP4Inv, &rk0)
	vistrutahApplyPerm(&vistrutahP5Inv, &rk1)

	// Final inverse round
	InvFinalRound(&s0, &rk0)
	InvFinalRound(&s1, &rk1)

	copy(plaintext[:16], s0[:])
	copy(plaintext[16:], s1[:])
}

// Vistrutah512Encrypt encrypts a 64-byte plaintext block using Vistrutah-512.
// Key must be 32 or 64 bytes.
func Vistrutah512Encrypt(plaintext, ciphertext, key []byte, rounds int) {
	if len(plaintext) != 64 || len(ciphertext) != 64 {
		panic("vistrutah512: plaintext and ciphertext must be 64 bytes")
	}
	if len(key) != 32 && len(key) != 64 {
		panic("vistrutah512: key must be 32 or 64 bytes")
	}
	if rounds%RoundsPerStep != 0 || rounds < 2 {
		panic("vistrutah512: rounds must be even and >= 2")
	}

	var fixedKey [64]byte
	var roundKey [64]byte
	steps := rounds / RoundsPerStep

	var s0, s1, s2, s3 Block
	copy(s0[:], plaintext[:16])
	copy(s1[:], plaintext[16:32])
	copy(s2[:], plaintext[32:48])
	copy(s3[:], plaintext[48:64])

	if len(key) == 32 {
		copy(fixedKey[:32], key)
		copy(fixedKey[32:], key)
	} else {
		copy(fixedKey[:], key)
	}

	// Apply KEXP shuffle to second half
	var temp [32]byte
	copy(temp[:], fixedKey[32:64])
	for i := 0; i < 32; i++ {
		fixedKey[32+i] = temp[vistrutahKexpShuffle[i]]
	}

	// Initialize round key: interleave halves
	copy(roundKey[:16], fixedKey[16:32])
	copy(roundKey[16:32], fixedKey[:16])
	copy(roundKey[32:48], fixedKey[48:64])
	copy(roundKey[48:64], fixedKey[32:48])

	var fk0, fk1, fk2, fk3 Block
	copy(fk0[:], fixedKey[:16])
	copy(fk1[:], fixedKey[16:32])
	copy(fk2[:], fixedKey[32:48])
	copy(fk3[:], fixedKey[48:64])

	var rk0, rk1, rk2, rk3 Block
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	copy(rk2[:], roundKey[32:48])
	copy(rk3[:], roundKey[48:64])

	// Initial XOR and first AES round
	xorBlocks(&s0, &rk0)
	xorBlocks(&s1, &rk1)
	xorBlocks(&s2, &rk2)
	xorBlocks(&s3, &rk3)

	Round(&s0, &fk0)
	Round(&s1, &fk1)
	Round(&s2, &fk2)
	Round(&s3, &fk3)

	// Main loop
	var zero Block
	for i := 1; i < steps; i++ {
		// AES round with zero key
		Round(&s0, &zero)
		Round(&s1, &zero)
		Round(&s2, &zero)
		Round(&s3, &zero)

		// Mixing layer
		mixingLayer512(&s0, &s1, &s2, &s3)

		// Rotate round keys
		copy(rk0[:], roundKey[:16])
		copy(rk1[:], roundKey[16:32])
		copy(rk2[:], roundKey[32:48])
		copy(rk3[:], roundKey[48:64])
		vistrutahRotateBytes(&rk0, 5)
		vistrutahRotateBytes(&rk1, 10)
		vistrutahRotateBytes(&rk2, 5)
		vistrutahRotateBytes(&rk3, 10)
		copy(roundKey[:16], rk0[:])
		copy(roundKey[16:32], rk1[:])
		copy(roundKey[32:48], rk2[:])
		copy(roundKey[48:64], rk3[:])

		// XOR state with round keys
		xorBlocks(&s0, &rk0)
		xorBlocks(&s1, &rk1)
		xorBlocks(&s2, &rk2)
		xorBlocks(&s3, &rk3)

		// XOR round constant with s0
		xorBlocks(&s0, &vistrutahRoundConstants[i-1])

		// AES round with fixed key
		Round(&s0, &fk0)
		Round(&s1, &fk1)
		Round(&s2, &fk2)
		Round(&s3, &fk3)
	}

	// Final rotation
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	copy(rk2[:], roundKey[32:48])
	copy(rk3[:], roundKey[48:64])
	vistrutahRotateBytes(&rk0, 5)
	vistrutahRotateBytes(&rk1, 10)
	vistrutahRotateBytes(&rk2, 5)
	vistrutahRotateBytes(&rk3, 10)

	// Final AES round (no MixColumns)
	FinalRound(&s0, &rk0)
	FinalRound(&s1, &rk1)
	FinalRound(&s2, &rk2)
	FinalRound(&s3, &rk3)

	copy(ciphertext[:16], s0[:])
	copy(ciphertext[16:32], s1[:])
	copy(ciphertext[32:48], s2[:])
	copy(ciphertext[48:64], s3[:])
}

// Vistrutah512Decrypt decrypts a 64-byte ciphertext block using Vistrutah-512.
func Vistrutah512Decrypt(ciphertext, plaintext, key []byte, rounds int) {
	if len(plaintext) != 64 || len(ciphertext) != 64 {
		panic("vistrutah512: plaintext and ciphertext must be 64 bytes")
	}
	if len(key) != 32 && len(key) != 64 {
		panic("vistrutah512: key must be 32 or 64 bytes")
	}
	if rounds%RoundsPerStep != 0 || rounds < 2 {
		panic("vistrutah512: rounds must be even and >= 2")
	}

	var fixedKey [64]byte
	var roundKey [64]byte
	steps := rounds / RoundsPerStep

	var s0, s1, s2, s3 Block
	copy(s0[:], ciphertext[:16])
	copy(s1[:], ciphertext[16:32])
	copy(s2[:], ciphertext[32:48])
	copy(s3[:], ciphertext[48:64])

	if len(key) == 32 {
		copy(fixedKey[:32], key)
		copy(fixedKey[32:], key)
	} else {
		copy(fixedKey[:], key)
	}

	// Apply KEXP shuffle to second half
	var temp [32]byte
	copy(temp[:], fixedKey[32:64])
	for i := 0; i < 32; i++ {
		fixedKey[32+i] = temp[vistrutahKexpShuffle[i]]
	}

	// Initialize round key: interleave halves
	copy(roundKey[:16], fixedKey[16:32])
	copy(roundKey[16:32], fixedKey[:16])
	copy(roundKey[32:48], fixedKey[48:64])
	copy(roundKey[48:64], fixedKey[32:48])

	// Advance round keys to final state
	var rk0, rk1, rk2, rk3 Block
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	copy(rk2[:], roundKey[32:48])
	copy(rk3[:], roundKey[48:64])
	for i := 0; i < steps; i++ {
		vistrutahRotateBytes(&rk0, 5)
		vistrutahRotateBytes(&rk1, 10)
		vistrutahRotateBytes(&rk2, 5)
		vistrutahRotateBytes(&rk3, 10)
	}
	copy(roundKey[:16], rk0[:])
	copy(roundKey[16:32], rk1[:])
	copy(roundKey[32:48], rk2[:])
	copy(roundKey[48:64], rk3[:])

	var fk0, fk1, fk2, fk3 Block
	copy(fk0[:], fixedKey[:16])
	copy(fk1[:], fixedKey[16:32])
	copy(fk2[:], fixedKey[32:48])
	copy(fk3[:], fixedKey[48:64])

	// Apply InvMixColumns to fixed keys
	fk0Imc := fk0
	fk1Imc := fk1
	fk2Imc := fk2
	fk3Imc := fk3
	InvMixColumns(&fk0Imc)
	InvMixColumns(&fk1Imc)
	InvMixColumns(&fk2Imc)
	InvMixColumns(&fk3Imc)

	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	copy(rk2[:], roundKey[32:48])
	copy(rk3[:], roundKey[48:64])

	// Initial XOR and first inverse AES round
	xorBlocks(&s0, &rk0)
	xorBlocks(&s1, &rk1)
	xorBlocks(&s2, &rk2)
	xorBlocks(&s3, &rk3)

	InvRound(&s0, &fk0Imc)
	InvRound(&s1, &fk1Imc)
	InvRound(&s2, &fk2Imc)
	InvRound(&s3, &fk3Imc)

	// Main loop (backwards)
	for i := steps - 1; i >= 1; i-- {
		// Inverse rotate round keys (rotate backward = rotate forward by 16-shift)
		copy(rk0[:], roundKey[:16])
		copy(rk1[:], roundKey[16:32])
		copy(rk2[:], roundKey[32:48])
		copy(rk3[:], roundKey[48:64])
		vistrutahRotateBytes(&rk0, 16-5)
		vistrutahRotateBytes(&rk1, 16-10)
		vistrutahRotateBytes(&rk2, 16-5)
		vistrutahRotateBytes(&rk3, 16-10)
		copy(roundKey[:16], rk0[:])
		copy(roundKey[16:32], rk1[:])
		copy(roundKey[32:48], rk2[:])
		copy(roundKey[48:64], rk3[:])

		// Inverse final round
		InvFinalRound(&s0, &rk0)
		InvFinalRound(&s1, &rk1)
		InvFinalRound(&s2, &rk2)
		InvFinalRound(&s3, &rk3)

		// XOR round constant
		xorBlocks(&s0, &vistrutahRoundConstants[i-1])

		// Inverse mixing layer
		invMixingLayer512(&s0, &s1, &s2, &s3)

		// Apply InvMixColumns to state
		InvMixColumns(&s0)
		InvMixColumns(&s1)
		InvMixColumns(&s2)
		InvMixColumns(&s3)

		// Inverse AES round
		InvRound(&s0, &fk0Imc)
		InvRound(&s1, &fk1Imc)
		InvRound(&s2, &fk2Imc)
		InvRound(&s3, &fk3Imc)
	}

	// Final inverse rotation
	copy(rk0[:], roundKey[:16])
	copy(rk1[:], roundKey[16:32])
	copy(rk2[:], roundKey[32:48])
	copy(rk3[:], roundKey[48:64])
	vistrutahRotateBytes(&rk0, 16-5)
	vistrutahRotateBytes(&rk1, 16-10)
	vistrutahRotateBytes(&rk2, 16-5)
	vistrutahRotateBytes(&rk3, 16-10)

	// Final inverse round
	InvFinalRound(&s0, &rk0)
	InvFinalRound(&s1, &rk1)
	InvFinalRound(&s2, &rk2)
	InvFinalRound(&s3, &rk3)

	copy(plaintext[:16], s0[:])
	copy(plaintext[16:32], s1[:])
	copy(plaintext[32:48], s2[:])
	copy(plaintext[48:64], s3[:])
}
