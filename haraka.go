package aes

import (
	"encoding/binary"
)

// Haraka v2 round constants derived from the digits of pi.
// Each 128-bit constant is stored as 4 uint32 values in little-endian order.
// _mm_set_epi32(a, b, c, d) maps to [d, c, b, a] in memory (d is lowest address).
// Haraka-256 uses 20 constants (indices 0-19), Haraka-512 uses 40 (indices 0-39).
var harakaRC = [40][4]uint32{
	{0x75817b9d, 0xb2c5fef0, 0xe620c00a, 0x0684704c}, // rc[0]
	{0x2f08f717, 0x640f6ba4, 0x88f3a06b, 0x8b66b4e1}, // rc[1]
	{0x9f029114, 0xcf029d60, 0x53f28498, 0x3402de2d}, // rc[2]
	{0xfd5b4f79, 0xbbf3bcaf, 0x2e7b4f08, 0x0ed6eae6}, // rc[3]
	{0xbe397044, 0x79eecd1c, 0x4872448b, 0xcbcfb0cb}, // rc[4]
	{0x2b8a057b, 0x8d5335ed, 0x6e9032b7, 0x7eeacdee}, // rc[5]
	{0xda4fef1b, 0xe2412761, 0x5e2e7cd0, 0x67c28f43}, // rc[6]
	{0x1fc70b3b, 0x675ffde2, 0xafcacc07, 0x2924d9b0}, // rc[7]
	{0xb9d465ee, 0xecdb8fca, 0xe6867fe9, 0xab4d63f1}, // rc[8]
	{0xad037e33, 0x5b2a404f, 0xd4b7cd64, 0x1c30bf84}, // rc[9]
	{0x8df69800, 0x69028b2e, 0x941723bf, 0xb2cc0bb9}, // rc[10]
	{0x5c9d2d8a, 0x4aaa9ec8, 0xde6f5572, 0xfa0478a6}, // rc[11]
	{0x29129fd4, 0x0efa4f2e, 0x6b772a12, 0xdfb49f2b}, // rc[12]
	{0xbb6a12ee, 0x32d611ae, 0xf449a236, 0x1ea10344}, // rc[13]
	{0x9ca8eca6, 0x5f9600c9, 0x4b050084, 0xaf044988}, // rc[14]
	{0x27e593ec, 0x78a2c7e3, 0x9d199c4f, 0x21025ed8}, // rc[15]
	{0x82d40173, 0xb9282ecd, 0xa759c9b7, 0xbf3aaaf8}, // rc[16]
	{0x10307d6b, 0x37f2efd9, 0x6186b017, 0x6260700d}, // rc[17]
	{0xf6fc9ac6, 0x81c29153, 0x21300443, 0x5aca45c2}, // rc[18]
	{0x36d1943a, 0x2caf92e8, 0x226b68bb, 0x9223973c}, // rc[19]
	{0xe51071b4, 0x6cbab958, 0x225886eb, 0xd3bf9238}, // rc[20]
	{0x24e1128d, 0x933dfddd, 0xaef0c677, 0xdb863ce5}, // rc[21]
	{0xcb2212b1, 0x83e48de3, 0xffeba09c, 0xbb606268}, // rc[22]
	{0xc72bf77d, 0x2db91a4e, 0xe2e4d19c, 0x734bd3dc}, // rc[23]
	{0x2cb3924e, 0x4b1415c4, 0x61301b43, 0x43bb47c3}, // rc[24]
	{0x16eb6899, 0x03b231dd, 0xe707eff6, 0xdba775a8}, // rc[25]
	{0x7eca472c, 0x8e5e2302, 0x3c755977, 0x6df3614b}, // rc[26]
	{0xb88617f9, 0x6d1be5b9, 0xd6de7d77, 0xcda75a17}, // rc[27]
	{0xa946ee5d, 0x9d6c069d, 0x6ba8e9aa, 0xec6b43f0}, // rc[28]
	{0x3bf327c1, 0xa2531159, 0xf957332b, 0xcb1e6950}, // rc[29]
	{0x600ed0d9, 0xe4ed0353, 0x00da619c, 0x2cee0c75}, // rc[30]
	{0x63a4a350, 0x80bbbabc, 0x96e90cab, 0xf0b1a5a1}, // rc[31]
	{0x938dca39, 0xab0dde30, 0x5e962988, 0xae3db102}, // rc[32]
	{0x2e75b442, 0x8814f3a8, 0xd554a40b, 0x17bb8f38}, // rc[33]
	{0x360a16f6, 0xaeb6b779, 0x5f427fd7, 0x34bb8a5b}, // rc[34]
	{0xffbaafde, 0x43ce5918, 0xcbe55438, 0x26f65241}, // rc[35]
	{0x839ec978, 0xa2ca9cf7, 0xb9f3026a, 0x4ce99a54}, // rc[36]
	{0x22901235, 0x40c06e28, 0x1bdff7be, 0xae51a51a}, // rc[37]
	{0x48a659cf, 0xc173bc0f, 0xba7ed22b, 0xa0c1613c}, // rc[38]
	{0xe9c59da1, 0x4ad6bdfd, 0x02288288, 0x756acc03}, // rc[39]
}

// Pre-computed 128-bit round constants in byte form for efficient access
var harakaRC128 [40][16]byte

func init() {
	for i := range 40 {
		binary.LittleEndian.PutUint32(harakaRC128[i][0:4], harakaRC[i][0])
		binary.LittleEndian.PutUint32(harakaRC128[i][4:8], harakaRC[i][1])
		binary.LittleEndian.PutUint32(harakaRC128[i][8:12], harakaRC[i][2])
		binary.LittleEndian.PutUint32(harakaRC128[i][12:16], harakaRC[i][3])
	}
}

// mix2 performs the MIX2 permutation for Haraka-256.
// Implements: tmp = unpacklo_epi32(s0, s1); s1 = unpackhi_epi32(s0, s1); s0 = tmp
// This interleaves 32-bit dwords from the two 128-bit state blocks.
func mix2(s0, s1 *Block) {
	// Read as 32-bit values
	a0 := binary.LittleEndian.Uint32(s0[0:4])
	a1 := binary.LittleEndian.Uint32(s0[4:8])
	a2 := binary.LittleEndian.Uint32(s0[8:12])
	a3 := binary.LittleEndian.Uint32(s0[12:16])
	b0 := binary.LittleEndian.Uint32(s1[0:4])
	b1 := binary.LittleEndian.Uint32(s1[4:8])
	b2 := binary.LittleEndian.Uint32(s1[8:12])
	b3 := binary.LittleEndian.Uint32(s1[12:16])

	// unpacklo_epi32(s0, s1) -> [a0, b0, a1, b1]
	// unpackhi_epi32(s0, s1) -> [a2, b2, a3, b3]
	binary.LittleEndian.PutUint32(s0[0:4], a0)
	binary.LittleEndian.PutUint32(s0[4:8], b0)
	binary.LittleEndian.PutUint32(s0[8:12], a1)
	binary.LittleEndian.PutUint32(s0[12:16], b1)
	binary.LittleEndian.PutUint32(s1[0:4], a2)
	binary.LittleEndian.PutUint32(s1[4:8], b2)
	binary.LittleEndian.PutUint32(s1[8:12], a3)
	binary.LittleEndian.PutUint32(s1[12:16], b3)
}

// mix512 performs the MIX512 permutation for Haraka-512.
// From the reference implementation:
// s[0..15] = s[3], s[11], s[7], s[15], s[8], s[0], s[12], s[4],
//            s[9], s[1], s[13], s[5], s[2], s[10], s[6], s[14]
func mix512(s0, s1, s2, s3 *Block) {
	// Read all 32-bit values (state as 16 dwords)
	// s0 = state[0:4], s1 = state[4:8], s2 = state[8:12], s3 = state[12:16]
	a0 := binary.LittleEndian.Uint32(s0[0:4])   // state[0]
	a1 := binary.LittleEndian.Uint32(s0[4:8])   // state[1]
	a2 := binary.LittleEndian.Uint32(s0[8:12])  // state[2]
	a3 := binary.LittleEndian.Uint32(s0[12:16]) // state[3]
	b0 := binary.LittleEndian.Uint32(s1[0:4])   // state[4]
	b1 := binary.LittleEndian.Uint32(s1[4:8])   // state[5]
	b2 := binary.LittleEndian.Uint32(s1[8:12])  // state[6]
	b3 := binary.LittleEndian.Uint32(s1[12:16]) // state[7]
	c0 := binary.LittleEndian.Uint32(s2[0:4])   // state[8]
	c1 := binary.LittleEndian.Uint32(s2[4:8])   // state[9]
	c2 := binary.LittleEndian.Uint32(s2[8:12])  // state[10]
	c3 := binary.LittleEndian.Uint32(s2[12:16]) // state[11]
	d0 := binary.LittleEndian.Uint32(s3[0:4])   // state[12]
	d1 := binary.LittleEndian.Uint32(s3[4:8])   // state[13]
	d2 := binary.LittleEndian.Uint32(s3[8:12])  // state[14]
	d3 := binary.LittleEndian.Uint32(s3[12:16]) // state[15]

	// Apply the permutation:
	// new[0]=old[3], new[1]=old[11], new[2]=old[7], new[3]=old[15]
	// new[4]=old[8], new[5]=old[0], new[6]=old[12], new[7]=old[4]
	// new[8]=old[9], new[9]=old[1], new[10]=old[13], new[11]=old[5]
	// new[12]=old[2], new[13]=old[10], new[14]=old[6], new[15]=old[14]

	// old[3]=a3, old[11]=c3, old[7]=b3, old[15]=d3
	// old[8]=c0, old[0]=a0, old[12]=d0, old[4]=b0
	// old[9]=c1, old[1]=a1, old[13]=d1, old[5]=b1
	// old[2]=a2, old[10]=c2, old[6]=b2, old[14]=d2

	binary.LittleEndian.PutUint32(s0[0:4], a3)   // new[0] = old[3]
	binary.LittleEndian.PutUint32(s0[4:8], c3)   // new[1] = old[11]
	binary.LittleEndian.PutUint32(s0[8:12], b3)  // new[2] = old[7]
	binary.LittleEndian.PutUint32(s0[12:16], d3) // new[3] = old[15]
	binary.LittleEndian.PutUint32(s1[0:4], c0)   // new[4] = old[8]
	binary.LittleEndian.PutUint32(s1[4:8], a0)   // new[5] = old[0]
	binary.LittleEndian.PutUint32(s1[8:12], d0)  // new[6] = old[12]
	binary.LittleEndian.PutUint32(s1[12:16], b0) // new[7] = old[4]
	binary.LittleEndian.PutUint32(s2[0:4], c1)   // new[8] = old[9]
	binary.LittleEndian.PutUint32(s2[4:8], a1)   // new[9] = old[1]
	binary.LittleEndian.PutUint32(s2[8:12], d1)  // new[10] = old[13]
	binary.LittleEndian.PutUint32(s2[12:16], b1) // new[11] = old[5]
	binary.LittleEndian.PutUint32(s3[0:4], a2)   // new[12] = old[2]
	binary.LittleEndian.PutUint32(s3[4:8], c2)   // new[13] = old[10]
	binary.LittleEndian.PutUint32(s3[8:12], b2)  // new[14] = old[6]
	binary.LittleEndian.PutUint32(s3[12:16], d2) // new[15] = old[14]
}

// Haraka256 computes the Haraka-256 v2 hash of a 32-byte input.
// Returns a 32-byte hash output.
func Haraka256(input *[32]byte) [32]byte {
	// Copy input to state
	var s0, s1 Block
	copy(s0[:], input[0:16])
	copy(s1[:], input[16:32])

	// Save original for feed-forward
	var orig0, orig1 Block
	orig0 = s0
	orig1 = s1

	// 5 rounds
	// Note: The Go reference applies rounds in interleaved order:
	// first AES to s0, first AES to s1, second AES to s0, second AES to s1
	for round := range 5 {
		rcIdx := round * 4

		// Interleaved AES rounds as per the Go reference implementation
		Round(&s0, (*Block)(&harakaRC128[rcIdx+0]))
		Round(&s1, (*Block)(&harakaRC128[rcIdx+1]))
		Round(&s0, (*Block)(&harakaRC128[rcIdx+2]))
		Round(&s1, (*Block)(&harakaRC128[rcIdx+3]))

		// Mix
		mix2(&s0, &s1)
	}

	// Feed-forward XOR
	XorBlock(&s0, &s0, &orig0)
	XorBlock(&s1, &s1, &orig1)

	// Output
	var out [32]byte
	copy(out[0:16], s0[:])
	copy(out[16:32], s1[:])
	return out
}

// Haraka512 computes the Haraka-512 v2 hash of a 64-byte input.
// Returns a 32-byte hash output (truncated).
func Haraka512(input *[64]byte) [32]byte {
	// Copy input to state
	var s0, s1, s2, s3 Block
	copy(s0[:], input[0:16])
	copy(s1[:], input[16:32])
	copy(s2[:], input[32:48])
	copy(s3[:], input[48:64])

	// Save original for feed-forward
	var orig0, orig1, orig2, orig3 Block
	orig0 = s0
	orig1 = s1
	orig2 = s2
	orig3 = s3

	// 5 rounds
	// Reference order: first AES on all 4 blocks, then second AES on all 4 blocks
	for round := range 5 {
		rcIdx := round * 8

		// First AES round on each block
		Round(&s0, (*Block)(&harakaRC128[rcIdx+0]))
		Round(&s1, (*Block)(&harakaRC128[rcIdx+1]))
		Round(&s2, (*Block)(&harakaRC128[rcIdx+2]))
		Round(&s3, (*Block)(&harakaRC128[rcIdx+3]))

		// Second AES round on each block
		Round(&s0, (*Block)(&harakaRC128[rcIdx+4]))
		Round(&s1, (*Block)(&harakaRC128[rcIdx+5]))
		Round(&s2, (*Block)(&harakaRC128[rcIdx+6]))
		Round(&s3, (*Block)(&harakaRC128[rcIdx+7]))

		// Mix
		mix512(&s0, &s1, &s2, &s3)
	}

	// Feed-forward XOR
	XorBlock(&s0, &s0, &orig0)
	XorBlock(&s1, &s1, &orig1)
	XorBlock(&s2, &s2, &orig2)
	XorBlock(&s3, &s3, &orig3)

	// Truncated output: take bytes from specific positions
	// In terms of 32-bit dwords, output indices are: 2, 3, 6, 7, 8, 9, 12, 13
	// Which corresponds to:
	// s0[8:16] || s1[8:16] || s2[0:8] || s3[0:8]
	var out [32]byte
	copy(out[0:8], s0[8:16])
	copy(out[8:16], s1[8:16])
	copy(out[16:24], s2[0:8])
	copy(out[24:32], s3[0:8])
	return out
}

// Haraka256ToBlock computes Haraka-256 and returns a single 16-byte block.
// This is a convenience function that takes only the first half of the output.
func Haraka256ToBlock(input *[32]byte) Block {
	out := Haraka256(input)
	var result Block
	copy(result[:], out[0:16])
	return result
}

// Haraka512ToBlock computes Haraka-512 and returns a single 16-byte block.
// This is a convenience function that takes only the first half of the output.
func Haraka512ToBlock(input *[64]byte) Block {
	out := Haraka512(input)
	var result Block
	copy(result[:], out[0:16])
	return result
}
