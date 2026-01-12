package aes

// Areion256 represents a 256-bit (32-byte) state for the Areion256 permutation.
// Areion256 is a wide-block cryptographic permutation built from AES round
// functions, designed for hash functions and authenticated encryption. The state
// consists of two 128-bit AES blocks processed through 10 rounds. The permutation
// uses round constants derived from the digits of pi and is hardware-accelerated
// on platforms with AES-NI or ARM Crypto Extensions.
type Areion256 [32]byte

// Areion512 represents a 512-bit (64-byte) state for the Areion512 permutation.
// Areion512 is a wide-block cryptographic permutation providing higher throughput
// than Areion256 for large constructions. The state consists of four 128-bit AES
// blocks processed through 15 rounds. Like Areion256, it uses pi-based round
// constants and is hardware-accelerated on platforms with AES-NI or ARM Crypto.
type Areion512 [64]byte

// Round constants for Areion (digits of pi in little-endian format).
// The first 10 constants are used by Areion256, all 15 are used by Areion512.
var areionRoundConstants = [15][16]byte{
	// 0x243f6a8885a308d313198a2e03707344
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	// 0xa4093822299f31d0082efa98ec4e6c89
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	// 0x452821e638d01377be5466cf34e90c6c
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	// 0xc0ac29b7c97c50dd3f84d5b5b5470917
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	// 0x9216d5d98979fb1bd1310ba698dfb5ac
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	// 0x2ffd72dbd01adfb7b8e1afed6a267e96
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	// 0xba7c9045f12c7f9924a19947b3916cf7
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	// 0x801f2e2858efc16636920d871574e690
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	// 0xa458fea3f4933d7e0d95748f728eb658
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	// 0x718bcd5882154aee7b54a41dc25a59b5
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	// Areion512-only constants:
	// 0x9c30d5392af26013c5d1b023286085f0
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	// 0xca417918b8db38ef8e79dcb0603a180e
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	// 0x6c9e0e8bb01e8a3ed71577c1bd314b27
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	// 0x78af2fda55605c60e65525f3aa55ab94
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	// 0x5748986263e8144055ca396a2aab10b6
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
}

// Permute applies the 10-round Areion256 permutation in-place. The permutation
// transforms the 32-byte state using AES round functions and pi-based constants.
// Automatically uses hardware acceleration (AES-NI or ARM Crypto) when available,
// otherwise falls back to software implementation. The permutation is designed
// to be secure for cryptographic applications like hash functions and MACs.
func (state *Areion256) Permute() {
	areion256Permute(state)
}

// InversePermute applies the inverse of the Areion256 permutation in-place.
// This inverts the transformation performed by Permute, satisfying
// InversePermute(Permute(state)) == state. Like Permute, it automatically
// uses hardware acceleration when available.
func (state *Areion256) InversePermute() {
	areion256InversePermute(state)
}

// Permute applies the 15-round Areion512 permutation in-place. The permutation
// transforms the 64-byte state using AES round functions and pi-based constants,
// providing higher throughput than Areion256 for applications processing large
// amounts of data. Automatically uses hardware acceleration when available.
func (state *Areion512) Permute() {
	areion512Permute(state)
}

// InversePermute applies the inverse of the Areion512 permutation in-place.
// This inverts the transformation performed by Permute, satisfying
// InversePermute(Permute(state)) == state. Like Permute, it automatically
// uses hardware acceleration when available.
func (state *Areion512) InversePermute() {
	areion512InversePermute(state)
}

// Software implementation of Areion256 permutation
func areion256PermuteSoftware(state *Areion256) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])

	for r := 0; r < 10; r++ {
		rc := areionRoundConstants[r]

		if r%2 == 0 {
			var temp [16]byte
			copy(temp[:], x0[:])
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(x1))
			FinalRoundNoKey((*Block)(x0))
			copy(x1[:], temp[:])
		} else {
			var temp [16]byte
			copy(temp[:], x1[:])
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(x0))
			FinalRoundNoKey((*Block)(x1))
			copy(x0[:], temp[:])
		}
	}
}

// Software implementation of Areion256 inverse permutation
func areion256InversePermuteSoftware(state *Areion256) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])

	for i := 0; i < 10; i += 2 {
		rc := areionRoundConstants[9-i]
		InvFinalRoundNoKey((*Block)(x1))
		var temp [16]byte
		copy(temp[:], x1[:])
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(x0), (*Block)(&temp), (*Block)(x0))

		rc = areionRoundConstants[8-i]
		InvFinalRoundNoKey((*Block)(x0))
		copy(temp[:], x0[:])
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(x1), (*Block)(&temp), (*Block)(x1))
	}
}

// Software implementation of Areion512 permutation
func areion512PermuteSoftware(state *Areion512) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])
	x2 := (*[16]byte)(state[32:48])
	x3 := (*[16]byte)(state[48:64])

	areion512Round := func(a, b, c, d *[16]byte, rc *[16]byte) {
		var temp1 [16]byte
		copy(temp1[:], a[:])
		RoundNoKey((*Block)(&temp1))
		XorBlock((*Block)(b), (*Block)(&temp1), (*Block)(b))

		var temp2 [16]byte
		copy(temp2[:], c[:])
		RoundNoKey((*Block)(&temp2))
		XorBlock((*Block)(d), (*Block)(&temp2), (*Block)(d))

		FinalRoundNoKey((*Block)(a))
		FinalRoundNoKey((*Block)(c))
		XorBlock((*Block)(c), (*Block)(c), (*Block)(rc))
		RoundNoKey((*Block)(c))
	}

	// Main 12 rounds
	for i := 0; i < 12; i += 4 {
		areion512Round(x0, x1, x2, x3, &areionRoundConstants[i+0])
		areion512Round(x1, x2, x3, x0, &areionRoundConstants[i+1])
		areion512Round(x2, x3, x0, x1, &areionRoundConstants[i+2])
		areion512Round(x3, x0, x1, x2, &areionRoundConstants[i+3])
	}

	// Final 3 rounds
	areion512Round(x0, x1, x2, x3, &areionRoundConstants[12])
	areion512Round(x1, x2, x3, x0, &areionRoundConstants[13])
	areion512Round(x2, x3, x0, x1, &areionRoundConstants[14])

	// Final rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	var temp [16]byte
	copy(temp[:], x0[:])
	copy(x0[:], x3[:])
	copy(x3[:], x2[:])
	copy(x2[:], x1[:])
	copy(x1[:], temp[:])
}

// Software implementation of Areion512 inverse permutation
func areion512InversePermuteSoftware(state *Areion512) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])
	x2 := (*[16]byte)(state[32:48])
	x3 := (*[16]byte)(state[48:64])

	// Reverse the final rotation: temp=x0; x0=x1; x1=x2; x2=x3; x3=temp
	var temp [16]byte
	copy(temp[:], x0[:])
	copy(x0[:], x1[:])
	copy(x1[:], x2[:])
	copy(x2[:], x3[:])
	copy(x3[:], temp[:])

	areion512InvRound := func(a, b, c, d *[16]byte, rc *[16]byte) {
		InvFinalRoundNoKey((*Block)(a))
		InvMixColumns((*Block)(c))
		InvFinalRoundNoKey((*Block)(c))
		XorBlock((*Block)(c), (*Block)(c), (*Block)(rc))
		InvFinalRoundNoKey((*Block)(c))

		var temp1 [16]byte
		copy(temp1[:], a[:])
		RoundNoKey((*Block)(&temp1))
		XorBlock((*Block)(b), (*Block)(&temp1), (*Block)(b))

		var temp2 [16]byte
		copy(temp2[:], c[:])
		RoundNoKey((*Block)(&temp2))
		XorBlock((*Block)(d), (*Block)(&temp2), (*Block)(d))
	}

	// Last 3 inverse rounds
	areion512InvRound(x2, x3, x0, x1, &areionRoundConstants[14])
	areion512InvRound(x1, x2, x3, x0, &areionRoundConstants[13])
	areion512InvRound(x0, x1, x2, x3, &areionRoundConstants[12])

	// Main 12 inverse rounds
	for i := 0; i < 12; i += 4 {
		areion512InvRound(x3, x0, x1, x2, &areionRoundConstants[11-i])
		areion512InvRound(x2, x3, x0, x1, &areionRoundConstants[10-i])
		areion512InvRound(x1, x2, x3, x0, &areionRoundConstants[9-i])
		areion512InvRound(x0, x1, x2, x3, &areionRoundConstants[8-i])
	}
}
