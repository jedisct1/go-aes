package aes

// RoundKeys types for multi-round operations
type (
	RoundKeys4  [4]Block  // 4 round keys for 4 rounds
	RoundKeys6  [6]Block  // 6 round keys for 6 rounds (5 full + 1 final)
	RoundKeys7  [7]Block  // 7 round keys for 7 rounds
	RoundKeys10 [10]Block // 10 round keys for 10 rounds
	RoundKeys12 [12]Block // 12 round keys for 12 rounds
	RoundKeys14 [14]Block // 14 round keys for 14 rounds
)

// Per-block round key types for parallel operations with different keys per block
// Each block in Block2/Block4 gets its own sequence of round keys

// PerBlockRoundKeys4_2 holds 4 round keys for each of 2 blocks
type PerBlockRoundKeys4_2 [2]RoundKeys4

// PerBlockRoundKeys7_2 holds 7 round keys for each of 2 blocks
type PerBlockRoundKeys7_2 [2]RoundKeys7

// PerBlockRoundKeys10_2 holds 10 round keys for each of 2 blocks
type PerBlockRoundKeys10_2 [2]RoundKeys10

// PerBlockRoundKeys12_2 holds 12 round keys for each of 2 blocks
type PerBlockRoundKeys12_2 [2]RoundKeys12

// PerBlockRoundKeys14_2 holds 14 round keys for each of 2 blocks
type PerBlockRoundKeys14_2 [2]RoundKeys14

// PerBlockRoundKeys4_4 holds 4 round keys for each of 4 blocks
type PerBlockRoundKeys4_4 [4]RoundKeys4

// PerBlockRoundKeys7_4 holds 7 round keys for each of 4 blocks
type PerBlockRoundKeys7_4 [4]RoundKeys7

// PerBlockRoundKeys10_4 holds 10 round keys for each of 4 blocks
type PerBlockRoundKeys10_4 [4]RoundKeys10

// PerBlockRoundKeys12_4 holds 12 round keys for each of 4 blocks
type PerBlockRoundKeys12_4 [4]RoundKeys12

// PerBlockRoundKeys14_4 holds 14 round keys for each of 4 blocks
type PerBlockRoundKeys14_4 [4]RoundKeys14

// Rounds4 performs 4 AES encryption rounds (SubBytes, ShiftRows, MixColumns, AddRoundKey)
func Rounds4(block *Block, roundKeys *RoundKeys4) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
}

// InvRounds4 performs 4 AES decryption rounds (InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey)
func InvRounds4(block *Block, roundKeys *RoundKeys4) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
}

// Rounds7 performs 7 AES encryption rounds
func Rounds7(block *Block, roundKeys *RoundKeys7) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
}

// InvRounds7 performs 7 AES decryption rounds
func InvRounds7(block *Block, roundKeys *RoundKeys7) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
}

// Rounds6 performs 6 AES encryption rounds
func Rounds6(block *Block, roundKeys *RoundKeys6) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
}

// InvRounds6 performs 6 AES decryption rounds
func InvRounds6(block *Block, roundKeys *RoundKeys6) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
}

// Rounds6WithFinal performs 5 full AES encryption rounds + 1 final round
// This is useful for constructions like AES-PRF where you need 5+1 rounds
// (5 rounds with MixColumns, final round without)
func Rounds6WithFinal(block *Block, roundKeys *RoundKeys6) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	FinalRound(block, &roundKeys[5])
}

// Rounds10 performs 10 AES encryption rounds
func Rounds10(block *Block, roundKeys *RoundKeys10) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	Round(block, &roundKeys[9])
}

// Rounds10WithFinal performs 9 full AES encryption rounds + 1 final round (for AES-128)
// This is the standard AES-128 structure: 9 rounds with MixColumns, final round without
func Rounds10WithFinal(block *Block, roundKeys *RoundKeys10) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	FinalRound(block, &roundKeys[9])
}

// InvRounds10 performs 10 AES decryption rounds
func InvRounds10(block *Block, roundKeys *RoundKeys10) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvRound(block, &roundKeys[9])
}

// Rounds12 performs 12 AES encryption rounds
func Rounds12(block *Block, roundKeys *RoundKeys12) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	Round(block, &roundKeys[9])
	Round(block, &roundKeys[10])
	Round(block, &roundKeys[11])
}

// Rounds12WithFinal performs 11 full AES encryption rounds + 1 final round (for AES-192)
func Rounds12WithFinal(block *Block, roundKeys *RoundKeys12) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	Round(block, &roundKeys[9])
	Round(block, &roundKeys[10])
	FinalRound(block, &roundKeys[11])
}

// InvRounds12 performs 12 AES decryption rounds
func InvRounds12(block *Block, roundKeys *RoundKeys12) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvRound(block, &roundKeys[9])
	InvRound(block, &roundKeys[10])
	InvRound(block, &roundKeys[11])
}

// Rounds14 performs 14 AES encryption rounds
func Rounds14(block *Block, roundKeys *RoundKeys14) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	Round(block, &roundKeys[9])
	Round(block, &roundKeys[10])
	Round(block, &roundKeys[11])
	Round(block, &roundKeys[12])
	Round(block, &roundKeys[13])
}

// Rounds14WithFinal performs 13 full AES encryption rounds + 1 final round (for AES-256)
func Rounds14WithFinal(block *Block, roundKeys *RoundKeys14) {
	Round(block, &roundKeys[0])
	Round(block, &roundKeys[1])
	Round(block, &roundKeys[2])
	Round(block, &roundKeys[3])
	Round(block, &roundKeys[4])
	Round(block, &roundKeys[5])
	Round(block, &roundKeys[6])
	Round(block, &roundKeys[7])
	Round(block, &roundKeys[8])
	Round(block, &roundKeys[9])
	Round(block, &roundKeys[10])
	Round(block, &roundKeys[11])
	Round(block, &roundKeys[12])
	FinalRound(block, &roundKeys[13])
}

// InvRounds14 performs 14 AES decryption rounds
func InvRounds14(block *Block, roundKeys *RoundKeys14) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvRound(block, &roundKeys[9])
	InvRound(block, &roundKeys[10])
	InvRound(block, &roundKeys[11])
	InvRound(block, &roundKeys[12])
	InvRound(block, &roundKeys[13])
}

// InvWithFinal variants - perform N-1 inverse full rounds + 1 inverse final round
// The inverse final round does not include InvMixColumns

// InvRounds4WithFinal performs 3 full AES decryption rounds + 1 inverse final round
func InvRounds4WithFinal(block *Block, roundKeys *RoundKeys4) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvFinalRound(block, &roundKeys[3])
}

// InvRounds6WithFinal performs 5 full AES decryption rounds + 1 inverse final round
func InvRounds6WithFinal(block *Block, roundKeys *RoundKeys6) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvFinalRound(block, &roundKeys[5])
}

// InvRounds7WithFinal performs 6 full AES decryption rounds + 1 inverse final round
func InvRounds7WithFinal(block *Block, roundKeys *RoundKeys7) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvFinalRound(block, &roundKeys[6])
}

// InvRounds10WithFinal performs 9 full AES decryption rounds + 1 inverse final round (for AES-128)
func InvRounds10WithFinal(block *Block, roundKeys *RoundKeys10) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvFinalRound(block, &roundKeys[9])
}

// InvRounds12WithFinal performs 11 full AES decryption rounds + 1 inverse final round (for AES-192)
func InvRounds12WithFinal(block *Block, roundKeys *RoundKeys12) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvRound(block, &roundKeys[9])
	InvRound(block, &roundKeys[10])
	InvFinalRound(block, &roundKeys[11])
}

// InvRounds14WithFinal performs 13 full AES decryption rounds + 1 inverse final round (for AES-256)
func InvRounds14WithFinal(block *Block, roundKeys *RoundKeys14) {
	InvRound(block, &roundKeys[0])
	InvRound(block, &roundKeys[1])
	InvRound(block, &roundKeys[2])
	InvRound(block, &roundKeys[3])
	InvRound(block, &roundKeys[4])
	InvRound(block, &roundKeys[5])
	InvRound(block, &roundKeys[6])
	InvRound(block, &roundKeys[7])
	InvRound(block, &roundKeys[8])
	InvRound(block, &roundKeys[9])
	InvRound(block, &roundKeys[10])
	InvRound(block, &roundKeys[11])
	InvRound(block, &roundKeys[12])
	InvFinalRound(block, &roundKeys[13])
}

// NoKey variants - perform rounds without key XOR
// Useful for permutations and custom constructions

// Rounds4NoKey performs 4 AES encryption rounds without AddRoundKey
func Rounds4NoKey(block *Block) {
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
}

// InvRounds4NoKey performs 4 AES decryption rounds without AddRoundKey
func InvRounds4NoKey(block *Block) {
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
}

// Rounds7NoKey performs 7 AES encryption rounds without AddRoundKey
func Rounds7NoKey(block *Block) {
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
}

// InvRounds7NoKey performs 7 AES decryption rounds without AddRoundKey
func InvRounds7NoKey(block *Block) {
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
}

// Rounds10NoKey performs 10 AES encryption rounds without AddRoundKey
func Rounds10NoKey(block *Block) {
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
}

// InvRounds10NoKey performs 10 AES decryption rounds without AddRoundKey
func InvRounds10NoKey(block *Block) {
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
}

// Rounds12NoKey performs 12 AES encryption rounds without AddRoundKey
func Rounds12NoKey(block *Block) {
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
}

// InvRounds12NoKey performs 12 AES decryption rounds without AddRoundKey
func InvRounds12NoKey(block *Block) {
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
}

// Rounds14NoKey performs 14 AES encryption rounds without AddRoundKey
func Rounds14NoKey(block *Block) {
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
	RoundNoKey(block)
}

// InvRounds14NoKey performs 14 AES decryption rounds without AddRoundKey
func InvRounds14NoKey(block *Block) {
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
	InvRoundNoKey(block)
}

// Rounds4_2 performs 4 AES encryption rounds on 2 blocks
func Rounds4_2(blocks *Block2, roundKeys *RoundKeys4) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 4; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
	}
}

// InvRounds4_2 performs 4 AES decryption rounds on 2 blocks
func InvRounds4_2(blocks *Block2, roundKeys *RoundKeys4) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 4; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
	}
}

// Rounds7_2 performs 7 AES encryption rounds on 2 blocks
func Rounds7_2(blocks *Block2, roundKeys *RoundKeys7) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 7; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
	}
}

// InvRounds7_2 performs 7 AES decryption rounds on 2 blocks
func InvRounds7_2(blocks *Block2, roundKeys *RoundKeys7) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 7; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
	}
}

// Rounds10_2 performs 10 AES encryption rounds on 2 blocks
func Rounds10_2(blocks *Block2, roundKeys *RoundKeys10) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 10; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
	}
}

// InvRounds10_2 performs 10 AES decryption rounds on 2 blocks
func InvRounds10_2(blocks *Block2, roundKeys *RoundKeys10) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 10; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
	}
}

// Rounds12_2 performs 12 AES encryption rounds on 2 blocks
func Rounds12_2(blocks *Block2, roundKeys *RoundKeys12) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 12; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
	}
}

// InvRounds12_2 performs 12 AES decryption rounds on 2 blocks
func InvRounds12_2(blocks *Block2, roundKeys *RoundKeys12) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 12; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
	}
}

// Rounds14_2 performs 14 AES encryption rounds on 2 blocks
func Rounds14_2(blocks *Block2, roundKeys *RoundKeys14) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 14; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
	}
}

// InvRounds14_2 performs 14 AES decryption rounds on 2 blocks
func InvRounds14_2(blocks *Block2, roundKeys *RoundKeys14) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 14; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
	}
}

// Rounds4_4 performs 4 AES encryption rounds on 4 blocks
func Rounds4_4(blocks *Block4, roundKeys *RoundKeys4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 4; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
}

// InvRounds4_4 performs 4 AES decryption rounds on 4 blocks
func InvRounds4_4(blocks *Block4, roundKeys *RoundKeys4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 4; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
		InvRound(b2, &roundKeys[i])
		InvRound(b3, &roundKeys[i])
	}
}

// Rounds7_4 performs 7 AES encryption rounds on 4 blocks
func Rounds7_4(blocks *Block4, roundKeys *RoundKeys7) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 7; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
}

// InvRounds7_4 performs 7 AES decryption rounds on 4 blocks
func InvRounds7_4(blocks *Block4, roundKeys *RoundKeys7) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 7; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
		InvRound(b2, &roundKeys[i])
		InvRound(b3, &roundKeys[i])
	}
}

// Rounds10_4 performs 10 AES encryption rounds on 4 blocks
func Rounds10_4(blocks *Block4, roundKeys *RoundKeys10) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 10; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
}

// InvRounds10_4 performs 10 AES decryption rounds on 4 blocks
func InvRounds10_4(blocks *Block4, roundKeys *RoundKeys10) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 10; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
		InvRound(b2, &roundKeys[i])
		InvRound(b3, &roundKeys[i])
	}
}

// Rounds12_4 performs 12 AES encryption rounds on 4 blocks
func Rounds12_4(blocks *Block4, roundKeys *RoundKeys12) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 12; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
}

// InvRounds12_4 performs 12 AES decryption rounds on 4 blocks
func InvRounds12_4(blocks *Block4, roundKeys *RoundKeys12) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 12; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
		InvRound(b2, &roundKeys[i])
		InvRound(b3, &roundKeys[i])
	}
}

// Rounds14_4 performs 14 AES encryption rounds on 4 blocks
func Rounds14_4(blocks *Block4, roundKeys *RoundKeys14) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 14; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
}

// InvRounds14_4 performs 14 AES decryption rounds on 4 blocks
func InvRounds14_4(blocks *Block4, roundKeys *RoundKeys14) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 14; i++ {
		InvRound(b0, &roundKeys[i])
		InvRound(b1, &roundKeys[i])
		InvRound(b2, &roundKeys[i])
		InvRound(b3, &roundKeys[i])
	}
}

// Rounds10WithFinal_4 performs 9 full AES encryption rounds + 1 final round on 4 blocks
func Rounds10WithFinal_4(blocks *Block4, roundKeys *RoundKeys10) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 9; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
	FinalRound(b0, &roundKeys[9])
	FinalRound(b1, &roundKeys[9])
	FinalRound(b2, &roundKeys[9])
	FinalRound(b3, &roundKeys[9])
}

// Rounds12WithFinal_4 performs 11 full AES encryption rounds + 1 final round on 4 blocks
func Rounds12WithFinal_4(blocks *Block4, roundKeys *RoundKeys12) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 11; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
	FinalRound(b0, &roundKeys[11])
	FinalRound(b1, &roundKeys[11])
	FinalRound(b2, &roundKeys[11])
	FinalRound(b3, &roundKeys[11])
}

// Rounds14WithFinal_4 performs 13 full AES encryption rounds + 1 final round on 4 blocks
func Rounds14WithFinal_4(blocks *Block4, roundKeys *RoundKeys14) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 13; i++ {
		Round(b0, &roundKeys[i])
		Round(b1, &roundKeys[i])
		Round(b2, &roundKeys[i])
		Round(b3, &roundKeys[i])
	}
	FinalRound(b0, &roundKeys[13])
	FinalRound(b1, &roundKeys[13])
	FinalRound(b2, &roundKeys[13])
	FinalRound(b3, &roundKeys[13])
}

// Rounds4NoKey_2 performs 4 AES encryption rounds without AddRoundKey on 2 blocks
func Rounds4NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 4; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
	}
}

// InvRounds4NoKey_2 performs 4 AES decryption rounds without AddRoundKey on 2 blocks
func InvRounds4NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 4; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
	}
}

// Rounds7NoKey_2 performs 7 AES encryption rounds without AddRoundKey on 2 blocks
func Rounds7NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 7; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
	}
}

// InvRounds7NoKey_2 performs 7 AES decryption rounds without AddRoundKey on 2 blocks
func InvRounds7NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 7; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
	}
}

// Rounds10NoKey_2 performs 10 AES encryption rounds without AddRoundKey on 2 blocks
func Rounds10NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 10; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
	}
}

// InvRounds10NoKey_2 performs 10 AES decryption rounds without AddRoundKey on 2 blocks
func InvRounds10NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 10; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
	}
}

// Rounds12NoKey_2 performs 12 AES encryption rounds without AddRoundKey on 2 blocks
func Rounds12NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 12; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
	}
}

// InvRounds12NoKey_2 performs 12 AES decryption rounds without AddRoundKey on 2 blocks
func InvRounds12NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 12; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
	}
}

// Rounds14NoKey_2 performs 14 AES encryption rounds without AddRoundKey on 2 blocks
func Rounds14NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 14; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
	}
}

// InvRounds14NoKey_2 performs 14 AES decryption rounds without AddRoundKey on 2 blocks
func InvRounds14NoKey_2(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	for i := 0; i < 14; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
	}
}

// Rounds4NoKey_4 performs 4 AES encryption rounds without AddRoundKey on 4 blocks
func Rounds4NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 4; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
		RoundNoKey(b2)
		RoundNoKey(b3)
	}
}

// InvRounds4NoKey_4 performs 4 AES decryption rounds without AddRoundKey on 4 blocks
func InvRounds4NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 4; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
		InvRoundNoKey(b2)
		InvRoundNoKey(b3)
	}
}

// Rounds7NoKey_4 performs 7 AES encryption rounds without AddRoundKey on 4 blocks
func Rounds7NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 7; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
		RoundNoKey(b2)
		RoundNoKey(b3)
	}
}

// InvRounds7NoKey_4 performs 7 AES decryption rounds without AddRoundKey on 4 blocks
func InvRounds7NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 7; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
		InvRoundNoKey(b2)
		InvRoundNoKey(b3)
	}
}

// Rounds10NoKey_4 performs 10 AES encryption rounds without AddRoundKey on 4 blocks
func Rounds10NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 10; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
		RoundNoKey(b2)
		RoundNoKey(b3)
	}
}

// InvRounds10NoKey_4 performs 10 AES decryption rounds without AddRoundKey on 4 blocks
func InvRounds10NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 10; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
		InvRoundNoKey(b2)
		InvRoundNoKey(b3)
	}
}

// Rounds12NoKey_4 performs 12 AES encryption rounds without AddRoundKey on 4 blocks
func Rounds12NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 12; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
		RoundNoKey(b2)
		RoundNoKey(b3)
	}
}

// InvRounds12NoKey_4 performs 12 AES decryption rounds without AddRoundKey on 4 blocks
func InvRounds12NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 12; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
		InvRoundNoKey(b2)
		InvRoundNoKey(b3)
	}
}

// Rounds14NoKey_4 performs 14 AES encryption rounds without AddRoundKey on 4 blocks
func Rounds14NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 14; i++ {
		RoundNoKey(b0)
		RoundNoKey(b1)
		RoundNoKey(b2)
		RoundNoKey(b3)
	}
}

// InvRounds14NoKey_4 performs 14 AES decryption rounds without AddRoundKey on 4 blocks
func InvRounds14NoKey_4(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := 0; i < 14; i++ {
		InvRoundNoKey(b0)
		InvRoundNoKey(b1)
		InvRoundNoKey(b2)
		InvRoundNoKey(b3)
	}
}

// PerBlockRounds4_2 performs 4 rounds on 2 blocks, each with its own keys
func PerBlockRounds4_2(blocks *Block2, keySets *PerBlockRoundKeys4_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 4 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
}

// PerBlockRounds7_2 performs 7 rounds on 2 blocks, each with its own keys
func PerBlockRounds7_2(blocks *Block2, keySets *PerBlockRoundKeys7_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 7 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
}

// PerBlockRounds10_2 performs 10 rounds on 2 blocks, each with its own keys
func PerBlockRounds10_2(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 10 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
}

// PerBlockRounds12_2 performs 12 rounds on 2 blocks, each with its own keys
func PerBlockRounds12_2(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 12 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
}

// PerBlockRounds14_2 performs 14 rounds on 2 blocks, each with its own keys
func PerBlockRounds14_2(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 14 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
}

// PerBlockRounds4_4 performs 4 rounds on 4 blocks, each with its own keys
func PerBlockRounds4_4(blocks *Block4, keySets *PerBlockRoundKeys4_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 4 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
}

// PerBlockRounds7_4 performs 7 rounds on 4 blocks, each with its own keys
func PerBlockRounds7_4(blocks *Block4, keySets *PerBlockRoundKeys7_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 7 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
}

// PerBlockRounds10_4 performs 10 rounds on 4 blocks, each with its own keys
func PerBlockRounds10_4(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 10 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
}

// PerBlockRounds12_4 performs 12 rounds on 4 blocks, each with its own keys
func PerBlockRounds12_4(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 12 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
}

// PerBlockRounds14_4 performs 14 rounds on 4 blocks, each with its own keys
func PerBlockRounds14_4(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 14 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
}

// PerBlockRounds10WithFinal_2 performs 9 full rounds + 1 final round on 2 blocks, each with its own keys
func PerBlockRounds10WithFinal_2(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 9 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
	FinalRound(b0, &keySets[0][9])
	FinalRound(b1, &keySets[1][9])
}

// PerBlockRounds12WithFinal_2 performs 11 full rounds + 1 final round on 2 blocks, each with its own keys
func PerBlockRounds12WithFinal_2(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 11 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
	FinalRound(b0, &keySets[0][11])
	FinalRound(b1, &keySets[1][11])
}

// PerBlockRounds14WithFinal_2 performs 13 full rounds + 1 final round on 2 blocks, each with its own keys
func PerBlockRounds14WithFinal_2(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	b0, b1 := block2Ptrs(blocks)
	for i := range 13 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
	}
	FinalRound(b0, &keySets[0][13])
	FinalRound(b1, &keySets[1][13])
}

// PerBlockRounds10WithFinal_4 performs 9 full rounds + 1 final round on 4 blocks, each with its own keys
func PerBlockRounds10WithFinal_4(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 9 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
	FinalRound(b0, &keySets[0][9])
	FinalRound(b1, &keySets[1][9])
	FinalRound(b2, &keySets[2][9])
	FinalRound(b3, &keySets[3][9])
}

// PerBlockRounds12WithFinal_4 performs 11 full rounds + 1 final round on 4 blocks, each with its own keys
func PerBlockRounds12WithFinal_4(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 11 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
	FinalRound(b0, &keySets[0][11])
	FinalRound(b1, &keySets[1][11])
	FinalRound(b2, &keySets[2][11])
	FinalRound(b3, &keySets[3][11])
}

// PerBlockRounds14WithFinal_4 performs 13 full rounds + 1 final round on 4 blocks, each with its own keys
func PerBlockRounds14WithFinal_4(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	for i := range 13 {
		Round(b0, &keySets[0][i])
		Round(b1, &keySets[1][i])
		Round(b2, &keySets[2][i])
		Round(b3, &keySets[3][i])
	}
	FinalRound(b0, &keySets[0][13])
	FinalRound(b1, &keySets[1][13])
	FinalRound(b2, &keySets[2][13])
	FinalRound(b3, &keySets[3][13])
}
