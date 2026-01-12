//go:build (!amd64 && !arm64) || purego

package aes

// Software fallback for platforms without hardware AES acceleration

// Rounds4HW performs 4 AES encryption rounds (software fallback)
func Rounds4HW(block *Block, roundKeys *RoundKeys4) {
	Rounds4(block, roundKeys)
}

// InvRounds4HW performs 4 AES decryption rounds (software fallback)
func InvRounds4HW(block *Block, roundKeys *RoundKeys4) {
	InvRounds4(block, roundKeys)
}

// Rounds6HW performs 6 AES encryption rounds (software fallback)
func Rounds6HW(block *Block, roundKeys *RoundKeys6) {
	Rounds6(block, roundKeys)
}

// InvRounds6HW performs 6 AES decryption rounds (software fallback)
func InvRounds6HW(block *Block, roundKeys *RoundKeys6) {
	InvRounds6(block, roundKeys)
}

// Rounds7HW performs 7 AES encryption rounds (software fallback)
func Rounds7HW(block *Block, roundKeys *RoundKeys7) {
	Rounds7(block, roundKeys)
}

// InvRounds7HW performs 7 AES decryption rounds (software fallback)
func InvRounds7HW(block *Block, roundKeys *RoundKeys7) {
	InvRounds7(block, roundKeys)
}

// Rounds10HW performs 10 AES encryption rounds (software fallback)
func Rounds10HW(block *Block, roundKeys *RoundKeys10) {
	Rounds10(block, roundKeys)
}

// InvRounds10HW performs 10 AES decryption rounds (software fallback)
func InvRounds10HW(block *Block, roundKeys *RoundKeys10) {
	InvRounds10(block, roundKeys)
}

// Rounds12HW performs 12 AES encryption rounds (software fallback)
func Rounds12HW(block *Block, roundKeys *RoundKeys12) {
	Rounds12(block, roundKeys)
}

// InvRounds12HW performs 12 AES decryption rounds (software fallback)
func InvRounds12HW(block *Block, roundKeys *RoundKeys12) {
	InvRounds12(block, roundKeys)
}

// Rounds14HW performs 14 AES encryption rounds (software fallback)
func Rounds14HW(block *Block, roundKeys *RoundKeys14) {
	Rounds14(block, roundKeys)
}

// InvRounds14HW performs 14 AES decryption rounds (software fallback)
func InvRounds14HW(block *Block, roundKeys *RoundKeys14) {
	InvRounds14(block, roundKeys)
}

// NoKey variants (software fallback)

// Rounds4NoKeyHW performs 4 AES encryption rounds without AddRoundKey (software fallback)
func Rounds4NoKeyHW(block *Block) {
	Rounds4NoKey(block)
}

// InvRounds4NoKeyHW performs 4 AES decryption rounds without AddRoundKey (software fallback)
func InvRounds4NoKeyHW(block *Block) {
	InvRounds4NoKey(block)
}

// Rounds7NoKeyHW performs 7 AES encryption rounds without AddRoundKey (software fallback)
func Rounds7NoKeyHW(block *Block) {
	Rounds7NoKey(block)
}

// InvRounds7NoKeyHW performs 7 AES decryption rounds without AddRoundKey (software fallback)
func InvRounds7NoKeyHW(block *Block) {
	InvRounds7NoKey(block)
}

// Rounds10NoKeyHW performs 10 AES encryption rounds without AddRoundKey (software fallback)
func Rounds10NoKeyHW(block *Block) {
	Rounds10NoKey(block)
}

// InvRounds10NoKeyHW performs 10 AES decryption rounds without AddRoundKey (software fallback)
func InvRounds10NoKeyHW(block *Block) {
	InvRounds10NoKey(block)
}

// Rounds12NoKeyHW performs 12 AES encryption rounds without AddRoundKey (software fallback)
func Rounds12NoKeyHW(block *Block) {
	Rounds12NoKey(block)
}

// InvRounds12NoKeyHW performs 12 AES decryption rounds without AddRoundKey (software fallback)
func InvRounds12NoKeyHW(block *Block) {
	InvRounds12NoKey(block)
}

// Rounds14NoKeyHW performs 14 AES encryption rounds without AddRoundKey (software fallback)
func Rounds14NoKeyHW(block *Block) {
	Rounds14NoKey(block)
}

// InvRounds14NoKeyHW performs 14 AES decryption rounds without AddRoundKey (software fallback)
func InvRounds14NoKeyHW(block *Block) {
	InvRounds14NoKey(block)
}

// Parallel Block2 variants (software fallback)

// Rounds4_2HW performs 4 AES encryption rounds on 2 blocks (software fallback)
func Rounds4_2HW(blocks *Block2, roundKeys *RoundKeys4) {
	Rounds4_2(blocks, roundKeys)
}

// InvRounds4_2HW performs 4 AES decryption rounds on 2 blocks (software fallback)
func InvRounds4_2HW(blocks *Block2, roundKeys *RoundKeys4) {
	InvRounds4_2(blocks, roundKeys)
}

// Rounds7_2HW performs 7 AES encryption rounds on 2 blocks (software fallback)
func Rounds7_2HW(blocks *Block2, roundKeys *RoundKeys7) {
	Rounds7_2(blocks, roundKeys)
}

// InvRounds7_2HW performs 7 AES decryption rounds on 2 blocks (software fallback)
func InvRounds7_2HW(blocks *Block2, roundKeys *RoundKeys7) {
	InvRounds7_2(blocks, roundKeys)
}

// Rounds10_2HW performs 10 AES encryption rounds on 2 blocks (software fallback)
func Rounds10_2HW(blocks *Block2, roundKeys *RoundKeys10) {
	Rounds10_2(blocks, roundKeys)
}

// InvRounds10_2HW performs 10 AES decryption rounds on 2 blocks (software fallback)
func InvRounds10_2HW(blocks *Block2, roundKeys *RoundKeys10) {
	InvRounds10_2(blocks, roundKeys)
}

// Rounds12_2HW performs 12 AES encryption rounds on 2 blocks (software fallback)
func Rounds12_2HW(blocks *Block2, roundKeys *RoundKeys12) {
	Rounds12_2(blocks, roundKeys)
}

// InvRounds12_2HW performs 12 AES decryption rounds on 2 blocks (software fallback)
func InvRounds12_2HW(blocks *Block2, roundKeys *RoundKeys12) {
	InvRounds12_2(blocks, roundKeys)
}

// Rounds14_2HW performs 14 AES encryption rounds on 2 blocks (software fallback)
func Rounds14_2HW(blocks *Block2, roundKeys *RoundKeys14) {
	Rounds14_2(blocks, roundKeys)
}

// InvRounds14_2HW performs 14 AES decryption rounds on 2 blocks (software fallback)
func InvRounds14_2HW(blocks *Block2, roundKeys *RoundKeys14) {
	InvRounds14_2(blocks, roundKeys)
}

// Parallel Block4 variants (software fallback)

// Rounds4_4HW performs 4 AES encryption rounds on 4 blocks (software fallback)
func Rounds4_4HW(blocks *Block4, roundKeys *RoundKeys4) {
	Rounds4_4(blocks, roundKeys)
}

// InvRounds4_4HW performs 4 AES decryption rounds on 4 blocks (software fallback)
func InvRounds4_4HW(blocks *Block4, roundKeys *RoundKeys4) {
	InvRounds4_4(blocks, roundKeys)
}

// Rounds7_4HW performs 7 AES encryption rounds on 4 blocks (software fallback)
func Rounds7_4HW(blocks *Block4, roundKeys *RoundKeys7) {
	Rounds7_4(blocks, roundKeys)
}

// InvRounds7_4HW performs 7 AES decryption rounds on 4 blocks (software fallback)
func InvRounds7_4HW(blocks *Block4, roundKeys *RoundKeys7) {
	InvRounds7_4(blocks, roundKeys)
}

// Rounds10_4HW performs 10 AES encryption rounds on 4 blocks (software fallback)
func Rounds10_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	Rounds10_4(blocks, roundKeys)
}

// InvRounds10_4HW performs 10 AES decryption rounds on 4 blocks (software fallback)
func InvRounds10_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	InvRounds10_4(blocks, roundKeys)
}

// Rounds12_4HW performs 12 AES encryption rounds on 4 blocks (software fallback)
func Rounds12_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	Rounds12_4(blocks, roundKeys)
}

// InvRounds12_4HW performs 12 AES decryption rounds on 4 blocks (software fallback)
func InvRounds12_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	InvRounds12_4(blocks, roundKeys)
}

// Rounds14_4HW performs 14 AES encryption rounds on 4 blocks (software fallback)
func Rounds14_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	Rounds14_4(blocks, roundKeys)
}

// InvRounds14_4HW performs 14 AES decryption rounds on 4 blocks (software fallback)
func InvRounds14_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	InvRounds14_4(blocks, roundKeys)
}

// Parallel WithFinal Block4 variants (software fallback)

// Rounds10WithFinal_4HW performs 9 full AES rounds + 1 final round on 4 blocks (software fallback)
func Rounds10WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	Rounds10WithFinal_4(blocks, roundKeys)
}

// Rounds12WithFinal_4HW performs 11 full AES rounds + 1 final round on 4 blocks (software fallback)
func Rounds12WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	Rounds12WithFinal_4(blocks, roundKeys)
}

// Rounds14WithFinal_4HW performs 13 full AES rounds + 1 final round on 4 blocks (software fallback)
func Rounds14WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	Rounds14WithFinal_4(blocks, roundKeys)
}

// Parallel NoKey Block2 variants (software fallback)

// Rounds4NoKey_2HW performs 4 AES encryption rounds on 2 blocks without AddRoundKey (software fallback)
func Rounds4NoKey_2HW(blocks *Block2) {
	Rounds4NoKey_2(blocks)
}

// InvRounds4NoKey_2HW performs 4 AES decryption rounds on 2 blocks without AddRoundKey (software fallback)
func InvRounds4NoKey_2HW(blocks *Block2) {
	InvRounds4NoKey_2(blocks)
}

// Rounds7NoKey_2HW performs 7 AES encryption rounds on 2 blocks without AddRoundKey (software fallback)
func Rounds7NoKey_2HW(blocks *Block2) {
	Rounds7NoKey_2(blocks)
}

// InvRounds7NoKey_2HW performs 7 AES decryption rounds on 2 blocks without AddRoundKey (software fallback)
func InvRounds7NoKey_2HW(blocks *Block2) {
	InvRounds7NoKey_2(blocks)
}

// Rounds10NoKey_2HW performs 10 AES encryption rounds on 2 blocks without AddRoundKey (software fallback)
func Rounds10NoKey_2HW(blocks *Block2) {
	Rounds10NoKey_2(blocks)
}

// InvRounds10NoKey_2HW performs 10 AES decryption rounds on 2 blocks without AddRoundKey (software fallback)
func InvRounds10NoKey_2HW(blocks *Block2) {
	InvRounds10NoKey_2(blocks)
}

// Rounds12NoKey_2HW performs 12 AES encryption rounds on 2 blocks without AddRoundKey (software fallback)
func Rounds12NoKey_2HW(blocks *Block2) {
	Rounds12NoKey_2(blocks)
}

// InvRounds12NoKey_2HW performs 12 AES decryption rounds on 2 blocks without AddRoundKey (software fallback)
func InvRounds12NoKey_2HW(blocks *Block2) {
	InvRounds12NoKey_2(blocks)
}

// Rounds14NoKey_2HW performs 14 AES encryption rounds on 2 blocks without AddRoundKey (software fallback)
func Rounds14NoKey_2HW(blocks *Block2) {
	Rounds14NoKey_2(blocks)
}

// InvRounds14NoKey_2HW performs 14 AES decryption rounds on 2 blocks without AddRoundKey (software fallback)
func InvRounds14NoKey_2HW(blocks *Block2) {
	InvRounds14NoKey_2(blocks)
}

// Parallel NoKey Block4 variants (software fallback)

// Rounds4NoKey_4HW performs 4 AES encryption rounds on 4 blocks without AddRoundKey (software fallback)
func Rounds4NoKey_4HW(blocks *Block4) {
	Rounds4NoKey_4(blocks)
}

// InvRounds4NoKey_4HW performs 4 AES decryption rounds on 4 blocks without AddRoundKey (software fallback)
func InvRounds4NoKey_4HW(blocks *Block4) {
	InvRounds4NoKey_4(blocks)
}

// Rounds7NoKey_4HW performs 7 AES encryption rounds on 4 blocks without AddRoundKey (software fallback)
func Rounds7NoKey_4HW(blocks *Block4) {
	Rounds7NoKey_4(blocks)
}

// InvRounds7NoKey_4HW performs 7 AES decryption rounds on 4 blocks without AddRoundKey (software fallback)
func InvRounds7NoKey_4HW(blocks *Block4) {
	InvRounds7NoKey_4(blocks)
}

// Rounds10NoKey_4HW performs 10 AES encryption rounds on 4 blocks without AddRoundKey (software fallback)
func Rounds10NoKey_4HW(blocks *Block4) {
	Rounds10NoKey_4(blocks)
}

// InvRounds10NoKey_4HW performs 10 AES decryption rounds on 4 blocks without AddRoundKey (software fallback)
func InvRounds10NoKey_4HW(blocks *Block4) {
	InvRounds10NoKey_4(blocks)
}

// Rounds12NoKey_4HW performs 12 AES encryption rounds on 4 blocks without AddRoundKey (software fallback)
func Rounds12NoKey_4HW(blocks *Block4) {
	Rounds12NoKey_4(blocks)
}

// InvRounds12NoKey_4HW performs 12 AES decryption rounds on 4 blocks without AddRoundKey (software fallback)
func InvRounds12NoKey_4HW(blocks *Block4) {
	InvRounds12NoKey_4(blocks)
}

// Rounds14NoKey_4HW performs 14 AES encryption rounds on 4 blocks without AddRoundKey (software fallback)
func Rounds14NoKey_4HW(blocks *Block4) {
	Rounds14NoKey_4(blocks)
}

// InvRounds14NoKey_4HW performs 14 AES decryption rounds on 4 blocks without AddRoundKey (software fallback)
func InvRounds14NoKey_4HW(blocks *Block4) {
	InvRounds14NoKey_4(blocks)
}

// Rounds6WithFinalHW performs 5 full AES encryption rounds + 1 final round.
func Rounds6WithFinalHW(block *Block, roundKeys *RoundKeys6) {
	Rounds6WithFinal(block, roundKeys)
}

// Rounds10WithFinalHW performs 9 full AES encryption rounds + 1 final round (for AES-128)
func Rounds10WithFinalHW(block *Block, roundKeys *RoundKeys10) {
	Rounds10WithFinal(block, roundKeys)
}

// Rounds12WithFinalHW performs 11 full AES encryption rounds + 1 final round (for AES-192)
func Rounds12WithFinalHW(block *Block, roundKeys *RoundKeys12) {
	Rounds12WithFinal(block, roundKeys)
}

// Rounds14WithFinalHW performs 13 full AES encryption rounds + 1 final round (for AES-256)
func Rounds14WithFinalHW(block *Block, roundKeys *RoundKeys14) {
	Rounds14WithFinal(block, roundKeys)
}

// InvRounds4WithFinalHW performs 3 full AES decryption rounds + 1 final round
func InvRounds4WithFinalHW(block *Block, roundKeys *RoundKeys4) {
	InvRounds4WithFinal(block, roundKeys)
}

// InvRounds6WithFinalHW performs 5 full AES decryption rounds + 1 final round
func InvRounds6WithFinalHW(block *Block, roundKeys *RoundKeys6) {
	InvRounds6WithFinal(block, roundKeys)
}

// InvRounds7WithFinalHW performs 6 full AES decryption rounds + 1 final round
func InvRounds7WithFinalHW(block *Block, roundKeys *RoundKeys7) {
	InvRounds7WithFinal(block, roundKeys)
}

// InvRounds10WithFinalHW performs 9 full AES decryption rounds + 1 final round (for AES-128)
func InvRounds10WithFinalHW(block *Block, roundKeys *RoundKeys10) {
	InvRounds10WithFinal(block, roundKeys)
}

// InvRounds12WithFinalHW performs 11 full AES decryption rounds + 1 final round (for AES-192)
func InvRounds12WithFinalHW(block *Block, roundKeys *RoundKeys12) {
	InvRounds12WithFinal(block, roundKeys)
}

// InvRounds14WithFinalHW performs 13 full AES decryption rounds + 1 final round (for AES-256)
func InvRounds14WithFinalHW(block *Block, roundKeys *RoundKeys14) {
	InvRounds14WithFinal(block, roundKeys)
}

func PerBlockRounds4_2HW(blocks *Block2, keySets *PerBlockRoundKeys4_2) {
	PerBlockRounds4_2(blocks, keySets)
}

func PerBlockRounds7_2HW(blocks *Block2, keySets *PerBlockRoundKeys7_2) {
	PerBlockRounds7_2(blocks, keySets)
}

func PerBlockRounds10_2HW(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	PerBlockRounds10_2(blocks, keySets)
}

func PerBlockRounds12_2HW(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	PerBlockRounds12_2(blocks, keySets)
}

func PerBlockRounds14_2HW(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	PerBlockRounds14_2(blocks, keySets)
}

func PerBlockRounds10WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	PerBlockRounds10WithFinal_2(blocks, keySets)
}

func PerBlockRounds12WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	PerBlockRounds12WithFinal_2(blocks, keySets)
}

func PerBlockRounds14WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	PerBlockRounds14WithFinal_2(blocks, keySets)
}

// Block4 variants
func PerBlockRounds4_4HW(blocks *Block4, keySets *PerBlockRoundKeys4_4) {
	PerBlockRounds4_4(blocks, keySets)
}

func PerBlockRounds7_4HW(blocks *Block4, keySets *PerBlockRoundKeys7_4) {
	PerBlockRounds7_4(blocks, keySets)
}

func PerBlockRounds10_4HW(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	PerBlockRounds10_4(blocks, keySets)
}

func PerBlockRounds12_4HW(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	PerBlockRounds12_4(blocks, keySets)
}

func PerBlockRounds14_4HW(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	PerBlockRounds14_4(blocks, keySets)
}

func PerBlockRounds10WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	PerBlockRounds10WithFinal_4(blocks, keySets)
}

func PerBlockRounds12WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	PerBlockRounds12WithFinal_4(blocks, keySets)
}

func PerBlockRounds14WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	PerBlockRounds14WithFinal_4(blocks, keySets)
}
