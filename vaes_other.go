//go:build (!amd64 && !arm64) || purego

package aes

// Software fallback implementations for platforms without VAES support

func Round2HW(blocks *Block2, roundKeys *Key2) {
	Round2(blocks, roundKeys)
}

func Round4HW(blocks *Block4, roundKeys *Key4) {
	Round4(blocks, roundKeys)
}

func FinalRound2HW(blocks *Block2, roundKeys *Key2) {
	FinalRound2(blocks, roundKeys)
}

func FinalRound4HW(blocks *Block4, roundKeys *Key4) {
	FinalRound4(blocks, roundKeys)
}

func InvRound2HW(blocks *Block2, roundKeys *Key2) {
	InvRound2(blocks, roundKeys)
}

func InvRound4HW(blocks *Block4, roundKeys *Key4) {
	InvRound4(blocks, roundKeys)
}

func InvFinalRound2HW(blocks *Block2, roundKeys *Key2) {
	InvFinalRound2(blocks, roundKeys)
}

func InvFinalRound4HW(blocks *Block4, roundKeys *Key4) {
	InvFinalRound4(blocks, roundKeys)
}

func InvMixColumns2HW(blocks *Block2) {
	b0, b1 := block2Ptrs(blocks)
	InvMixColumns(b0)
	InvMixColumns(b1)
}

func InvMixColumns4HW(blocks *Block4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	InvMixColumns(b0)
	InvMixColumns(b1)
	InvMixColumns(b2)
	InvMixColumns(b3)
}

func RoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	RoundKeyFirst2(blocks, roundKeys)
}

func RoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	RoundKeyFirst4(blocks, roundKeys)
}

func FinalRoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	FinalRoundKeyFirst2(blocks, roundKeys)
}

func FinalRoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	FinalRoundKeyFirst4(blocks, roundKeys)
}

func InvRoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	InvRoundKeyFirst2(blocks, roundKeys)
}

func InvRoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	InvRoundKeyFirst4(blocks, roundKeys)
}

func InvFinalRoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	InvFinalRoundKeyFirst2(blocks, roundKeys)
}

func InvFinalRoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	InvFinalRoundKeyFirst4(blocks, roundKeys)
}

func RoundNoKey2HW(blocks *Block2) {
	RoundNoKey2(blocks)
}

func RoundNoKey4HW(blocks *Block4) {
	RoundNoKey4(blocks)
}

func FinalRoundNoKey2HW(blocks *Block2) {
	FinalRoundNoKey2(blocks)
}

func FinalRoundNoKey4HW(blocks *Block4) {
	FinalRoundNoKey4(blocks)
}

func InvRoundNoKey2HW(blocks *Block2) {
	InvRoundNoKey2(blocks)
}

func InvRoundNoKey4HW(blocks *Block4) {
	InvRoundNoKey4(blocks)
}

func InvFinalRoundNoKey2HW(blocks *Block2) {
	InvFinalRoundNoKey2(blocks)
}

func InvFinalRoundNoKey4HW(blocks *Block4) {
	InvFinalRoundNoKey4(blocks)
}
