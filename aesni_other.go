//go:build (!amd64 && !arm64) || purego

package aes

// Software fallback for non-AMD64 platforms

func RoundHW(block *Block, roundKey *Block) {
	Round(block, roundKey)
}

func FinalRoundHW(block *Block, roundKey *Block) {
	FinalRound(block, roundKey)
}

func InvRoundHW(block *Block, roundKey *Block) {
	InvRound(block, roundKey)
}

func InvFinalRoundHW(block *Block, roundKey *Block) {
	InvFinalRound(block, roundKey)
}

func InvMixColumnsHW(block *Block) {
	InvMixColumns(block)
}

func RoundKeyFirstHW(block *Block, roundKey *Block) {
	RoundKeyFirst(block, roundKey)
}

func FinalRoundKeyFirstHW(block *Block, roundKey *Block) {
	FinalRoundKeyFirst(block, roundKey)
}

func InvRoundKeyFirstHW(block *Block, roundKey *Block) {
	InvRoundKeyFirst(block, roundKey)
}

func InvFinalRoundKeyFirstHW(block *Block, roundKey *Block) {
	InvFinalRoundKeyFirst(block, roundKey)
}

func RoundNoKeyHW(block *Block) {
	RoundNoKey(block)
}

func FinalRoundNoKeyHW(block *Block) {
	FinalRoundNoKey(block)
}

func InvRoundNoKeyHW(block *Block) {
	InvRoundNoKey(block)
}

func InvFinalRoundNoKeyHW(block *Block) {
	InvFinalRoundNoKey(block)
}
