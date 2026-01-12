//go:build amd64 && !purego

package aes

// Hardware-accelerated AES round functions using Intel AES-NI instructions

// aesniRound performs one AES encryption round using AES-NI
//
//go:noescape
func aesniRound(block *Block, roundKey *Block)

// aesniFinalRound performs the final AES encryption round using AES-NI
//
//go:noescape
func aesniFinalRound(block *Block, roundKey *Block)

// aesniInvRound performs one AES decryption round using AES-NI
//
//go:noescape
func aesniInvRound(block *Block, roundKey *Block)

// aesniInvFinalRound performs the final AES decryption round using AES-NI
//
//go:noescape
func aesniInvFinalRound(block *Block, roundKey *Block)

// aesniInvMixColumns performs inverse MixColumns using AES-NI
//
//go:noescape
func aesniInvMixColumns(block *Block)

// RoundHW performs one AES encryption round with hardware acceleration if available
func RoundHW(block *Block, roundKey *Block) {
	if CPU.HasAESNI {
		aesniRound(block, roundKey)
	} else {
		Round(block, roundKey)
	}
}

// FinalRoundHW performs the final AES encryption round with hardware acceleration if available
func FinalRoundHW(block *Block, roundKey *Block) {
	if CPU.HasAESNI {
		aesniFinalRound(block, roundKey)
	} else {
		FinalRound(block, roundKey)
	}
}

// InvRoundHW performs one AES decryption round with hardware acceleration if available
func InvRoundHW(block *Block, roundKey *Block) {
	if CPU.HasAESNI {
		// Software InvRound does: InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey
		// Intel AESDEC does: InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey
		// They match, so use AESDEC directly
		aesniInvRound(block, roundKey)
	} else {
		InvRound(block, roundKey)
	}
}

// InvFinalRoundHW performs the final AES decryption round with hardware acceleration if available
func InvFinalRoundHW(block *Block, roundKey *Block) {
	if CPU.HasAESNI {
		aesniInvFinalRound(block, roundKey)
	} else {
		InvFinalRound(block, roundKey)
	}
}

// InvMixColumnsHW performs inverse MixColumns with hardware acceleration if available
func InvMixColumnsHW(block *Block) {
	if CPU.HasAESNI {
		aesniInvMixColumns(block)
	} else {
		InvMixColumns(block)
	}
}

// KeyFirst variants fall back to software on Intel since AES-NI instructions
// naturally XOR the key at the end (standard semantics)
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

// NoKey variants use software fallback on Intel since AES-NI instructions
// always include the key XOR operation
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
