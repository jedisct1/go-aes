//go:build arm64 && !purego

package aes

// Hardware-accelerated AES round functions using ARM Crypto extensions

// armRound performs one AES encryption round using ARM Crypto
//
//go:noescape
func armRound(block *Block, roundKey *Block)

// armFinalRound performs the final AES encryption round using ARM Crypto
//
//go:noescape
func armFinalRound(block *Block, roundKey *Block)

// armInvRound performs one AES decryption round using ARM Crypto
//
//go:noescape
func armInvRound(block *Block, roundKey *Block)

// armInvFinalRound performs the final AES decryption round using ARM Crypto
//
//go:noescape
func armInvFinalRound(block *Block, roundKey *Block)

// armInvMixColumns performs inverse MixColumns using ARM Crypto
//
//go:noescape
func armInvMixColumns(block *Block)

// armRoundKeyFirst performs one AES encryption round with key XOR first using ARM Crypto
//
//go:noescape
func armRoundKeyFirst(block *Block, roundKey *Block)

// armFinalRoundKeyFirst performs the final AES encryption round with key XOR first using ARM Crypto
//
//go:noescape
func armFinalRoundKeyFirst(block *Block, roundKey *Block)

// armInvRoundKeyFirst performs one AES decryption round with key XOR first using ARM Crypto
//
//go:noescape
func armInvRoundKeyFirst(block *Block, roundKey *Block)

// armInvFinalRoundKeyFirst performs the final AES decryption round with key XOR first using ARM Crypto
//
//go:noescape
func armInvFinalRoundKeyFirst(block *Block, roundKey *Block)

// armRoundNoKey performs one AES encryption round without AddRoundKey using ARM Crypto
//
//go:noescape
func armRoundNoKey(block *Block)

// armFinalRoundNoKey performs the final AES encryption round without AddRoundKey using ARM Crypto
//
//go:noescape
func armFinalRoundNoKey(block *Block)

// armInvRoundNoKey performs one AES decryption round without AddRoundKey using ARM Crypto
//
//go:noescape
func armInvRoundNoKey(block *Block)

// armInvFinalRoundNoKey performs the final AES decryption round without AddRoundKey using ARM Crypto
//
//go:noescape
func armInvFinalRoundNoKey(block *Block)

// RoundHW performs one AES encryption round with hardware acceleration if available
func RoundHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armRound(block, roundKey)
	} else {
		Round(block, roundKey)
	}
}

// FinalRoundHW performs the final AES encryption round with hardware acceleration if available
func FinalRoundHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armFinalRound(block, roundKey)
	} else {
		FinalRound(block, roundKey)
	}
}

// InvRoundHW performs one AES decryption round with hardware acceleration if available
func InvRoundHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armInvRound(block, roundKey)
	} else {
		InvRound(block, roundKey)
	}
}

// InvFinalRoundHW performs the final AES decryption round with hardware acceleration if available
func InvFinalRoundHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armInvFinalRound(block, roundKey)
	} else {
		InvFinalRound(block, roundKey)
	}
}

// InvMixColumnsHW performs inverse MixColumns with hardware acceleration if available
func InvMixColumnsHW(block *Block) {
	if CPU.HasARMCrypto {
		armInvMixColumns(block)
	} else {
		InvMixColumns(block)
	}
}

// RoundKeyFirstHW performs one AES encryption round (key XOR first) with hardware acceleration if available
func RoundKeyFirstHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armRoundKeyFirst(block, roundKey)
	} else {
		RoundKeyFirst(block, roundKey)
	}
}

// FinalRoundKeyFirstHW performs the final AES encryption round (key XOR first) with hardware acceleration if available
func FinalRoundKeyFirstHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armFinalRoundKeyFirst(block, roundKey)
	} else {
		FinalRoundKeyFirst(block, roundKey)
	}
}

// InvRoundKeyFirstHW performs one AES decryption round (key XOR first) with hardware acceleration if available
func InvRoundKeyFirstHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armInvRoundKeyFirst(block, roundKey)
	} else {
		InvRoundKeyFirst(block, roundKey)
	}
}

// InvFinalRoundKeyFirstHW performs the final AES decryption round (key XOR first) with hardware acceleration if available
func InvFinalRoundKeyFirstHW(block *Block, roundKey *Block) {
	if CPU.HasARMCrypto {
		armInvFinalRoundKeyFirst(block, roundKey)
	} else {
		InvFinalRoundKeyFirst(block, roundKey)
	}
}

// RoundNoKeyHW performs one AES encryption round without AddRoundKey with hardware acceleration if available
func RoundNoKeyHW(block *Block) {
	if CPU.HasARMCrypto {
		armRoundNoKey(block)
	} else {
		RoundNoKey(block)
	}
}

// FinalRoundNoKeyHW performs the final AES encryption round without AddRoundKey with hardware acceleration if available
func FinalRoundNoKeyHW(block *Block) {
	if CPU.HasARMCrypto {
		armFinalRoundNoKey(block)
	} else {
		FinalRoundNoKey(block)
	}
}

// InvRoundNoKeyHW performs one AES decryption round without AddRoundKey with hardware acceleration if available
func InvRoundNoKeyHW(block *Block) {
	if CPU.HasARMCrypto {
		armInvRoundNoKey(block)
	} else {
		InvRoundNoKey(block)
	}
}

// InvFinalRoundNoKeyHW performs the final AES decryption round without AddRoundKey with hardware acceleration if available
func InvFinalRoundNoKeyHW(block *Block) {
	if CPU.HasARMCrypto {
		armInvFinalRoundNoKey(block)
	} else {
		InvFinalRoundNoKey(block)
	}
}
