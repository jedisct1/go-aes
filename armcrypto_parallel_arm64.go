//go:build arm64 && !purego

package aes

// Hardware-accelerated parallel AES round functions using ARM Crypto Extensions
// These reduce Go/Assembly boundary crossings by processing multiple blocks per call

// Standard round variants (key XOR at end)

//go:noescape
func armRound2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armFinalRound2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armInvRound2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armInvFinalRound2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armRound4(blocks *Block4, roundKeys *Key4)

//go:noescape
func armFinalRound4(blocks *Block4, roundKeys *Key4)

//go:noescape
func armInvRound4(blocks *Block4, roundKeys *Key4)

//go:noescape
func armInvFinalRound4(blocks *Block4, roundKeys *Key4)

// KeyFirst variants (key XOR at beginning - native ARM semantics)

//go:noescape
func armRoundKeyFirst2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armFinalRoundKeyFirst2(blocks *Block2, roundKeys *Key2)

//go:noescape
func armRoundKeyFirst4(blocks *Block4, roundKeys *Key4)

//go:noescape
func armFinalRoundKeyFirst4(blocks *Block4, roundKeys *Key4)

// Round2HW performs one AES encryption round on 2 blocks with hardware acceleration if available
func Round2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armRound2(blocks, roundKeys)
	} else {
		Round2(blocks, roundKeys)
	}
}

// Round4HW performs one AES encryption round on 4 blocks with hardware acceleration if available
func Round4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armRound4(blocks, roundKeys)
	} else {
		Round4(blocks, roundKeys)
	}
}

// FinalRound2HW performs the final AES encryption round on 2 blocks with hardware acceleration if available
func FinalRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armFinalRound2(blocks, roundKeys)
	} else {
		FinalRound2(blocks, roundKeys)
	}
}

// FinalRound4HW performs the final AES encryption round on 4 blocks with hardware acceleration if available
func FinalRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armFinalRound4(blocks, roundKeys)
	} else {
		FinalRound4(blocks, roundKeys)
	}
}

// InvRound2HW performs one AES decryption round on 2 blocks with hardware acceleration if available
func InvRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armInvRound2(blocks, roundKeys)
	} else {
		InvRound2(blocks, roundKeys)
	}
}

// InvRound4HW performs one AES decryption round on 4 blocks with hardware acceleration if available
func InvRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armInvRound4(blocks, roundKeys)
	} else {
		InvRound4(blocks, roundKeys)
	}
}

// InvFinalRound2HW performs the final AES decryption round on 2 blocks with hardware acceleration if available
func InvFinalRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armInvFinalRound2(blocks, roundKeys)
	} else {
		InvFinalRound2(blocks, roundKeys)
	}
}

// InvFinalRound4HW performs the final AES decryption round on 4 blocks with hardware acceleration if available
func InvFinalRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armInvFinalRound4(blocks, roundKeys)
	} else {
		InvFinalRound4(blocks, roundKeys)
	}
}

// InvMixColumns2HW performs inverse MixColumns on 2 blocks with hardware acceleration if available
func InvMixColumns2HW(blocks *Block2) {
	if CPU.HasARMCrypto {
		// ARM doesn't have a dedicated parallel InvMixColumns, use individual blocks
		b0 := (*Block)(blocks[0:16])
		b1 := (*Block)(blocks[16:32])
		InvMixColumnsHW(b0)
		InvMixColumnsHW(b1)
	} else {
		b0 := (*Block)(blocks[0:16])
		b1 := (*Block)(blocks[16:32])
		InvMixColumns(b0)
		InvMixColumns(b1)
	}
}

// InvMixColumns4HW performs inverse MixColumns on 4 blocks with hardware acceleration if available
func InvMixColumns4HW(blocks *Block4) {
	if CPU.HasARMCrypto {
		// ARM doesn't have a dedicated parallel InvMixColumns, use individual blocks
		b0 := (*Block)(blocks[0:16])
		b1 := (*Block)(blocks[16:32])
		b2 := (*Block)(blocks[32:48])
		b3 := (*Block)(blocks[48:64])
		InvMixColumnsHW(b0)
		InvMixColumnsHW(b1)
		InvMixColumnsHW(b2)
		InvMixColumnsHW(b3)
	} else {
		b0 := (*Block)(blocks[0:16])
		b1 := (*Block)(blocks[16:32])
		b2 := (*Block)(blocks[32:48])
		b3 := (*Block)(blocks[48:64])
		InvMixColumns(b0)
		InvMixColumns(b1)
		InvMixColumns(b2)
		InvMixColumns(b3)
	}
}

// KeyFirst variants - these are more efficient on ARM since they match native AESE semantics

func RoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armRoundKeyFirst2(blocks, roundKeys)
	} else {
		RoundKeyFirst2(blocks, roundKeys)
	}
}

func RoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armRoundKeyFirst4(blocks, roundKeys)
	} else {
		RoundKeyFirst4(blocks, roundKeys)
	}
}

func FinalRoundKeyFirst2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasARMCrypto {
		armFinalRoundKeyFirst2(blocks, roundKeys)
	} else {
		FinalRoundKeyFirst2(blocks, roundKeys)
	}
}

func FinalRoundKeyFirst4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasARMCrypto {
		armFinalRoundKeyFirst4(blocks, roundKeys)
	} else {
		FinalRoundKeyFirst4(blocks, roundKeys)
	}
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

// NoKey variants use software fallback

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
