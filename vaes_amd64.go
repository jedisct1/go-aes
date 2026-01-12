//go:build amd64 && !purego

package aes

// Hardware-accelerated parallel AES round functions using VAES instructions

// vaesRound2 performs one AES encryption round on 2 blocks using VAES
//
//go:noescape
func vaesRound2(blocks *Block2, roundKeys *Key2)

// vaesFinalRound2 performs the final AES encryption round on 2 blocks using VAES
//
//go:noescape
func vaesFinalRound2(blocks *Block2, roundKeys *Key2)

// vaesInvRound2 performs one AES decryption round on 2 blocks using VAES
//
//go:noescape
func vaesInvRound2(blocks *Block2, roundKeys *Key2)

// vaesInvFinalRound2 performs the final AES decryption round on 2 blocks using VAES
//
//go:noescape
func vaesInvFinalRound2(blocks *Block2, roundKeys *Key2)

// vaesRound4 performs one AES encryption round on 4 blocks using VAES
//
//go:noescape
func vaesRound4(blocks *Block4, roundKeys *Key4)

// vaesFinalRound4 performs the final AES encryption round on 4 blocks using VAES
//
//go:noescape
func vaesFinalRound4(blocks *Block4, roundKeys *Key4)

// vaesInvRound4 performs one AES decryption round on 4 blocks using VAES
//
//go:noescape
func vaesInvRound4(blocks *Block4, roundKeys *Key4)

// vaesInvFinalRound4 performs the final AES decryption round on 4 blocks using VAES
//
//go:noescape
func vaesInvFinalRound4(blocks *Block4, roundKeys *Key4)

// vaesInvMixColumns2 performs inverse MixColumns on 2 blocks using VAES
//
//go:noescape
func vaesInvMixColumns2(blocks *Block2)

// vaesInvMixColumns4 performs inverse MixColumns on 4 blocks using VAES
//
//go:noescape
func vaesInvMixColumns4(blocks *Block4)

// Round2HW performs one AES encryption round on 2 blocks with hardware acceleration if available
func Round2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasVAES && CPU.HasAVX2 {
		vaesRound2(blocks, roundKeys)
	} else {
		Round2(blocks, roundKeys)
	}
}

// Round4HW performs one AES encryption round on 4 blocks with hardware acceleration if available
func Round4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasVAES && CPU.HasAVX512 {
		vaesRound4(blocks, roundKeys)
	} else {
		Round4(blocks, roundKeys)
	}
}

// FinalRound2HW performs the final AES encryption round on 2 blocks with hardware acceleration if available
func FinalRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasVAES && CPU.HasAVX2 {
		vaesFinalRound2(blocks, roundKeys)
	} else {
		FinalRound2(blocks, roundKeys)
	}
}

// FinalRound4HW performs the final AES encryption round on 4 blocks with hardware acceleration if available
func FinalRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasVAES && CPU.HasAVX512 {
		vaesFinalRound4(blocks, roundKeys)
	} else {
		FinalRound4(blocks, roundKeys)
	}
}

// InvRound2HW performs one AES decryption round on 2 blocks with hardware acceleration if available
func InvRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasVAES && CPU.HasAVX2 {
		// Software InvRound2 does: InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey
		// VAESDEC does the same, so use it directly
		vaesInvRound2(blocks, roundKeys)
	} else {
		InvRound2(blocks, roundKeys)
	}
}

// InvRound4HW performs one AES decryption round on 4 blocks with hardware acceleration if available
func InvRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasVAES && CPU.HasAVX512 {
		// Software InvRound4 does: InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey
		// VAESDEC does the same, so use it directly
		vaesInvRound4(blocks, roundKeys)
	} else {
		InvRound4(blocks, roundKeys)
	}
}

// InvFinalRound2HW performs the final AES decryption round on 2 blocks with hardware acceleration if available
func InvFinalRound2HW(blocks *Block2, roundKeys *Key2) {
	if CPU.HasVAES && CPU.HasAVX2 {
		vaesInvFinalRound2(blocks, roundKeys)
	} else {
		InvFinalRound2(blocks, roundKeys)
	}
}

// InvFinalRound4HW performs the final AES decryption round on 4 blocks with hardware acceleration if available
func InvFinalRound4HW(blocks *Block4, roundKeys *Key4) {
	if CPU.HasVAES && CPU.HasAVX512 {
		vaesInvFinalRound4(blocks, roundKeys)
	} else {
		InvFinalRound4(blocks, roundKeys)
	}
}

// InvMixColumns2HW performs inverse MixColumns on 2 blocks with hardware acceleration if available
func InvMixColumns2HW(blocks *Block2) {
	if CPU.HasVAES && CPU.HasAVX2 {
		vaesInvMixColumns2(blocks)
	} else {
		b0, b1 := block2Ptrs(blocks)
		InvMixColumns(b0)
		InvMixColumns(b1)
	}
}

// InvMixColumns4HW performs inverse MixColumns on 4 blocks with hardware acceleration if available
func InvMixColumns4HW(blocks *Block4) {
	if CPU.HasVAES && CPU.HasAVX512 {
		vaesInvMixColumns4(blocks)
	} else {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		InvMixColumns(b0)
		InvMixColumns(b1)
		InvMixColumns(b2)
		InvMixColumns(b3)
	}
}

// KeyFirst and NoKey variants use software fallback on Intel
// since implementing them efficiently with VAES would require additional instructions

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
