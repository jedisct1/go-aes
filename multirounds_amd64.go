//go:build amd64 && !purego

package aes

//go:noescape
func aesniRounds4(block *Block, roundKeys *RoundKeys4)

//go:noescape
func aesniInvRounds4(block *Block, roundKeys *RoundKeys4)

//go:noescape
func aesniRounds6(block *Block, roundKeys *RoundKeys6)

//go:noescape
func aesniInvRounds6(block *Block, roundKeys *RoundKeys6)

//go:noescape
func aesniRounds7(block *Block, roundKeys *RoundKeys7)

//go:noescape
func aesniInvRounds7(block *Block, roundKeys *RoundKeys7)

//go:noescape
func aesniRounds10(block *Block, roundKeys *RoundKeys10)

//go:noescape
func aesniInvRounds10(block *Block, roundKeys *RoundKeys10)

//go:noescape
func aesniRounds12(block *Block, roundKeys *RoundKeys12)

//go:noescape
func aesniInvRounds12(block *Block, roundKeys *RoundKeys12)

//go:noescape
func aesniRounds14(block *Block, roundKeys *RoundKeys14)

//go:noescape
func aesniInvRounds14(block *Block, roundKeys *RoundKeys14)

//go:noescape
func aesniRounds4NoKey(block *Block)

//go:noescape
//nolint:unused
func aesniInvRounds4NoKey(block *Block)

//go:noescape
func aesniRounds7NoKey(block *Block)

//go:noescape
//nolint:unused
func aesniInvRounds7NoKey(block *Block)

//go:noescape
func aesniRounds10NoKey(block *Block)

//go:noescape
//nolint:unused
func aesniInvRounds10NoKey(block *Block)

//go:noescape
func aesniRounds12NoKey(block *Block)

//go:noescape
//nolint:unused
func aesniInvRounds12NoKey(block *Block)

//go:noescape
func aesniRounds14NoKey(block *Block)

//go:noescape
//nolint:unused
func aesniInvRounds14NoKey(block *Block)

//go:noescape
func aesniRounds6WithFinal(block *Block, roundKeys *RoundKeys6)

//go:noescape
func aesniRounds10WithFinal(block *Block, roundKeys *RoundKeys10)

//go:noescape
func aesniRounds12WithFinal(block *Block, roundKeys *RoundKeys12)

//go:noescape
func aesniRounds14WithFinal(block *Block, roundKeys *RoundKeys14)

//go:noescape
func aesniInvRounds4WithFinal(block *Block, roundKeys *RoundKeys4)

//go:noescape
func aesniInvRounds6WithFinal(block *Block, roundKeys *RoundKeys6)

//go:noescape
func aesniInvRounds7WithFinal(block *Block, roundKeys *RoundKeys7)

//go:noescape
func aesniInvRounds10WithFinal(block *Block, roundKeys *RoundKeys10)

//go:noescape
func aesniInvRounds12WithFinal(block *Block, roundKeys *RoundKeys12)

//go:noescape
func aesniInvRounds14WithFinal(block *Block, roundKeys *RoundKeys14)

func Rounds4HW(block *Block, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		aesniRounds4(block, roundKeys)
	} else {
		Rounds4(block, roundKeys)
	}
}

func InvRounds4HW(block *Block, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		aesniInvRounds4(block, roundKeys)
	} else {
		InvRounds4(block, roundKeys)
	}
}

func Rounds6HW(block *Block, roundKeys *RoundKeys6) {
	if CPU.HasAESNI {
		aesniRounds6(block, roundKeys)
	} else {
		Rounds6(block, roundKeys)
	}
}

func InvRounds6HW(block *Block, roundKeys *RoundKeys6) {
	if CPU.HasAESNI {
		aesniInvRounds6(block, roundKeys)
	} else {
		InvRounds6(block, roundKeys)
	}
}

func Rounds7HW(block *Block, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		aesniRounds7(block, roundKeys)
	} else {
		Rounds7(block, roundKeys)
	}
}

func InvRounds7HW(block *Block, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		aesniInvRounds7(block, roundKeys)
	} else {
		InvRounds7(block, roundKeys)
	}
}

func Rounds10HW(block *Block, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		aesniRounds10(block, roundKeys)
	} else {
		Rounds10(block, roundKeys)
	}
}

func InvRounds10HW(block *Block, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		aesniInvRounds10(block, roundKeys)
	} else {
		InvRounds10(block, roundKeys)
	}
}

func Rounds12HW(block *Block, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		aesniRounds12(block, roundKeys)
	} else {
		Rounds12(block, roundKeys)
	}
}

func InvRounds12HW(block *Block, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		aesniInvRounds12(block, roundKeys)
	} else {
		InvRounds12(block, roundKeys)
	}
}

func Rounds14HW(block *Block, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		aesniRounds14(block, roundKeys)
	} else {
		Rounds14(block, roundKeys)
	}
}

func InvRounds14HW(block *Block, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		aesniInvRounds14(block, roundKeys)
	} else {
		InvRounds14(block, roundKeys)
	}
}

func Rounds4NoKeyHW(block *Block) {
	if CPU.HasAESNI {
		aesniRounds4NoKey(block)
	} else {
		Rounds4NoKey(block)
	}
}

// Falls back to software due to AESDEC operation order mismatch.
func InvRounds4NoKeyHW(block *Block) {
	InvRounds4NoKey(block)
}

func Rounds7NoKeyHW(block *Block) {
	if CPU.HasAESNI {
		aesniRounds7NoKey(block)
	} else {
		Rounds7NoKey(block)
	}
}

func InvRounds7NoKeyHW(block *Block) {
	InvRounds7NoKey(block)
}

func Rounds10NoKeyHW(block *Block) {
	if CPU.HasAESNI {
		aesniRounds10NoKey(block)
	} else {
		Rounds10NoKey(block)
	}
}

func InvRounds10NoKeyHW(block *Block) {
	InvRounds10NoKey(block)
}

func Rounds12NoKeyHW(block *Block) {
	if CPU.HasAESNI {
		aesniRounds12NoKey(block)
	} else {
		Rounds12NoKey(block)
	}
}

func InvRounds12NoKeyHW(block *Block) {
	InvRounds12NoKey(block)
}

func Rounds14NoKeyHW(block *Block) {
	if CPU.HasAESNI {
		aesniRounds14NoKey(block)
	} else {
		Rounds14NoKey(block)
	}
}

func InvRounds14NoKeyHW(block *Block) {
	InvRounds14NoKey(block)
}

func Rounds6WithFinalHW(block *Block, roundKeys *RoundKeys6) {
	if CPU.HasAESNI {
		aesniRounds6WithFinal(block, roundKeys)
	} else {
		Rounds6WithFinal(block, roundKeys)
	}
}

func Rounds10WithFinalHW(block *Block, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		aesniRounds10WithFinal(block, roundKeys)
	} else {
		Rounds10WithFinal(block, roundKeys)
	}
}

func Rounds12WithFinalHW(block *Block, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		aesniRounds12WithFinal(block, roundKeys)
	} else {
		Rounds12WithFinal(block, roundKeys)
	}
}

func Rounds14WithFinalHW(block *Block, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		aesniRounds14WithFinal(block, roundKeys)
	} else {
		Rounds14WithFinal(block, roundKeys)
	}
}

func InvRounds4WithFinalHW(block *Block, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		aesniInvRounds4WithFinal(block, roundKeys)
	} else {
		InvRounds4WithFinal(block, roundKeys)
	}
}

func InvRounds6WithFinalHW(block *Block, roundKeys *RoundKeys6) {
	if CPU.HasAESNI {
		aesniInvRounds6WithFinal(block, roundKeys)
	} else {
		InvRounds6WithFinal(block, roundKeys)
	}
}

func InvRounds7WithFinalHW(block *Block, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		aesniInvRounds7WithFinal(block, roundKeys)
	} else {
		InvRounds7WithFinal(block, roundKeys)
	}
}

func InvRounds10WithFinalHW(block *Block, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		aesniInvRounds10WithFinal(block, roundKeys)
	} else {
		InvRounds10WithFinal(block, roundKeys)
	}
}

func InvRounds12WithFinalHW(block *Block, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		aesniInvRounds12WithFinal(block, roundKeys)
	} else {
		InvRounds12WithFinal(block, roundKeys)
	}
}

func InvRounds14WithFinalHW(block *Block, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		aesniInvRounds14WithFinal(block, roundKeys)
	} else {
		InvRounds14WithFinal(block, roundKeys)
	}
}

func Rounds4_2HW(blocks *Block2, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 4; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
		}
	} else {
		Rounds4_2(blocks, roundKeys)
	}
}

func InvRounds4_2HW(blocks *Block2, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 4; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
		}
	} else {
		InvRounds4_2(blocks, roundKeys)
	}
}

func Rounds7_2HW(blocks *Block2, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 7; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
		}
	} else {
		Rounds7_2(blocks, roundKeys)
	}
}

func InvRounds7_2HW(blocks *Block2, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 7; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
		}
	} else {
		InvRounds7_2(blocks, roundKeys)
	}
}

func Rounds10_2HW(blocks *Block2, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 10; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
		}
	} else {
		Rounds10_2(blocks, roundKeys)
	}
}

func InvRounds10_2HW(blocks *Block2, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 10; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
		}
	} else {
		InvRounds10_2(blocks, roundKeys)
	}
}

func Rounds12_2HW(blocks *Block2, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 12; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
		}
	} else {
		Rounds12_2(blocks, roundKeys)
	}
}

func InvRounds12_2HW(blocks *Block2, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 12; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
		}
	} else {
		InvRounds12_2(blocks, roundKeys)
	}
}

func Rounds14_2HW(blocks *Block2, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 14; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
		}
	} else {
		Rounds14_2(blocks, roundKeys)
	}
}

func InvRounds14_2HW(blocks *Block2, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		for i := 0; i < 14; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
		}
	} else {
		InvRounds14_2(blocks, roundKeys)
	}
}

func Rounds4_4HW(blocks *Block4, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 4; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
	} else {
		Rounds4_4(blocks, roundKeys)
	}
}

func InvRounds4_4HW(blocks *Block4, roundKeys *RoundKeys4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 4; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
			aesniInvRound(b2, &roundKeys[i])
			aesniInvRound(b3, &roundKeys[i])
		}
	} else {
		InvRounds4_4(blocks, roundKeys)
	}
}

func Rounds7_4HW(blocks *Block4, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 7; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
	} else {
		Rounds7_4(blocks, roundKeys)
	}
}

func InvRounds7_4HW(blocks *Block4, roundKeys *RoundKeys7) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 7; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
			aesniInvRound(b2, &roundKeys[i])
			aesniInvRound(b3, &roundKeys[i])
		}
	} else {
		InvRounds7_4(blocks, roundKeys)
	}
}

func Rounds10_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 10; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
	} else {
		Rounds10_4(blocks, roundKeys)
	}
}

func InvRounds10_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 10; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
			aesniInvRound(b2, &roundKeys[i])
			aesniInvRound(b3, &roundKeys[i])
		}
	} else {
		InvRounds10_4(blocks, roundKeys)
	}
}

func Rounds12_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 12; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
	} else {
		Rounds12_4(blocks, roundKeys)
	}
}

func InvRounds12_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 12; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
			aesniInvRound(b2, &roundKeys[i])
			aesniInvRound(b3, &roundKeys[i])
		}
	} else {
		InvRounds12_4(blocks, roundKeys)
	}
}

func Rounds14_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 14; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
	} else {
		Rounds14_4(blocks, roundKeys)
	}
}

func InvRounds14_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 14; i++ {
			aesniInvRound(b0, &roundKeys[i])
			aesniInvRound(b1, &roundKeys[i])
			aesniInvRound(b2, &roundKeys[i])
			aesniInvRound(b3, &roundKeys[i])
		}
	} else {
		InvRounds14_4(blocks, roundKeys)
	}
}

func Rounds10WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys10) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 9; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
		aesniFinalRound(b0, &roundKeys[9])
		aesniFinalRound(b1, &roundKeys[9])
		aesniFinalRound(b2, &roundKeys[9])
		aesniFinalRound(b3, &roundKeys[9])
	} else {
		Rounds10WithFinal_4(blocks, roundKeys)
	}
}

func Rounds12WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys12) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 11; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
		aesniFinalRound(b0, &roundKeys[11])
		aesniFinalRound(b1, &roundKeys[11])
		aesniFinalRound(b2, &roundKeys[11])
		aesniFinalRound(b3, &roundKeys[11])
	} else {
		Rounds12WithFinal_4(blocks, roundKeys)
	}
}

func Rounds14WithFinal_4HW(blocks *Block4, roundKeys *RoundKeys14) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		for i := 0; i < 13; i++ {
			aesniRound(b0, &roundKeys[i])
			aesniRound(b1, &roundKeys[i])
			aesniRound(b2, &roundKeys[i])
			aesniRound(b3, &roundKeys[i])
		}
		aesniFinalRound(b0, &roundKeys[13])
		aesniFinalRound(b1, &roundKeys[13])
		aesniFinalRound(b2, &roundKeys[13])
		aesniFinalRound(b3, &roundKeys[13])
	} else {
		Rounds14WithFinal_4(blocks, roundKeys)
	}
}

func Rounds4NoKey_2HW(blocks *Block2) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 4; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
		}
	} else {
		Rounds4NoKey_2(blocks)
	}
}

func Rounds10NoKey_2HW(blocks *Block2) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 10; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
		}
	} else {
		Rounds10NoKey_2(blocks)
	}
}

func Rounds4NoKey_4HW(blocks *Block4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 4; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
			aesniRound(b2, &zeroKey)
			aesniRound(b3, &zeroKey)
		}
	} else {
		Rounds4NoKey_4(blocks)
	}
}

func Rounds7NoKey_2HW(blocks *Block2) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 7; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
		}
	} else {
		Rounds7NoKey_2(blocks)
	}
}

func Rounds12NoKey_2HW(blocks *Block2) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 12; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
		}
	} else {
		Rounds12NoKey_2(blocks)
	}
}

func Rounds14NoKey_2HW(blocks *Block2) {
	if CPU.HasAESNI {
		b0, b1 := block2Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 14; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
		}
	} else {
		Rounds14NoKey_2(blocks)
	}
}

func Rounds7NoKey_4HW(blocks *Block4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 7; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
			aesniRound(b2, &zeroKey)
			aesniRound(b3, &zeroKey)
		}
	} else {
		Rounds7NoKey_4(blocks)
	}
}

func Rounds10NoKey_4HW(blocks *Block4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 10; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
			aesniRound(b2, &zeroKey)
			aesniRound(b3, &zeroKey)
		}
	} else {
		Rounds10NoKey_4(blocks)
	}
}

func Rounds12NoKey_4HW(blocks *Block4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 12; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
			aesniRound(b2, &zeroKey)
			aesniRound(b3, &zeroKey)
		}
	} else {
		Rounds12NoKey_4(blocks)
	}
}

func Rounds14NoKey_4HW(blocks *Block4) {
	if CPU.HasAESNI {
		b0, b1, b2, b3 := block4Ptrs(blocks)
		var zeroKey Block
		for i := 0; i < 14; i++ {
			aesniRound(b0, &zeroKey)
			aesniRound(b1, &zeroKey)
			aesniRound(b2, &zeroKey)
			aesniRound(b3, &zeroKey)
		}
	} else {
		Rounds14NoKey_4(blocks)
	}
}

func InvRounds4NoKey_2HW(blocks *Block2) {
	InvRounds4NoKey_2(blocks)
}

func InvRounds7NoKey_2HW(blocks *Block2) {
	InvRounds7NoKey_2(blocks)
}

func InvRounds10NoKey_2HW(blocks *Block2) {
	InvRounds10NoKey_2(blocks)
}

func InvRounds12NoKey_2HW(blocks *Block2) {
	InvRounds12NoKey_2(blocks)
}

func InvRounds14NoKey_2HW(blocks *Block2) {
	InvRounds14NoKey_2(blocks)
}

func InvRounds4NoKey_4HW(blocks *Block4) {
	InvRounds4NoKey_4(blocks)
}

func InvRounds7NoKey_4HW(blocks *Block4) {
	InvRounds7NoKey_4(blocks)
}

func InvRounds10NoKey_4HW(blocks *Block4) {
	InvRounds10NoKey_4(blocks)
}

func InvRounds12NoKey_4HW(blocks *Block4) {
	InvRounds12NoKey_4(blocks)
}

func InvRounds14NoKey_4HW(blocks *Block4) {
	InvRounds14NoKey_4(blocks)
}

func PerBlockRounds4_2HW(blocks *Block2, keySets *PerBlockRoundKeys4_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 4 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
	} else {
		PerBlockRounds4_2(blocks, keySets)
	}
}

func PerBlockRounds7_2HW(blocks *Block2, keySets *PerBlockRoundKeys7_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 7 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
	} else {
		PerBlockRounds7_2(blocks, keySets)
	}
}

func PerBlockRounds10_2HW(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 10 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
	} else {
		PerBlockRounds10_2(blocks, keySets)
	}
}

func PerBlockRounds12_2HW(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 12 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
	} else {
		PerBlockRounds12_2(blocks, keySets)
	}
}

func PerBlockRounds14_2HW(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 14 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
	} else {
		PerBlockRounds14_2(blocks, keySets)
	}
}

func PerBlockRounds10WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys10_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 9 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
		FinalRoundHW(b0, &keySets[0][9])
		FinalRoundHW(b1, &keySets[1][9])
	} else {
		PerBlockRounds10WithFinal_2(blocks, keySets)
	}
}

func PerBlockRounds12WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys12_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 11 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
		FinalRoundHW(b0, &keySets[0][11])
		FinalRoundHW(b1, &keySets[1][11])
	} else {
		PerBlockRounds12WithFinal_2(blocks, keySets)
	}
}

func PerBlockRounds14WithFinal_2HW(blocks *Block2, keySets *PerBlockRoundKeys14_2) {
	b0, b1 := block2Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 13 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
		}
		FinalRoundHW(b0, &keySets[0][13])
		FinalRoundHW(b1, &keySets[1][13])
	} else {
		PerBlockRounds14WithFinal_2(blocks, keySets)
	}
}

func PerBlockRounds4_4HW(blocks *Block4, keySets *PerBlockRoundKeys4_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 4 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
	} else {
		PerBlockRounds4_4(blocks, keySets)
	}
}

func PerBlockRounds7_4HW(blocks *Block4, keySets *PerBlockRoundKeys7_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 7 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
	} else {
		PerBlockRounds7_4(blocks, keySets)
	}
}

func PerBlockRounds10_4HW(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 10 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
	} else {
		PerBlockRounds10_4(blocks, keySets)
	}
}

func PerBlockRounds12_4HW(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 12 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
	} else {
		PerBlockRounds12_4(blocks, keySets)
	}
}

func PerBlockRounds14_4HW(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 14 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
	} else {
		PerBlockRounds14_4(blocks, keySets)
	}
}

func PerBlockRounds10WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys10_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 9 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
		FinalRoundHW(b0, &keySets[0][9])
		FinalRoundHW(b1, &keySets[1][9])
		FinalRoundHW(b2, &keySets[2][9])
		FinalRoundHW(b3, &keySets[3][9])
	} else {
		PerBlockRounds10WithFinal_4(blocks, keySets)
	}
}

func PerBlockRounds12WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys12_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 11 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
		FinalRoundHW(b0, &keySets[0][11])
		FinalRoundHW(b1, &keySets[1][11])
		FinalRoundHW(b2, &keySets[2][11])
		FinalRoundHW(b3, &keySets[3][11])
	} else {
		PerBlockRounds12WithFinal_4(blocks, keySets)
	}
}

func PerBlockRounds14WithFinal_4HW(blocks *Block4, keySets *PerBlockRoundKeys14_4) {
	b0, b1, b2, b3 := block4Ptrs(blocks)
	if CPU.HasAESNI {
		for i := range 13 {
			RoundHW(b0, &keySets[0][i])
			RoundHW(b1, &keySets[1][i])
			RoundHW(b2, &keySets[2][i])
			RoundHW(b3, &keySets[3][i])
		}
		FinalRoundHW(b0, &keySets[0][13])
		FinalRoundHW(b1, &keySets[1][13])
		FinalRoundHW(b2, &keySets[2][13])
		FinalRoundHW(b3, &keySets[3][13])
	} else {
		PerBlockRounds14WithFinal_4(blocks, keySets)
	}
}
