package aes

// KiasuEncryptHW encrypts a single 16-byte block using KIASU-BC with hardware acceleration.
// It uses hardware-accelerated multi-round AES functions when available.
func (ctx *KiasuContext) KiasuEncryptHW(block [16]byte, tweak [8]byte) [16]byte {
	tweakedKeys := ctx.getTweakedKeys(tweak)
	b := (*Block)(&block)

	// Initial AddRoundKey
	AddRoundKey(b, &tweakedKeys[0])

	// 9 full rounds + 1 final round using hardware-accelerated multi-round function
	var keys RoundKeys10
	for i := range 10 {
		keys[i] = tweakedKeys[i+1]
	}
	Rounds10WithFinalHW(b, &keys)

	return block
}

// KiasuDecryptHW decrypts a single 16-byte block using KIASU-BC with hardware acceleration.
// It uses hardware-accelerated multi-round AES functions when available.
func (ctx *KiasuContext) KiasuDecryptHW(block [16]byte, tweak [8]byte) [16]byte {
	tweakedKeys := ctx.getTweakedKeys(tweak)

	// Create inverse keys by applying InvMixColumns to middle keys (rounds 1-9)
	var invKeys RoundKeys10
	invKeys[9] = tweakedKeys[0] // First encryption key becomes last decryption key (no InvMixColumns)
	for i := 0; i < 9; i++ {
		invKeys[i] = tweakedKeys[9-i]
		InvMixColumns(&invKeys[i])
	}

	b := (*Block)(&block)
	AddRoundKey(b, &tweakedKeys[10]) // Initial AddRoundKey with last encryption key

	// 9 inverse rounds + 1 inverse final round using hardware-accelerated multi-round function
	InvRounds10WithFinalHW(b, &invKeys)

	return block
}
