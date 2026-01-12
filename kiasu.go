package aes

// KIASU-BC is a tweakable block cipher based on AES-128.
// It extends AES-128 by incorporating an 8-byte tweak into each round.
// The tweak is padded to 16 bytes and XORed with each round key.

// KiasuContext holds the base key schedule for KIASU-BC encryption/decryption.
// For each encryption/decryption, a tweaked key schedule is created by XORing
// the base key schedule with the padded tweak.
type KiasuContext struct {
	baseKS *KeySchedule
}

// NewKiasuContext creates a new KIASU-BC context with the given 16-byte key.
// The key schedule is identical to AES-128.
func NewKiasuContext(key [16]byte) (*KiasuContext, error) {
	ks, err := NewKeySchedule(key[:])
	if err != nil {
		return nil, err
	}
	return &KiasuContext{baseKS: ks}, nil
}

// getTweakedKeys creates tweaked round keys by XORing the base key schedule with the padded tweak.
func (ctx *KiasuContext) getTweakedKeys(tweak [8]byte) [11]Block {
	paddedTweak := PadTweak(tweak)
	var tweakedKeys [11]Block

	// XOR each round key with the padded tweak
	for i := 0; i <= 10; i++ {
		rk := ctx.baseKS.GetRoundKey(i)
		XorBlock(&tweakedKeys[i], rk, (*Block)(&paddedTweak))
	}

	return tweakedKeys
}

// PadTweak pads an 8-byte tweak to 16 bytes.
// The padding scheme places each 2-byte pair at the start of each 4-byte group:
// 8-byte tweak:    [T0 T1 T2 T3 T4 T5 T6 T7]
// 16-byte padded:  [T0 T1 00 00 T2 T3 00 00 T4 T5 00 00 T6 T7 00 00]
func PadTweak(tweak [8]byte) [16]byte {
	var padded [16]byte
	padded[0] = tweak[0]
	padded[1] = tweak[1]
	padded[4] = tweak[2]
	padded[5] = tweak[3]
	padded[8] = tweak[4]
	padded[9] = tweak[5]
	padded[12] = tweak[6]
	padded[13] = tweak[7]
	return padded
}

// KiasuEncrypt encrypts a single 16-byte block using KIASU-BC.
// It creates tweaked round keys by XORing the base key schedule with the padded tweak,
// then performs standard AES-128 encryption using optimized multi-round functions.
func (ctx *KiasuContext) KiasuEncrypt(block [16]byte, tweak [8]byte) [16]byte {
	tweakedKeys := ctx.getTweakedKeys(tweak)
	b := (*Block)(&block)

	// Initial AddRoundKey
	AddRoundKey(b, &tweakedKeys[0])

	// 9 full rounds + 1 final round using optimized multi-round function
	var keys RoundKeys10
	for i := range 10 {
		keys[i] = tweakedKeys[i+1]
	}
	Rounds10WithFinal(b, &keys)

	return block
}

// KiasuDecrypt decrypts a single 16-byte block using KIASU-BC.
// It creates tweaked round keys by XORing the base key schedule with the padded tweak,
// then performs standard AES-128 decryption using optimized multi-round functions.
func (ctx *KiasuContext) KiasuDecrypt(block [16]byte, tweak [8]byte) [16]byte {
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

	// 9 inverse rounds + 1 inverse final round using optimized multi-round function
	InvRounds10WithFinal(b, &invKeys)

	return block
}
