package aes

// AESPRF is a pseudorandom function built from AES (Mennink and Neves, ToSC 2017(3)).
//
// It encrypts the input with AES, then XORs the result with the state
// from the middle of that encryption.
//
// The middle state is taken after round 4 with a 128-bit key, round 6 with
// a 192-bit key and round 7 with a 256-bit key.
//
// For 128-bit keys, this uses round 4 instead of Mennink and Neves's original
// round 5. This choice follows the analysis of Derbez et al., ToSC 2018(2).
// It therefore differs from Mennink and Neves's AES-PRF-128 instance.
//
// References:
//   - Mennink and Neves, "Optimal PRFs from Blockcipher Designs":
//     https://doi.org/10.13154/tosc.v2017.i3.228-252
//   - Derbez et al., "Cryptanalysis of AES-PRF and Its Dual":
//     https://doi.org/10.13154/tosc.v2018.i2.161-191
type AESPRF struct {
	rounds int
	rk     [15]Block
}

// NewAESPRF returns an AES-PRF instance for a 16, 24 or 32-byte key.
func NewAESPRF(key []byte) (*AESPRF, error) {
	ks, err := NewKeySchedule(key)
	if err != nil {
		return nil, err
	}
	prf := &AESPRF{rounds: ks.Rounds()}
	copy(prf.rk[:], ks.keys)
	return prf, nil
}

// PRF replaces the block with its AES-PRF output.
func (prf *AESPRF) PRF(block *Block) {
	rk := &prf.rk

	AddRoundKey(block, &rk[0])

	// Computing mid on its own repeats a few rounds, but it lets the CPU
	// work on both at the same time, which is faster with AES instructions.
	mid := *block
	switch prf.rounds {
	case 10:
		Rounds4HW(&mid, (*RoundKeys4)(rk[1:5]))
		Rounds10WithFinalHW(block, (*RoundKeys10)(rk[1:11]))
	case 12:
		Rounds6HW(&mid, (*RoundKeys6)(rk[1:7]))
		Rounds12WithFinalHW(block, (*RoundKeys12)(rk[1:13]))
	case 14:
		Rounds7HW(&mid, (*RoundKeys7)(rk[1:8]))
		Rounds14WithFinalHW(block, (*RoundKeys14)(rk[1:15]))
	default:
		panic("aes: AESPRF must be created with NewAESPRF")
	}
	XorBlock(block, block, &mid)
}
