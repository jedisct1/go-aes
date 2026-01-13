package aes

import (
	"bytes"
	"testing"
)

// Test data
var (
	testBlockMR = Block{
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,
	}
)

// makeRoundKeys4 creates round keys for testing
func makeRoundKeys4() *RoundKeys4 {
	var keys RoundKeys4
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

func makeRoundKeys7() *RoundKeys7 {
	var keys RoundKeys7
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

func makeRoundKeys10() *RoundKeys10 {
	var keys RoundKeys10
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

func makeRoundKeys12() *RoundKeys12 {
	var keys RoundKeys12
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

func makeRoundKeys14() *RoundKeys14 {
	var keys RoundKeys14
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

// Test that multi-round functions match sequential single rounds
func TestRounds4MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys4()

	// Using multi-round function
	block1 := testBlockMR
	Rounds4(&block1, keys)

	// Using single rounds
	block2 := testBlockMR
	Round(&block2, &keys[0])
	Round(&block2, &keys[1])
	Round(&block2, &keys[2])
	Round(&block2, &keys[3])

	if block1 != block2 {
		t.Errorf("Rounds4 does not match 4 sequential Round calls\nRounds4:     %x\nSequential:  %x", block1, block2)
	}
}

func TestInvRounds4MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys4()

	block1 := testBlockMR
	InvRounds4(&block1, keys)

	block2 := testBlockMR
	InvRound(&block2, &keys[0])
	InvRound(&block2, &keys[1])
	InvRound(&block2, &keys[2])
	InvRound(&block2, &keys[3])

	if block1 != block2 {
		t.Errorf("InvRounds4 does not match 4 sequential InvRound calls")
	}
}

func TestRounds7MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys7()

	block1 := testBlockMR
	Rounds7(&block1, keys)

	block2 := testBlockMR
	for i := 0; i < 7; i++ {
		Round(&block2, &keys[i])
	}

	if block1 != block2 {
		t.Errorf("Rounds7 does not match 7 sequential Round calls")
	}
}

func TestRounds10MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys10()

	block1 := testBlockMR
	Rounds10(&block1, keys)

	block2 := testBlockMR
	for i := 0; i < 10; i++ {
		Round(&block2, &keys[i])
	}

	if block1 != block2 {
		t.Errorf("Rounds10 does not match 10 sequential Round calls")
	}
}

func TestRounds12MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys12()

	block1 := testBlockMR
	Rounds12(&block1, keys)

	block2 := testBlockMR
	for i := 0; i < 12; i++ {
		Round(&block2, &keys[i])
	}

	if block1 != block2 {
		t.Errorf("Rounds12 does not match 12 sequential Round calls")
	}
}

func TestRounds14MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys14()

	block1 := testBlockMR
	Rounds14(&block1, keys)

	block2 := testBlockMR
	for i := 0; i < 14; i++ {
		Round(&block2, &keys[i])
	}

	if block1 != block2 {
		t.Errorf("Rounds14 does not match 14 sequential Round calls")
	}
}

// Test hardware matches software
func TestRounds4HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys4()

	blockSW := testBlockMR
	Rounds4(&blockSW, keys)

	blockHW := testBlockMR
	Rounds4HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds4HW does not match Rounds4\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds4HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys4()

	blockSW := testBlockMR
	InvRounds4(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds4HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds4HW does not match InvRounds4")
	}
}

func TestRounds7HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys7()

	blockSW := testBlockMR
	Rounds7(&blockSW, keys)

	blockHW := testBlockMR
	Rounds7HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds7HW does not match Rounds7\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds7HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys7()

	blockSW := testBlockMR
	InvRounds7(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds7HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds7HW does not match InvRounds7")
	}
}

func TestRounds10HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	blockSW := testBlockMR
	Rounds10(&blockSW, keys)

	blockHW := testBlockMR
	Rounds10HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds10HW does not match Rounds10\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds10HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	blockSW := testBlockMR
	InvRounds10(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds10HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds10HW does not match InvRounds10")
	}
}

func TestRounds12HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys12()

	blockSW := testBlockMR
	Rounds12(&blockSW, keys)

	blockHW := testBlockMR
	Rounds12HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds12HW does not match Rounds12\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds12HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys12()

	blockSW := testBlockMR
	InvRounds12(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds12HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds12HW does not match InvRounds12")
	}
}

func TestRounds14HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys14()

	blockSW := testBlockMR
	Rounds14(&blockSW, keys)

	blockHW := testBlockMR
	Rounds14HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds14HW does not match Rounds14\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds14HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys14()

	blockSW := testBlockMR
	InvRounds14(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds14HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds14HW does not match InvRounds14")
	}
}

// makeRoundKeys6 creates round keys for 6-round testing
func makeRoundKeys6() *RoundKeys6 {
	var keys RoundKeys6
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte((i * 16) + j)
		}
	}
	return &keys
}

// Test Rounds6 variants
func TestRounds6MatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys6()

	block1 := testBlockMR
	Rounds6(&block1, keys)

	block2 := testBlockMR
	Round(&block2, &keys[0])
	Round(&block2, &keys[1])
	Round(&block2, &keys[2])
	Round(&block2, &keys[3])
	Round(&block2, &keys[4])
	Round(&block2, &keys[5])

	if block1 != block2 {
		t.Errorf("Rounds6 does not match 6 sequential Round calls\nRounds6:     %x\nSequential:  %x", block1, block2)
	}
}

func TestRounds6HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys6()

	blockSW := testBlockMR
	Rounds6(&blockSW, keys)

	blockHW := testBlockMR
	Rounds6HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds6HW does not match Rounds6\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds6HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys6()

	blockSW := testBlockMR
	InvRounds6(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds6HW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds6HW does not match InvRounds6\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

// Test WithFinal variants
func TestRounds6WithFinalMatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys6()

	block1 := testBlockMR
	Rounds6WithFinal(&block1, keys)

	block2 := testBlockMR
	Round(&block2, &keys[0])
	Round(&block2, &keys[1])
	Round(&block2, &keys[2])
	Round(&block2, &keys[3])
	Round(&block2, &keys[4])
	FinalRound(&block2, &keys[5])

	if block1 != block2 {
		t.Errorf("Rounds6WithFinal does not match expected\nRounds6WithFinal: %x\nSequential:       %x", block1, block2)
	}
}

func TestRounds6WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys6()

	blockSW := testBlockMR
	Rounds6WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	Rounds6WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds6WithFinalHW does not match Rounds6WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds10WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	blockSW := testBlockMR
	Rounds10WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	Rounds10WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds10WithFinalHW does not match Rounds10WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds12WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys12()

	blockSW := testBlockMR
	Rounds12WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	Rounds12WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds12WithFinalHW does not match Rounds12WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds14WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys14()

	blockSW := testBlockMR
	Rounds14WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	Rounds14WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("Rounds14WithFinalHW does not match Rounds14WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

// Test InvRoundsWithFinal variants
func TestInvRounds4WithFinalMatchesSingleRounds(t *testing.T) {
	keys := makeRoundKeys4()

	block1 := testBlockMR
	InvRounds4WithFinal(&block1, keys)

	block2 := testBlockMR
	InvRound(&block2, &keys[0])
	InvRound(&block2, &keys[1])
	InvRound(&block2, &keys[2])
	InvFinalRound(&block2, &keys[3])

	if block1 != block2 {
		t.Errorf("InvRounds4WithFinal does not match expected\nInvRounds4WithFinal: %x\nSequential:          %x", block1, block2)
	}
}

func TestInvRounds4WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys4()

	blockSW := testBlockMR
	InvRounds4WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds4WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds4WithFinalHW does not match InvRounds4WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds6WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys6()

	blockSW := testBlockMR
	InvRounds6WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds6WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds6WithFinalHW does not match InvRounds6WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds7WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys7()

	blockSW := testBlockMR
	InvRounds7WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds7WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds7WithFinalHW does not match InvRounds7WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds10WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	blockSW := testBlockMR
	InvRounds10WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds10WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds10WithFinalHW does not match InvRounds10WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds12WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys12()

	blockSW := testBlockMR
	InvRounds12WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds12WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds12WithFinalHW does not match InvRounds12WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds14WithFinalHWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys14()

	blockSW := testBlockMR
	InvRounds14WithFinal(&blockSW, keys)

	blockHW := testBlockMR
	InvRounds14WithFinalHW(&blockHW, keys)

	if blockSW != blockHW {
		t.Errorf("InvRounds14WithFinalHW does not match InvRounds14WithFinal\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

// Test NoKey variants
func TestRounds4NoKeyMatchesSingleRounds(t *testing.T) {
	block1 := testBlockMR
	Rounds4NoKey(&block1)

	block2 := testBlockMR
	RoundNoKey(&block2)
	RoundNoKey(&block2)
	RoundNoKey(&block2)
	RoundNoKey(&block2)

	if block1 != block2 {
		t.Errorf("Rounds4NoKey does not match 4 sequential RoundNoKey calls")
	}
}

func TestRounds4NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	Rounds4NoKey(&blockSW)

	blockHW := testBlockMR
	Rounds4NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("Rounds4NoKeyHW does not match Rounds4NoKey\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds7NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	Rounds7NoKey(&blockSW)

	blockHW := testBlockMR
	Rounds7NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("Rounds7NoKeyHW does not match Rounds7NoKey\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds10NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	Rounds10NoKey(&blockSW)

	blockHW := testBlockMR
	Rounds10NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("Rounds10NoKeyHW does not match Rounds10NoKey\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds12NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	Rounds12NoKey(&blockSW)

	blockHW := testBlockMR
	Rounds12NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("Rounds12NoKeyHW does not match Rounds12NoKey\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestRounds14NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	Rounds14NoKey(&blockSW)

	blockHW := testBlockMR
	Rounds14NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("Rounds14NoKeyHW does not match Rounds14NoKey\nSoftware: %x\nHardware: %x", blockSW, blockHW)
	}
}

func TestInvRounds4NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	InvRounds4NoKey(&blockSW)

	blockHW := testBlockMR
	InvRounds4NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("InvRounds4NoKeyHW does not match InvRounds4NoKey")
	}
}

func TestInvRounds7NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	InvRounds7NoKey(&blockSW)

	blockHW := testBlockMR
	InvRounds7NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("InvRounds7NoKeyHW does not match InvRounds7NoKey")
	}
}

func TestInvRounds10NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	InvRounds10NoKey(&blockSW)

	blockHW := testBlockMR
	InvRounds10NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("InvRounds10NoKeyHW does not match InvRounds10NoKey")
	}
}

func TestInvRounds12NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	InvRounds12NoKey(&blockSW)

	blockHW := testBlockMR
	InvRounds12NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("InvRounds12NoKeyHW does not match InvRounds12NoKey")
	}
}

func TestInvRounds14NoKeyHWMatchesSoftware(t *testing.T) {
	blockSW := testBlockMR
	InvRounds14NoKey(&blockSW)

	blockHW := testBlockMR
	InvRounds14NoKeyHW(&blockHW)

	if blockSW != blockHW {
		t.Errorf("InvRounds14NoKeyHW does not match InvRounds14NoKey")
	}
}

// Test NoKey round-trip (forward then inverse returns original)
func TestRounds4NoKeyRoundTrip(t *testing.T) {
	original := testBlockMR

	block := original
	Rounds4NoKeyHW(&block)
	InvRounds4NoKeyHW(&block)

	if block != original {
		t.Errorf("Rounds4NoKey round-trip failed\nOriginal: %x\nResult:   %x", original, block)
	}
}

func TestRounds7NoKeyRoundTrip(t *testing.T) {
	original := testBlockMR

	block := original
	Rounds7NoKeyHW(&block)
	InvRounds7NoKeyHW(&block)

	if block != original {
		t.Errorf("Rounds7NoKey round-trip failed\nOriginal: %x\nResult:   %x", original, block)
	}
}

func TestRounds10NoKeyRoundTrip(t *testing.T) {
	original := testBlockMR

	block := original
	Rounds10NoKeyHW(&block)
	InvRounds10NoKeyHW(&block)

	if block != original {
		t.Errorf("Rounds10NoKey round-trip failed\nOriginal: %x\nResult:   %x", original, block)
	}
}

func TestRounds12NoKeyRoundTrip(t *testing.T) {
	original := testBlockMR

	block := original
	Rounds12NoKeyHW(&block)
	InvRounds12NoKeyHW(&block)

	if block != original {
		t.Errorf("Rounds12NoKey round-trip failed\nOriginal: %x\nResult:   %x", original, block)
	}
}

func TestRounds14NoKeyRoundTrip(t *testing.T) {
	original := testBlockMR

	block := original
	Rounds14NoKeyHW(&block)
	InvRounds14NoKeyHW(&block)

	if block != original {
		t.Errorf("Rounds14NoKey round-trip failed\nOriginal: %x\nResult:   %x", original, block)
	}
}

// Test that output is deterministic (multiple calls with same input give same output)
func TestRounds4Deterministic(t *testing.T) {
	keys := makeRoundKeys4()

	block1 := testBlockMR
	Rounds4HW(&block1, keys)

	block2 := testBlockMR
	Rounds4HW(&block2, keys)

	if block1 != block2 {
		t.Errorf("Rounds4HW is not deterministic")
	}
}

// Test with random data
func TestMultiRoundsWithRandomData(t *testing.T) {
	// Use a deterministic "random" pattern
	var randomBlock Block
	var randomKeys RoundKeys14
	for i := range randomBlock {
		randomBlock[i] = byte(i*7 + 13)
	}
	for i := range randomKeys {
		for j := range randomKeys[i] {
			randomKeys[i][j] = byte((i*16+j)*11 + 17)
		}
	}

	// Test 4 rounds
	keys4 := (*RoundKeys4)(randomKeys[:4])
	block := randomBlock
	Rounds4(&block, keys4)
	blockHW := randomBlock
	Rounds4HW(&blockHW, keys4)
	if block != blockHW {
		t.Errorf("Rounds4 mismatch with random data")
	}

	// Test 7 rounds
	keys7 := (*RoundKeys7)(randomKeys[:7])
	block = randomBlock
	Rounds7(&block, keys7)
	blockHW = randomBlock
	Rounds7HW(&blockHW, keys7)
	if block != blockHW {
		t.Errorf("Rounds7 mismatch with random data")
	}

	// Test 10 rounds
	keys10 := (*RoundKeys10)(randomKeys[:10])
	block = randomBlock
	Rounds10(&block, keys10)
	blockHW = randomBlock
	Rounds10HW(&blockHW, keys10)
	if block != blockHW {
		t.Errorf("Rounds10 mismatch with random data")
	}

	// Test 12 rounds
	keys12 := (*RoundKeys12)(randomKeys[:12])
	block = randomBlock
	Rounds12(&block, keys12)
	blockHW = randomBlock
	Rounds12HW(&blockHW, keys12)
	if block != blockHW {
		t.Errorf("Rounds12 mismatch with random data")
	}

	// Test 14 rounds
	block = randomBlock
	Rounds14(&block, &randomKeys)
	blockHW = randomBlock
	Rounds14HW(&blockHW, &randomKeys)
	if block != blockHW {
		t.Errorf("Rounds14 mismatch with random data")
	}
}

// Benchmarks

func BenchmarkRounds4Software(b *testing.B) {
	keys := makeRoundKeys4()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds4(&block, keys)
	}
}

func BenchmarkRounds4HW(b *testing.B) {
	keys := makeRoundKeys4()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds4HW(&block, keys)
	}
}

func BenchmarkRounds7Software(b *testing.B) {
	keys := makeRoundKeys7()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds7(&block, keys)
	}
}

func BenchmarkRounds7HW(b *testing.B) {
	keys := makeRoundKeys7()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds7HW(&block, keys)
	}
}

func BenchmarkRounds10Software(b *testing.B) {
	keys := makeRoundKeys10()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10(&block, keys)
	}
}

func BenchmarkRounds10HW(b *testing.B) {
	keys := makeRoundKeys10()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10HW(&block, keys)
	}
}

func BenchmarkRounds12Software(b *testing.B) {
	keys := makeRoundKeys12()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds12(&block, keys)
	}
}

func BenchmarkRounds12HW(b *testing.B) {
	keys := makeRoundKeys12()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds12HW(&block, keys)
	}
}

func BenchmarkRounds14Software(b *testing.B) {
	keys := makeRoundKeys14()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds14(&block, keys)
	}
}

func BenchmarkRounds14HW(b *testing.B) {
	keys := makeRoundKeys14()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds14HW(&block, keys)
	}
}

func BenchmarkRounds10NoKeySoftware(b *testing.B) {
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10NoKey(&block)
	}
}

func BenchmarkRounds10NoKeyHW(b *testing.B) {
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10NoKeyHW(&block)
	}
}

// Benchmark comparison: multi-round vs sequential single rounds
func BenchmarkRounds10SequentialSingle(b *testing.B) {
	keys := makeRoundKeys10()
	block := testBlockMR
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RoundHW(&block, &keys[0])
		RoundHW(&block, &keys[1])
		RoundHW(&block, &keys[2])
		RoundHW(&block, &keys[3])
		RoundHW(&block, &keys[4])
		RoundHW(&block, &keys[5])
		RoundHW(&block, &keys[6])
		RoundHW(&block, &keys[7])
		RoundHW(&block, &keys[8])
		RoundHW(&block, &keys[9])
	}
}

// Test that bytes package is used properly (can be removed if not needed)
var _ = bytes.Equal

// Test Block2 parallel multi-rounds match sequential single-block operations
func TestRounds4_2MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys4()

	// Create test blocks
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	// Using parallel function
	blocksPar := blocks
	Rounds4_2(&blocksPar, keys)

	// Using single-block function on each block
	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds4(b0, keys)
	Rounds4(b1, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds4_2 does not match sequential single-block Rounds4\nParallel:   %x\nSequential: %x", blocksPar, blocks)
	}
}

func TestRounds7_2MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys7()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	blocksPar := blocks
	Rounds7_2(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds7(b0, keys)
	Rounds7(b1, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds7_2 does not match sequential single-block Rounds7")
	}
}

func TestRounds10_2MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	blocksPar := blocks
	Rounds10_2(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds10(b0, keys)
	Rounds10(b1, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds10_2 does not match sequential single-block Rounds10")
	}
}

func TestRounds12_2MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys12()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	blocksPar := blocks
	Rounds12_2(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds12(b0, keys)
	Rounds12(b1, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds12_2 does not match sequential single-block Rounds12")
	}
}

func TestRounds14_2MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys14()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	blocksPar := blocks
	Rounds14_2(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds14(b0, keys)
	Rounds14(b1, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds14_2 does not match sequential single-block Rounds14")
	}
}

// Test Block4 parallel multi-rounds match sequential single-block operations
func TestRounds4_4MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys4()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 5)
	}

	blocksPar := blocks
	Rounds4_4(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:32])
	b2 := (*Block)(blocks[32:48])
	b3 := (*Block)(blocks[48:])
	Rounds4(b0, keys)
	Rounds4(b1, keys)
	Rounds4(b2, keys)
	Rounds4(b3, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds4_4 does not match sequential single-block Rounds4")
	}
}

func TestRounds10_4MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 5)
	}

	blocksPar := blocks
	Rounds10_4(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:32])
	b2 := (*Block)(blocks[32:48])
	b3 := (*Block)(blocks[48:])
	Rounds10(b0, keys)
	Rounds10(b1, keys)
	Rounds10(b2, keys)
	Rounds10(b3, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds10_4 does not match sequential single-block Rounds10")
	}
}

func TestRounds14_4MatchesSingleBlock(t *testing.T) {
	keys := makeRoundKeys14()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 5)
	}

	blocksPar := blocks
	Rounds14_4(&blocksPar, keys)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:32])
	b2 := (*Block)(blocks[32:48])
	b3 := (*Block)(blocks[48:])
	Rounds14(b0, keys)
	Rounds14(b1, keys)
	Rounds14(b2, keys)
	Rounds14(b3, keys)

	if blocksPar != blocks {
		t.Errorf("Rounds14_4 does not match sequential single-block Rounds14")
	}
}

// Test parallel HW matches SW
func TestRounds10_2HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 7)
	}

	blocksSW := blocks
	Rounds10_2(&blocksSW, keys)

	blocksHW := blocks
	Rounds10_2HW(&blocksHW, keys)

	if blocksSW != blocksHW {
		t.Errorf("Rounds10_2HW does not match Rounds10_2\nSoftware: %x\nHardware: %x", blocksSW, blocksHW)
	}
}

func TestInvRounds10_2HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 7)
	}

	blocksSW := blocks
	InvRounds10_2(&blocksSW, keys)

	blocksHW := blocks
	InvRounds10_2HW(&blocksHW, keys)

	if blocksSW != blocksHW {
		t.Errorf("InvRounds10_2HW does not match InvRounds10_2")
	}
}

func TestRounds10_4HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 11)
	}

	blocksSW := blocks
	Rounds10_4(&blocksSW, keys)

	blocksHW := blocks
	Rounds10_4HW(&blocksHW, keys)

	if blocksSW != blocksHW {
		t.Errorf("Rounds10_4HW does not match Rounds10_4\nSoftware: %x\nHardware: %x", blocksSW, blocksHW)
	}
}

func TestInvRounds10_4HWMatchesSoftware(t *testing.T) {
	keys := makeRoundKeys10()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 11)
	}

	blocksSW := blocks
	InvRounds10_4(&blocksSW, keys)

	blocksHW := blocks
	InvRounds10_4HW(&blocksHW, keys)

	if blocksSW != blocksHW {
		t.Errorf("InvRounds10_4HW does not match InvRounds10_4")
	}
}

// Test parallel NoKey variants
func TestRounds10NoKey_2MatchesSingleBlock(t *testing.T) {
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 3)
	}

	blocksPar := blocks
	Rounds10NoKey_2(&blocksPar)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:])
	Rounds10NoKey(b0)
	Rounds10NoKey(b1)

	if blocksPar != blocks {
		t.Errorf("Rounds10NoKey_2 does not match sequential single-block Rounds10NoKey")
	}
}

func TestRounds10NoKey_2HWMatchesSoftware(t *testing.T) {
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 7)
	}

	blocksSW := blocks
	Rounds10NoKey_2(&blocksSW)

	blocksHW := blocks
	Rounds10NoKey_2HW(&blocksHW)

	if blocksSW != blocksHW {
		t.Errorf("Rounds10NoKey_2HW does not match Rounds10NoKey_2")
	}
}

func TestRounds10NoKey_4MatchesSingleBlock(t *testing.T) {
	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 5)
	}

	blocksPar := blocks
	Rounds10NoKey_4(&blocksPar)

	b0 := (*Block)(blocks[:16])
	b1 := (*Block)(blocks[16:32])
	b2 := (*Block)(blocks[32:48])
	b3 := (*Block)(blocks[48:])
	Rounds10NoKey(b0)
	Rounds10NoKey(b1)
	Rounds10NoKey(b2)
	Rounds10NoKey(b3)

	if blocksPar != blocks {
		t.Errorf("Rounds10NoKey_4 does not match sequential single-block Rounds10NoKey")
	}
}

func TestRounds10NoKey_4HWMatchesSoftware(t *testing.T) {
	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 11)
	}

	blocksSW := blocks
	Rounds10NoKey_4(&blocksSW)

	blocksHW := blocks
	Rounds10NoKey_4HW(&blocksHW)

	if blocksSW != blocksHW {
		t.Errorf("Rounds10NoKey_4HW does not match Rounds10NoKey_4")
	}
}

// Test parallel NoKey round-trip
// Note: Keyed round-trip tests require keys to be applied in reverse order for decryption,
// which is a different test scenario. NoKey round-trips work because there are no keys.
func TestRounds10NoKey_2RoundTrip(t *testing.T) {
	var original Block2
	for i := range original {
		original[i] = byte(i * 13)
	}

	blocks := original
	Rounds10NoKey_2HW(&blocks)
	InvRounds10NoKey_2HW(&blocks)

	if blocks != original {
		t.Errorf("Rounds10NoKey_2 round-trip failed\nOriginal: %x\nResult:   %x", original, blocks)
	}
}

func TestRounds10NoKey_4RoundTrip(t *testing.T) {
	var original Block4
	for i := range original {
		original[i] = byte(i * 17)
	}

	blocks := original
	Rounds10NoKey_4HW(&blocks)
	InvRounds10NoKey_4HW(&blocks)

	if blocks != original {
		t.Errorf("Rounds10NoKey_4 round-trip failed\nOriginal: %x\nResult:   %x", original, blocks)
	}
}

// Comprehensive test for all round counts (Block2) - verifies HW matches SW
func TestAllRoundCounts_2(t *testing.T) {
	keys4 := makeRoundKeys4()
	keys7 := makeRoundKeys7()
	keys10 := makeRoundKeys10()
	keys12 := makeRoundKeys12()
	keys14 := makeRoundKeys14()

	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i * 19)
	}

	tests := []struct {
		name  string
		encHW func(*Block2, interface{})
		encSW func(*Block2, interface{})
		keys  interface{}
	}{
		{
			"4 rounds", func(b *Block2, k interface{}) { Rounds4_2HW(b, k.(*RoundKeys4)) },
			func(b *Block2, k interface{}) { Rounds4_2(b, k.(*RoundKeys4)) }, keys4,
		},
		{
			"7 rounds", func(b *Block2, k interface{}) { Rounds7_2HW(b, k.(*RoundKeys7)) },
			func(b *Block2, k interface{}) { Rounds7_2(b, k.(*RoundKeys7)) }, keys7,
		},
		{
			"10 rounds", func(b *Block2, k interface{}) { Rounds10_2HW(b, k.(*RoundKeys10)) },
			func(b *Block2, k interface{}) { Rounds10_2(b, k.(*RoundKeys10)) }, keys10,
		},
		{
			"12 rounds", func(b *Block2, k interface{}) { Rounds12_2HW(b, k.(*RoundKeys12)) },
			func(b *Block2, k interface{}) { Rounds12_2(b, k.(*RoundKeys12)) }, keys12,
		},
		{
			"14 rounds", func(b *Block2, k interface{}) { Rounds14_2HW(b, k.(*RoundKeys14)) },
			func(b *Block2, k interface{}) { Rounds14_2(b, k.(*RoundKeys14)) }, keys14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bHW := blocks
			bSW := blocks
			tt.encHW(&bHW, tt.keys)
			tt.encSW(&bSW, tt.keys)
			if bHW != bSW {
				t.Errorf("%s Block2 HW/SW mismatch", tt.name)
			}
		})
	}
}

// Comprehensive test for all round counts (Block4) - verifies HW matches SW
func TestAllRoundCounts_4(t *testing.T) {
	keys4 := makeRoundKeys4()
	keys7 := makeRoundKeys7()
	keys10 := makeRoundKeys10()
	keys12 := makeRoundKeys12()
	keys14 := makeRoundKeys14()

	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i * 23)
	}

	tests := []struct {
		name  string
		encHW func(*Block4, interface{})
		encSW func(*Block4, interface{})
		keys  interface{}
	}{
		{
			"4 rounds", func(b *Block4, k interface{}) { Rounds4_4HW(b, k.(*RoundKeys4)) },
			func(b *Block4, k interface{}) { Rounds4_4(b, k.(*RoundKeys4)) }, keys4,
		},
		{
			"7 rounds", func(b *Block4, k interface{}) { Rounds7_4HW(b, k.(*RoundKeys7)) },
			func(b *Block4, k interface{}) { Rounds7_4(b, k.(*RoundKeys7)) }, keys7,
		},
		{
			"10 rounds", func(b *Block4, k interface{}) { Rounds10_4HW(b, k.(*RoundKeys10)) },
			func(b *Block4, k interface{}) { Rounds10_4(b, k.(*RoundKeys10)) }, keys10,
		},
		{
			"12 rounds", func(b *Block4, k interface{}) { Rounds12_4HW(b, k.(*RoundKeys12)) },
			func(b *Block4, k interface{}) { Rounds12_4(b, k.(*RoundKeys12)) }, keys12,
		},
		{
			"14 rounds", func(b *Block4, k interface{}) { Rounds14_4HW(b, k.(*RoundKeys14)) },
			func(b *Block4, k interface{}) { Rounds14_4(b, k.(*RoundKeys14)) }, keys14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bHW := blocks
			bSW := blocks
			tt.encHW(&bHW, tt.keys)
			tt.encSW(&bSW, tt.keys)
			if bHW != bSW {
				t.Errorf("%s Block4 HW/SW mismatch", tt.name)
			}
		})
	}
}

// Benchmarks for parallel multi-round functions

func BenchmarkRounds10_2Software(b *testing.B) {
	keys := makeRoundKeys10()
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(32) // 2 blocks = 32 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10_2(&blocks, keys)
	}
}

func BenchmarkRounds10_2HW(b *testing.B) {
	keys := makeRoundKeys10()
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(32) // 2 blocks = 32 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10_2HW(&blocks, keys)
	}
}

func BenchmarkRounds10_4Software(b *testing.B) {
	keys := makeRoundKeys10()
	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(64) // 4 blocks = 64 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10_4(&blocks, keys)
	}
}

func BenchmarkRounds10_4HW(b *testing.B) {
	keys := makeRoundKeys10()
	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(64) // 4 blocks = 64 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10_4HW(&blocks, keys)
	}
}

// Comparison: 4 single-block operations vs parallel Block4
func BenchmarkRounds10_4xSingleHW(b *testing.B) {
	keys := makeRoundKeys10()
	var blocks [4]Block
	for i := range blocks {
		for j := range blocks[i] {
			blocks[i][j] = byte(i*16 + j)
		}
	}
	b.SetBytes(64) // 4 blocks = 64 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10HW(&blocks[0], keys)
		Rounds10HW(&blocks[1], keys)
		Rounds10HW(&blocks[2], keys)
		Rounds10HW(&blocks[3], keys)
	}
}

func BenchmarkRounds10NoKey_2HW(b *testing.B) {
	var blocks Block2
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(32) // 2 blocks = 32 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10NoKey_2HW(&blocks)
	}
}

func BenchmarkRounds10NoKey_4HW(b *testing.B) {
	var blocks Block4
	for i := range blocks {
		blocks[i] = byte(i)
	}
	b.SetBytes(64) // 4 blocks = 64 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Rounds10NoKey_4HW(&blocks)
	}
}
