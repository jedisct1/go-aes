package aes

import (
	"encoding/hex"
	"testing"
)

func TestHaraka256(t *testing.T) {
	// Test vector from Appendix B of the Haraka v2 paper
	// Input: 0x00 0x01 0x02 ... 0x1f (32 bytes)
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}

	// Expected output from reference implementation
	expected, _ := hex.DecodeString("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c")

	output := Haraka256(&input)

	if string(output[:]) != string(expected) {
		t.Errorf("Haraka256 mismatch\nInput:    %x\nExpected: %x\nGot:      %x", input, expected, output)
	}
}

func TestHaraka512(t *testing.T) {
	// Test vector from Appendix B of the Haraka v2 paper
	// Input: 0x00 0x01 0x02 ... 0x3f (64 bytes)
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}

	// Expected output from reference implementation
	expected, _ := hex.DecodeString("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa")

	output := Haraka512(&input)

	if string(output[:]) != string(expected) {
		t.Errorf("Haraka512 mismatch\nInput:    %x\nExpected: %x\nGot:      %x", input, expected, output)
	}
}

func TestHaraka256ZeroInput(t *testing.T) {
	var input [32]byte
	output := Haraka256(&input)

	// Just ensure it doesn't panic and returns a non-zero output
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Haraka256 of zero input should not be zero")
	}
}

func TestHaraka512ZeroInput(t *testing.T) {
	var input [64]byte
	output := Haraka512(&input)

	// Just ensure it doesn't panic and returns a non-zero output
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Haraka512 of zero input should not be zero")
	}
}

func TestMix2Correctness(t *testing.T) {
	// Test that mix2 performs the expected permutation
	var s0, s1 Block

	// Set up known state
	for i := 0; i < 16; i++ {
		s0[i] = byte(i)
		s1[i] = byte(i + 16)
	}

	mix2(&s0, &s1)

	// After mix2:
	// s0 should be: [a0, b0, a1, b1] = [0-3, 16-19, 4-7, 20-23]
	// s1 should be: [a2, b2, a3, b3] = [8-11, 24-27, 12-15, 28-31]

	expected0 := []byte{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23}
	expected1 := []byte{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31}

	if string(s0[:]) != string(expected0) {
		t.Errorf("mix2 s0 mismatch\nExpected: %x\nGot:      %x", expected0, s0[:])
	}
	if string(s1[:]) != string(expected1) {
		t.Errorf("mix2 s1 mismatch\nExpected: %x\nGot:      %x", expected1, s1[:])
	}
}

func TestHaraka256Deterministic(t *testing.T) {
	// Test that the same input always produces the same output
	var input [32]byte
	for i := range input {
		input[i] = byte(i * 7)
	}

	output1 := Haraka256(&input)
	output2 := Haraka256(&input)

	if output1 != output2 {
		t.Errorf("Haraka256 not deterministic: %x != %x", output1, output2)
	}
}

func TestHaraka512Deterministic(t *testing.T) {
	// Test that the same input always produces the same output
	var input [64]byte
	for i := range input {
		input[i] = byte(i * 11)
	}

	output1 := Haraka512(&input)
	output2 := Haraka512(&input)

	if output1 != output2 {
		t.Errorf("Haraka512 not deterministic: %x != %x", output1, output2)
	}
}

func BenchmarkHaraka256(b *testing.B) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Haraka256(&input)
	}
}

func BenchmarkHaraka512(b *testing.B) {
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Haraka512(&input)
	}
}
