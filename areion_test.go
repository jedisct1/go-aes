package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from the reference Zig implementation
func TestAreion256Permutation(t *testing.T) {
	// Test vector 1: all zeros
	var state Areion256
	for i := range state {
		state[i] = 0
	}

	state.Permute()

	expectedHex := "2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion256 permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion256PermutationSequential(t *testing.T) {
	// Test vector 2: sequential bytes 0..31
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	state.Permute()

	expectedHex := "68845f132ee4616066c702d942a3b2c3a377f65b13bb05c7cd1fb29c89afa185"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion256 sequential permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion512Permutation(t *testing.T) {
	// Test vector 1: all zeros
	var state Areion512
	for i := range state {
		state[i] = 0
	}

	state.Permute()

	expectedHex := "b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion512 permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion512PermutationSequential(t *testing.T) {
	// Test vector 2: sequential bytes 0..63
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	state.Permute()

	expectedHex := "b690b88297ec470b07dda92b91959cff135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion512 sequential permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

// Test that permute and inverse permute are inverses of each other
func TestAreion256Roundtrip(t *testing.T) {
	var original, state Areion256
	for i := range original {
		original[i] = byte(i * 3)
	}
	copy(state[:], original[:])

	state.Permute()
	state.InversePermute()

	if !bytes.Equal(original[:], state[:]) {
		t.Errorf("Areion256 roundtrip failed\nOriginal: %x\nRoundtrip: %x", original[:], state[:])
	}
}

func TestAreion512Roundtrip(t *testing.T) {
	var original, state Areion512
	for i := range original {
		original[i] = byte(i * 5)
	}
	copy(state[:], original[:])

	state.Permute()
	state.InversePermute()

	if !bytes.Equal(original[:], state[:]) {
		t.Errorf("Areion512 roundtrip failed\nOriginal: %x\nRoundtrip: %x", original[:], state[:])
	}
}

// Test hardware vs software implementation consistency
func TestAreion256HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0xAA)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256PermuteAsm(&stateHW)

	// Software
	areion256PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0x55)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512PermuteAsm(&stateHW)

	// Software
	areion512PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion256InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i * 7)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256InversePermuteAsm(&stateHW)

	// Software
	areion256InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i * 11)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512InversePermuteAsm(&stateHW)

	// Software
	areion512InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

// Benchmarks
func BenchmarkAreion256Permute(b *testing.B) {
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.Permute()
	}
}

func BenchmarkAreion256InversePermute(b *testing.B) {
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.InversePermute()
	}
}

func BenchmarkAreion512Permute(b *testing.B) {
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.Permute()
	}
}

func BenchmarkAreion512InversePermute(b *testing.B) {
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.InversePermute()
	}
}
