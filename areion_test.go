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

// Areion256-DM tests (test vectors from reference C implementation)
func TestAreion256DM(t *testing.T) {
	// Test vector 1: all zeros
	var input [32]byte
	out := Areion256DM(&input)
	expected, _ := hex.DecodeString("2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion256DM(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Test vector 2: sequential bytes 0..31
	for i := range input {
		input[i] = byte(i)
	}
	out = Areion256DM(&input)
	expected, _ = hex.DecodeString("68855d102ae167676ece08d24eaebcccb366e44807ae13d0d506a88795b2bf9a")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion256DM(sequential) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreion512DM(t *testing.T) {
	// Test vector 1: all zeros
	var input [64]byte
	out := Areion512DM(&input)
	expected, _ := hex.DecodeString("59367122cb3c96a93fe6dc85779102e7e3f5501016ceed1dad168794bd96cff3")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion512DM(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Test vector 2: sequential bytes 0..63
	for i := range input {
		input[i] = byte(i)
	}
	out = Areion512DM(&input)
	expected, _ = hex.DecodeString("0fd4a3209d9892f05fbd2556b690b9bbc08e9ffbc2c773e5d451888ade4c23f1")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion512DM(sequential) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

// Even-Mansour tests

func TestAreion256EMRoundtrip(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}

	ciphertext := Areion256EM(&key, &plaintext)
	if bytes.Equal(ciphertext[:], plaintext[:]) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted := Areion256EMDecrypt(&key, &ciphertext)
	if !bytes.Equal(decrypted[:], plaintext[:]) {
		t.Errorf("Areion256EM roundtrip failed\nPlaintext:  %x\nDecrypted:  %x", plaintext[:], decrypted[:])
	}
}

func TestAreion512EMRoundtrip(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}

	ciphertext := Areion512EM(&key, &plaintext)
	if bytes.Equal(ciphertext[:], plaintext[:]) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted := Areion512EMDecrypt(&key, &ciphertext)
	if !bytes.Equal(decrypted[:], plaintext[:]) {
		t.Errorf("Areion512EM roundtrip failed\nPlaintext:  %x\nDecrypted:  %x", plaintext[:], decrypted[:])
	}
}

func TestAreion256EMZeroKey(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// With zero key, EM reduces to just the permutation
	ciphertext := Areion256EM(&key, &plaintext)

	var state Areion256
	copy(state[:], plaintext[:])
	state.Permute()

	if !bytes.Equal(ciphertext[:], state[:]) {
		t.Errorf("Areion256EM with zero key should equal bare permutation\nEM:   %x\nPerm: %x", ciphertext[:], state[:])
	}
}

func TestAreion512EMZeroKey(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext := Areion512EM(&key, &plaintext)

	var state Areion512
	copy(state[:], plaintext[:])
	state.Permute()

	if !bytes.Equal(ciphertext[:], state[:]) {
		t.Errorf("Areion512EM with zero key should equal bare permutation\nEM:   %x\nPerm: %x", ciphertext[:], state[:])
	}
}

func TestAreion256EMKnownAnswer(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte

	// Generate a known-answer test vector
	ciphertext := Areion256EM(&key, &plaintext)
	expected, _ := hex.DecodeString("2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8")
	if !bytes.Equal(ciphertext[:], expected) {
		t.Errorf("Areion256EM(zeros) failed\nGot:      %x\nExpected: %x", ciphertext[:], expected)
	}
}

func TestAreion512EMKnownAnswer(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte

	ciphertext := Areion512EM(&key, &plaintext)
	expected, _ := hex.DecodeString("b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928")
	if !bytes.Equal(ciphertext[:], expected) {
		t.Errorf("Areion512EM(zeros) failed\nGot:      %x\nExpected: %x", ciphertext[:], expected)
	}
}

// Sum of Even-Mansour tests

func TestAreionSoEM256(t *testing.T) {
	// All-zeros key and input
	var key [64]byte
	var input [32]byte
	out := AreionSoEM256(&key, &input)
	expected, _ := hex.DecodeString("d2754ec03e7025e852ab85dc0b38dae087add5a6522261dfc7b424c96cbed761")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM256(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Sequential key and input
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 64)
	}
	out = AreionSoEM256(&key, &input)
	expected, _ = hex.DecodeString("8cf756fef9750beb329f700a83e50493cec0615d698a7af94ab1654225d9320f")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM256(seq) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreionSoEM512(t *testing.T) {
	// All-zeros key and input
	var key [128]byte
	var input [64]byte
	out := AreionSoEM512(&key, &input)
	expected, _ := hex.DecodeString("53f751fa1dc08e0fd2bc595d06ebd77244aa9c66cd2a0c1823e27b31d114840622022da12be0ece250735ce6d170d77aa57d69191f1d01f3db3e3886b23e1918")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM512(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Sequential key and input
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 128)
	}
	out = AreionSoEM512(&key, &input)
	expected, _ = hex.DecodeString("3cb3f1cc85dede951a4f8f7f3ad229457ed67c61cdf31ec7ad9e4e0aaa9a917897d2a5b2d561da88e503d701fdf15dbfdc1a69f39bd316785f10bb893ce17d32")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM512(seq) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreionSoEM256DifferentKeys(t *testing.T) {
	var key1, key2 [64]byte
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	out1 := AreionSoEM256(&key1, &input)
	out2 := AreionSoEM256(&key2, &input)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM256: different keys should produce different outputs")
	}
}

func TestAreionSoEM512DifferentKeys(t *testing.T) {
	var key1, key2 [128]byte
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	out1 := AreionSoEM512(&key1, &input)
	out2 := AreionSoEM512(&key2, &input)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM512: different keys should produce different outputs")
	}
}

func TestAreionSoEM256DifferentInputs(t *testing.T) {
	var key [64]byte
	var input1, input2 [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input1 {
		input1[i] = byte(i)
		input2[i] = byte(i + 1)
	}
	out1 := AreionSoEM256(&key, &input1)
	out2 := AreionSoEM256(&key, &input2)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM256: different inputs should produce different outputs")
	}
}

func TestAreion256Parallel(t *testing.T) {
	for i := 0; i < 100; i++ {
		var s1, s2, s1ref, s2ref Areion256
		for j := range s1 {
			s1[j] = byte(i*3 + j)
			s2[j] = byte(i*5 + j + 128)
		}
		copy(s1ref[:], s1[:])
		copy(s2ref[:], s2[:])

		s1ref.Permute()
		s2ref.Permute()
		areion256Permute2(&s1, &s2)

		if !bytes.Equal(s1[:], s1ref[:]) {
			t.Fatalf("Areion256 parallel state1 mismatch at i=%d\nParallel:   %x\nSequential: %x", i, s1[:], s1ref[:])
		}
		if !bytes.Equal(s2[:], s2ref[:]) {
			t.Fatalf("Areion256 parallel state2 mismatch at i=%d\nParallel:   %x\nSequential: %x", i, s2[:], s2ref[:])
		}
	}
}

func TestAreion512Parallel(t *testing.T) {
	for i := 0; i < 100; i++ {
		var s1, s2, s1ref, s2ref Areion512
		for j := range s1 {
			s1[j] = byte(i*7 + j)
			s2[j] = byte(i*11 + j + 64)
		}
		copy(s1ref[:], s1[:])
		copy(s2ref[:], s2[:])

		s1ref.Permute()
		s2ref.Permute()
		areion512Permute2(&s1, &s2)

		if !bytes.Equal(s1[:], s1ref[:]) {
			t.Fatalf("Areion512 parallel state1 mismatch at i=%d\nParallel:   %x\nSequential: %x", i, s1[:], s1ref[:])
		}
		if !bytes.Equal(s2[:], s2ref[:]) {
			t.Fatalf("Areion512 parallel state2 mismatch at i=%d\nParallel:   %x\nSequential: %x", i, s2[:], s2ref[:])
		}
	}
}

// Benchmarks

func BenchmarkAreionSoEM256(b *testing.B) {
	var key [64]byte
	var input [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 64)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AreionSoEM256(&key, &input)
	}
}

func BenchmarkAreionSoEM512(b *testing.B) {
	var key [128]byte
	var input [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 128)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AreionSoEM512(&key, &input)
	}
}

func BenchmarkAreion256EM(b *testing.B) {
	var key [32]byte
	var block [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range block {
		block[i] = byte(i + 32)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256EM(&key, &block)
	}
}

func BenchmarkAreion512EM(b *testing.B) {
	var key [64]byte
	var block [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range block {
		block[i] = byte(i + 64)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512EM(&key, &block)
	}
}

func BenchmarkAreion256DM(b *testing.B) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256DM(&input)
	}
}

func BenchmarkAreion512DM(b *testing.B) {
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512DM(&input)
	}
}

func BenchmarkAreion256Permute2(b *testing.B) {
	var s1, s2 Areion256
	for i := range s1 {
		s1[i] = byte(i)
		s2[i] = byte(i + 32)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		areion256Permute2(&s1, &s2)
	}
}

func BenchmarkAreion512Permute2(b *testing.B) {
	var s1, s2 Areion512
	for i := range s1 {
		s1[i] = byte(i)
		s2[i] = byte(i + 64)
	}

	b.SetBytes(128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		areion512Permute2(&s1, &s2)
	}
}

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
