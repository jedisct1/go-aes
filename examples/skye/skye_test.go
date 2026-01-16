package skye

import (
	"bytes"
	"encoding/hex"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

func TestDExtLsb3Samples(t *testing.T) {
	// Test with 3 DH samples (typical X3DH without one-time prekey)
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	// Fill with test data
	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	key, err := DExtLsb([][]byte{sample1, sample2, sample3})
	if err != nil {
		t.Fatalf("DExtLsb failed: %v", err)
	}

	if key == nil {
		t.Fatal("DExtLsb returned nil key")
	}

	// Verify key is 16 bytes (128 bits)
	if len(key) != 16 {
		t.Errorf("Expected 16-byte key, got %d bytes", len(key))
	}

	// Key should not be all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Key should not be all zeros")
	}
}

func TestDExtLsb4Samples(t *testing.T) {
	// Test with 4 DH samples (typical X3DH with one-time prekey)
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)
	sample4 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
		sample4[i] = byte(i + 96)
	}

	key, err := DExtLsb([][]byte{sample1, sample2, sample3, sample4})
	if err != nil {
		t.Fatalf("DExtLsb failed: %v", err)
	}

	if key == nil {
		t.Fatal("DExtLsb returned nil key")
	}

	// Verify key is 16 bytes
	if len(key) != 16 {
		t.Errorf("Expected 16-byte key, got %d bytes", len(key))
	}
}

func TestDExtLsbInvalidSamples(t *testing.T) {
	// Test with invalid number of samples
	sample := make([]byte, 32)

	_, err := DExtLsb([][]byte{sample, sample})
	if err == nil {
		t.Error("Expected error for 2 samples")
	}

	_, err = DExtLsb([][]byte{sample, sample, sample, sample, sample})
	if err == nil {
		t.Error("Expected error for 5 samples")
	}

	// Test with samples too short
	shortSample := make([]byte, 30)
	_, err = DExtLsb([][]byte{sample, shortSample, sample})
	if err == nil {
		t.Error("Expected error for short sample")
	}
}

func TestDExtLsbDeterministic(t *testing.T) {
	// Same inputs should produce same output
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i * 3)
		sample2[i] = byte(i * 5)
		sample3[i] = byte(i * 7)
	}

	key1, _ := DExtLsb([][]byte{sample1, sample2, sample3})
	key2, _ := DExtLsb([][]byte{sample1, sample2, sample3})

	if !bytes.Equal(key1[:], key2[:]) {
		t.Error("DExtLsb should be deterministic")
	}
}

func TestFExpBasic(t *testing.T) {
	var key aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	// Test various output lengths
	lengths := []int{16, 32, 64, 128, 256, 512, 1024}

	for _, length := range lengths {
		output := FExp(&key, &info, length)
		if len(output) != length {
			t.Errorf("FExp(%d): expected %d bytes, got %d", length, length, len(output))
		}

		// Output should not be all zeros
		allZero := true
		for _, b := range output {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Errorf("FExp(%d): output should not be all zeros", length)
		}
	}
}

func TestFExpDeterministic(t *testing.T) {
	var key aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	output1 := FExp(&key, &info, 64)
	output2 := FExp(&key, &info, 64)

	if !bytes.Equal(output1, output2) {
		t.Error("FExp should be deterministic")
	}
}

func TestFExpDifferentInfoProducesDifferentOutput(t *testing.T) {
	var key aes.Block
	var info1, info2 SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info1[i] = byte(i)
		info2[i] = byte(i + 1)
	}

	output1 := FExp(&key, &info1, 64)
	output2 := FExp(&key, &info2, 64)

	if bytes.Equal(output1, output2) {
		t.Error("Different info should produce different output")
	}
}

func TestFExpDifferentKeyProducesDifferentOutput(t *testing.T) {
	var key1, key2 aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i)
	}

	output1 := FExp(&key1, &info, 64)
	output2 := FExp(&key2, &info, 64)

	if bytes.Equal(output1, output2) {
		t.Error("Different key should produce different output")
	}
}

func TestFExpZeroLength(t *testing.T) {
	var key aes.Block
	var info SkyeInfo

	output := FExp(&key, &info, 0)
	if output != nil {
		t.Error("FExp(0) should return nil")
	}

	output = FExp(&key, &info, -1)
	if output != nil {
		t.Error("FExp(-1) should return nil")
	}
}

func TestSkye(t *testing.T) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 128)
	}

	output, err := Skye([][]byte{sample1, sample2, sample3}, &info, 64)
	if err != nil {
		t.Fatalf("Skye failed: %v", err)
	}

	if len(output) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(output))
	}
}

func TestSkyeContext(t *testing.T) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	ctx, err := NewSkyeContext([][]byte{sample1, sample2, sample3})
	if err != nil {
		t.Fatalf("NewSkyeContext failed: %v", err)
	}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 128)
	}

	// Direct call and context should produce same result
	directOutput, _ := Skye([][]byte{sample1, sample2, sample3}, &info, 64)
	contextOutput := ctx.Expand(&info, 64)

	if !bytes.Equal(directOutput, contextOutput) {
		t.Error("Context and direct call should produce same output")
	}
}

func TestFExpContext(t *testing.T) {
	var key aes.Block
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}

	ctx := NewFExpContext(&key)

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	// Direct call and context should produce same result
	directOutput := FExp(&key, &info, 64)
	contextOutput := ctx.Expand(&info, 64)

	if !bytes.Equal(directOutput, contextOutput) {
		t.Error("FExpContext and direct call should produce same output")
	}
}

func TestExpandFromKey(t *testing.T) {
	var key aes.Block
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	output1 := FExp(&key, &info, 64)
	output2 := ExpandFromKey(&key, &info, 64)

	if !bytes.Equal(output1, output2) {
		t.Error("ExpandFromKey should match FExp")
	}
}

func TestDExtLsb3SamplesManual(t *testing.T) {
	// Manual test to verify the 3-sample extraction
	// For 3 samples with k=128: α1 = 64, α2 = 64
	// K_ext = lsb_64(DH1⊕DH2) || lsb_64(DH2⊕DH3)

	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	// Set specific values in the last 8 bytes (which will be extracted)
	for i := 23; i < 31; i++ {
		sample1[i] = byte(i - 23 + 1)       // 1, 2, 3, 4, 5, 6, 7, 8
		sample2[i] = byte((i - 23 + 1) * 2) // 2, 4, 6, 8, 10, 12, 14, 16
		sample3[i] = byte((i - 23 + 1) * 3) // 3, 6, 9, 12, 15, 18, 21, 24
	}

	key, err := DExtLsb([][]byte{sample1, sample2, sample3})
	if err != nil {
		t.Fatalf("DExtLsb failed: %v", err)
	}

	// First 8 bytes should be sample1[23:31] XOR sample2[23:31]
	// = (1,2,3,4,5,6,7,8) XOR (2,4,6,8,10,12,14,16)
	// = (3,6,5,12,15,10,9,24)
	expected1 := []byte{3, 6, 5, 12, 15, 10, 9, 24}
	if !bytes.Equal(key[0:8], expected1) {
		t.Errorf("First 8 bytes: expected %v, got %v", expected1, key[0:8])
	}

	// Second 8 bytes should be sample2[23:31] XOR sample3[23:31]
	// = (2,4,6,8,10,12,14,16) XOR (3,6,9,12,15,18,21,24)
	// = (1,2,15,4,5,30,27,8)
	expected2 := []byte{1, 2, 15, 4, 5, 30, 27, 8}
	if !bytes.Equal(key[8:16], expected2) {
		t.Errorf("Second 8 bytes: expected %v, got %v", expected2, key[8:16])
	}
}

func TestSkyeOutputConsistency(t *testing.T) {
	// Generate test samples
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i * 7)
		sample2[i] = byte(i * 11)
		sample3[i] = byte(i * 13)
	}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i * 17)
	}

	// Get outputs of different lengths
	out32, _ := Skye([][]byte{sample1, sample2, sample3}, &info, 32)
	out64, _ := Skye([][]byte{sample1, sample2, sample3}, &info, 64)
	out128, _ := Skye([][]byte{sample1, sample2, sample3}, &info, 128)

	// Shorter outputs should be prefixes of longer ones
	if !bytes.Equal(out32, out64[:32]) {
		t.Error("32-byte output should be prefix of 64-byte output")
	}
	if !bytes.Equal(out64, out128[:64]) {
		t.Error("64-byte output should be prefix of 128-byte output")
	}
}

func TestSkyeWithZeroInfo(t *testing.T) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	var info SkyeInfo // All zeros

	output, err := Skye([][]byte{sample1, sample2, sample3}, &info, 32)
	if err != nil {
		t.Fatalf("Skye with zero info failed: %v", err)
	}

	if len(output) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(output))
	}
}

// Test vector from paper or reference implementation (placeholder)
func TestSkyeTestVector(t *testing.T) {
	// Create deterministic test samples
	sample1, _ := hex.DecodeString("0001020304050607080910111213141516171819202122232425262728293031")
	sample2, _ := hex.DecodeString("1011121314151617181920212223242526272829303132333435363738394041")
	sample3, _ := hex.DecodeString("2021222324252627282930313233343536373839404142434445464748495051")

	var info SkyeInfo
	copy(info[:], []byte("Skye test info string for KDF!!")) // 31 bytes + 1 null

	output, err := Skye([][]byte{sample1, sample2, sample3}, &info, 32)
	if err != nil {
		t.Fatalf("Skye failed: %v", err)
	}

	// Verify output is reproducible
	output2, _ := Skye([][]byte{sample1, sample2, sample3}, &info, 32)
	if !bytes.Equal(output, output2) {
		t.Error("Skye should produce deterministic output")
	}
}

// Benchmarks

func BenchmarkDExtLsb3(b *testing.B) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	samples := [][]byte{sample1, sample2, sample3}

	b.SetBytes(3 * 32) // 3 samples of 32 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DExtLsb(samples)
	}
}

func BenchmarkDExtLsb4(b *testing.B) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)
	sample4 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
		sample4[i] = byte(i + 96)
	}

	samples := [][]byte{sample1, sample2, sample3, sample4}

	b.SetBytes(4 * 32) // 4 samples of 32 bytes
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DExtLsb(samples)
	}
}

func BenchmarkFExp32(b *testing.B) {
	var key aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FExp(&key, &info, 32)
	}
}

func BenchmarkFExp128(b *testing.B) {
	var key aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	b.SetBytes(128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FExp(&key, &info, 128)
	}
}

func BenchmarkFExp1024(b *testing.B) {
	var key aes.Block
	var info SkyeInfo

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 16)
	}

	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FExp(&key, &info, 1024)
	}
}

func BenchmarkSkye32(b *testing.B) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	samples := [][]byte{sample1, sample2, sample3}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 128)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Skye(samples, &info, 32)
	}
}

func BenchmarkSkye128(b *testing.B) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	samples := [][]byte{sample1, sample2, sample3}

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 128)
	}

	b.SetBytes(128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Skye(samples, &info, 128)
	}
}

func BenchmarkSkyeContext(b *testing.B) {
	sample1 := make([]byte, 32)
	sample2 := make([]byte, 32)
	sample3 := make([]byte, 32)

	for i := 0; i < 32; i++ {
		sample1[i] = byte(i)
		sample2[i] = byte(i + 32)
		sample3[i] = byte(i + 64)
	}

	ctx, _ := NewSkyeContext([][]byte{sample1, sample2, sample3})

	var info SkyeInfo
	for i := 0; i < 32; i++ {
		info[i] = byte(i + 128)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Expand(&info, 32)
	}
}
