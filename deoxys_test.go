package aes

import (
	"encoding/hex"
	"testing"
)

// TestDeoxysRoundConstant verifies the ButterKnife variant round constant generation.
// The round constant uses column-major format (matching AES state layout):
//   - Column 0: [1, 2, 4, 8]
//   - Column 1: [rc, rc, rc, rc]
//   - Column 2: [jb, jb, jb, jb] (domain)
//   - Column 3: [0, 0, 0, 0]
func TestDeoxysRoundConstant(t *testing.T) {
	tests := []struct {
		domain   byte
		roundNum int
		expected string
	}{
		{
			domain:   0,
			roundNum: 0,
			// RC[0] = 0x01, domain = 0
			// Col0=[1,2,4,8], Col1=[01,01,01,01], Col2=[00,00,00,00], Col3=[00,00,00,00]
			expected: "01020408010101010000000000000000",
		},
		{
			domain:   1,
			roundNum: 0,
			// RC[0] = 0x01, domain = 1
			// Col0=[1,2,4,8], Col1=[01,01,01,01], Col2=[01,01,01,01], Col3=[00,00,00,00]
			expected: "01020408010101010101010100000000",
		},
		{
			domain:   0,
			roundNum: 7,
			// RC[7] = 0x80, domain = 0
			// Col0=[1,2,4,8], Col1=[80,80,80,80], Col2=[00,00,00,00], Col3=[00,00,00,00]
			expected: "01020408808080800000000000000000",
		},
	}

	for _, tt := range tests {
		rconst := DeoxysRoundConstant(tt.domain, tt.roundNum)
		got := hex.EncodeToString(rconst[:])
		if got != tt.expected {
			t.Errorf("DeoxysRoundConstant(domain=%d, round=%d) = %s, want %s",
				tt.domain, tt.roundNum, got, tt.expected)
		}
	}
}

// TestDeoxysPermuteTK verifies the Deoxys tweakey permutation
func TestDeoxysPermuteTK(t *testing.T) {
	// Test with a known pattern
	// h permutation: byte at position i moves to position h[i]
	// h = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8]
	// So: byte 0 -> pos 1, byte 1 -> pos 6, byte 2 -> pos 11, etc.
	tk := Block{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	// Expected: output[h[i]] = input[i]
	// output[1]=0, output[6]=1, output[11]=2, output[12]=3, output[5]=4, output[10]=5,
	// output[15]=6, output[0]=7, output[9]=8, output[14]=9, output[3]=10, output[4]=11,
	// output[13]=12, output[2]=13, output[7]=14, output[8]=15
	expected := Block{7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6}

	DeoxysPermuteTK(&tk)

	if tk != expected {
		t.Errorf("DeoxysPermuteTK failed\ngot:  %v\nwant: %v", tk, expected)
	}
}

// TestDeoxysLFSR2 verifies the LFSR operation on all 16 bytes
func TestDeoxysLFSR2(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			// Test with zeros (LFSR of 0 is 0)
			input:    "00000000000000000000000000000000",
			expected: "00000000000000000000000000000000",
		},
		{
			// Test with 0x01: (00000001) -> (00000010)
			input:    "01000000000000000000000000000000",
			expected: "02000000000000000000000000000000",
		},
		{
			// Test with 0x80: (10000000) -> (00000001 ⊕ 1) = (00000000)
			input:    "80000000000000000000000000000000",
			expected: "01000000000000000000000000000000",
		},
		{
			// Test with 0xFF: (11111111) -> (11111110 ⊕ 1 ⊕ 1) = (11111110)
			input:    "ff000000000000000000000000000000",
			expected: "fe000000000000000000000000000000",
		},
		{
			// Test that LFSR2 applies to ALL 16 bytes, not just first 8
			// Each byte is shifted independently
			// LFSR2: (b << 1) | ((b >> 7) ^ (b >> 5)) & 1
			// 0x20 = 00100000 → shift left: 01000000, feedback: (0 ^ 1) & 1 = 1 → 0x41
			input:    "01020408102040800102040810204080",
			expected: "02040810204180010204081020418001",
		},
		{
			// Test with all 0x80 bytes - each becomes 0x01
			input:    "80808080808080808080808080808080",
			expected: "01010101010101010101010101010101",
		},
	}

	for _, tt := range tests {
		input, _ := hex.DecodeString(tt.input)
		expected, _ := hex.DecodeString(tt.expected)

		var tk Block
		copy(tk[:], input)
		DeoxysLFSR2(&tk)

		if tk != *(*Block)(expected) {
			t.Errorf("DeoxysLFSR2(%s) = %x, want %s",
				tt.input, tk[:], tt.expected)
		}
	}
}

// TestDeoxysExpandTweakey256 verifies the tweakey expansion (ButterKnife variant)
func TestDeoxysExpandTweakey256(t *testing.T) {
	// Test with zero tweakey
	var tweakey Tweakey256
	rtk := DeoxysExpandTweakey256(&tweakey)

	// Verify we get 17 round keys for each state (for ButterKnife: rounds 0-16)
	if len(rtk.TK1) != 17 {
		t.Errorf("Expected 17 TK1 round keys, got %d", len(rtk.TK1))
	}
	if len(rtk.TK2) != 17 {
		t.Errorf("Expected 17 TK2 round keys, got %d", len(rtk.TK2))
	}

	// TK1[0] and TK2[0] should be zero
	var zeroBlock Block
	if rtk.TK1[0] != zeroBlock {
		t.Errorf("TK1[0] should be zero for zero tweakey")
	}
	if rtk.TK2[0] != zeroBlock {
		t.Errorf("TK2[0] should be zero for zero tweakey")
	}

	// For zero input, all TK1 rounds should be zero (permutation of zero is zero)
	for i := 1; i < 17; i++ {
		if rtk.TK1[i] != zeroBlock {
			t.Errorf("TK1[%d] should be zero for zero tweakey", i)
		}
	}

	// TK2 rounds should also be zero (LFSR of zero is zero)
	for i := 1; i < 17; i++ {
		if rtk.TK2[i] != zeroBlock {
			t.Errorf("TK2[%d] should be zero for zero tweakey", i)
		}
	}
}

// TestDeoxysRound verifies a single Deoxys round
func TestDeoxysRound(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rtk := DeoxysExpandTweakey256(&tweakey)

	var state Block
	for i := 0; i < 16; i++ {
		state[i] = byte(i)
	}

	// Run a round
	DeoxysRound(&state, rtk, 0, 0)

	// State should be modified
	var zeroBlock Block
	if state == zeroBlock {
		t.Error("State should be modified after round")
	}
}

// TestDeoxysBC256RoundConstant verifies the round constant format matches the specification.
// Format: [1, 2, 4, 8, rc, rc, rc, rc, 0, 0, 0, 0, 0, 0, 0, 0]
// where rc is the RCON value for that round, starting at AES RCON position 16 (0x2f).
func TestDeoxysBC256RoundConstant(t *testing.T) {
	// With zero tweakey, STK[0] = 0 XOR 0 XOR RCON[0]
	var tweakey Tweakey256
	rk := NewDeoxysBC256(&tweakey)

	// Expected: [1, 2, 4, 8, 0x2f, 0x2f, 0x2f, 0x2f, 0, 0, 0, 0, 0, 0, 0, 0]
	expected, _ := hex.DecodeString("010204082f2f2f2f0000000000000000")
	if rk.STK[0] != *(*Block)(expected) {
		t.Errorf("STK[0] with zero tweakey:\ngot:  %x\nwant: %s", rk.STK[0][:], "010204082f2f2f2f0000000000000000")
	}
}

// TestDeoxysBC256Subtweakeys verifies subtweakey generation with a known tweakey
func TestDeoxysBC256Subtweakeys(t *testing.T) {
	// Tweakey = 0x10,0x11,...,0x2f (incrementing from 0x10)
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(0x10 + i)
	}

	rk := NewDeoxysBC256(&tweakey)

	// STK[0] = TK1 XOR TK2 XOR RCON[0]
	// TK1 = [0x10..0x1f], TK2 = [0x20..0x2f], RCON[0] = [1,2,4,8,0x2f,0x2f,0x2f,0x2f,0,0,0,0,0,0,0,0]
	expected0, _ := hex.DecodeString("313234381f1f1f1f3030303030303030")
	if rk.STK[0] != *(*Block)(expected0) {
		t.Errorf("STK[0] mismatch:\ngot:  %x\nwant: %s", rk.STK[0][:], "313234381f1f1f1f3030303030303030")
	}
}

// TestDeoxysBC256ZeroTweakey tests Deoxys-BC-256 with zero input
func TestDeoxysBC256ZeroTweakey(t *testing.T) {
	// Test with all-zero tweakey and plaintext
	var tweakey Tweakey256
	rk := NewDeoxysBC256(&tweakey)

	var plaintext Block
	ct := DeoxysBC256Encrypt(rk, &plaintext)

	// With all zeros, ciphertext should not be zero (encryption should mix)
	var zeroBlock Block
	if ct == zeroBlock {
		t.Error("Encryption of zero plaintext with zero tweakey should not be zero")
	}

	// Verify the actual ciphertext value (self-generated test vector)
	expectedCT, _ := hex.DecodeString("868f13071b5cb95a0ea173afcb091968")
	if ct != *(*Block)(expectedCT) {
		t.Errorf("Ciphertext mismatch:\ngot:  %x\nwant: %s", ct[:], "868f13071b5cb95a0ea173afcb091968")
	}

	// Decrypt should recover plaintext
	decrypted := DeoxysBC256Decrypt(rk, &ct)
	if decrypted != plaintext {
		t.Errorf("Decrypt failed: got %x, want %x", decrypted[:], plaintext[:])
	}
}

// TestDeoxysBC256RoundTrip verifies encrypt then decrypt gives original plaintext
func TestDeoxysBC256RoundTrip(t *testing.T) {
	// Test with random-looking data
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i * 17)
	}

	rk := NewDeoxysBC256(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i * 13)
	}

	// Encrypt
	ciphertext := DeoxysBC256Encrypt(rk, &plaintext)

	// Decrypt
	decrypted := DeoxysBC256Decrypt(rk, &ciphertext)

	if decrypted != plaintext {
		t.Errorf("Round trip failed\noriginal:  %x\ndecrypted: %x", plaintext[:], decrypted[:])
	}
}

// BenchmarkDeoxysBC256Encrypt benchmarks standard Deoxys-BC-256 encryption
func BenchmarkDeoxysBC256Encrypt(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rk := NewDeoxysBC256(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i)
	}

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysBC256Encrypt(rk, &plaintext)
	}
}

// BenchmarkDeoxysBC256Decrypt benchmarks standard Deoxys-BC-256 decryption
func BenchmarkDeoxysBC256Decrypt(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rk := NewDeoxysBC256(&tweakey)

	var ciphertext Block
	for i := 0; i < 16; i++ {
		ciphertext[i] = byte(i)
	}

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysBC256Decrypt(rk, &ciphertext)
	}
}

// BenchmarkNewDeoxysBC256 benchmarks standard Deoxys-BC-256 key expansion
func BenchmarkNewDeoxysBC256(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewDeoxysBC256(&tweakey)
	}
}

// BenchmarkDeoxysExpandTweakey256 benchmarks the tweakey expansion
func BenchmarkDeoxysExpandTweakey256(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysExpandTweakey256(&tweakey)
	}
}

// BenchmarkDeoxysRound benchmarks a single Deoxys round
func BenchmarkDeoxysRound(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rtk := DeoxysExpandTweakey256(&tweakey)

	var state Block
	for i := 0; i < 16; i++ {
		state[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysRound(&state, rtk, 0, 0)
	}
}

// TestDeoxysBC256EncryptHW verifies hardware encryption matches software
func TestDeoxysBC256EncryptHW(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i * 17)
	}

	rk := NewDeoxysBC256(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i * 13)
	}

	// Software encryption
	swCiphertext := DeoxysBC256Encrypt(rk, &plaintext)

	// Hardware encryption
	hwCiphertext := DeoxysBC256EncryptHW(rk, &plaintext)

	if swCiphertext != hwCiphertext {
		t.Errorf("HW encrypt mismatch:\nsw: %x\nhw: %x", swCiphertext[:], hwCiphertext[:])
	}
}

// TestDeoxysBC256DecryptHW verifies hardware decryption matches software
func TestDeoxysBC256DecryptHW(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i * 17)
	}

	rk := NewDeoxysBC256HW(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i * 13)
	}

	// Encrypt first
	ciphertext := DeoxysBC256Encrypt(&rk.DeoxysBC256RoundKeys, &plaintext)

	// Software decryption
	swPlaintext := DeoxysBC256Decrypt(&rk.DeoxysBC256RoundKeys, &ciphertext)

	// Hardware decryption
	hwPlaintext := DeoxysBC256DecryptHW(rk, &ciphertext)

	if swPlaintext != hwPlaintext {
		t.Errorf("HW decrypt mismatch:\nsw: %x\nhw: %x", swPlaintext[:], hwPlaintext[:])
	}

	if hwPlaintext != plaintext {
		t.Errorf("HW decrypt round-trip failed:\noriginal: %x\ndecrypted: %x", plaintext[:], hwPlaintext[:])
	}
}

// TestDeoxysBC256HWRoundTrip verifies encrypt/decrypt round-trip with HW
func TestDeoxysBC256HWRoundTrip(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i ^ 0xAA)
	}

	rk := NewDeoxysBC256HW(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i * 7)
	}

	// Encrypt with HW
	ciphertext := DeoxysBC256EncryptHW(&rk.DeoxysBC256RoundKeys, &plaintext)

	// Decrypt with HW
	decrypted := DeoxysBC256DecryptHW(rk, &ciphertext)

	if decrypted != plaintext {
		t.Errorf("HW round-trip failed:\noriginal: %x\ndecrypted: %x", plaintext[:], decrypted[:])
	}
}

// BenchmarkDeoxysBC256EncryptHW benchmarks hardware-accelerated encryption
func BenchmarkDeoxysBC256EncryptHW(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rk := NewDeoxysBC256(&tweakey)

	var plaintext Block
	for i := 0; i < 16; i++ {
		plaintext[i] = byte(i)
	}

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysBC256EncryptHW(rk, &plaintext)
	}
}

// BenchmarkDeoxysBC256DecryptHW benchmarks hardware-accelerated decryption
func BenchmarkDeoxysBC256DecryptHW(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	rk := NewDeoxysBC256HW(&tweakey)

	var ciphertext Block
	for i := 0; i < 16; i++ {
		ciphertext[i] = byte(i)
	}

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeoxysBC256DecryptHW(rk, &ciphertext)
	}
}
