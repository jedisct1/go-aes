package aes

import (
	"encoding/hex"
	"testing"
)

func TestPadTweak(t *testing.T) {
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	expected := [16]byte{0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00}
	padded := PadTweak(tweak)
	if padded != expected {
		t.Errorf("PadTweak failed:\nGot:      %x\nExpected: %x", padded, expected)
	}
}

// Test vector from the reference implementation
func TestKiasuEncryptDecrypt(t *testing.T) {
	// Test vector from test_vectors.json: ipcrypt-nd variant
	// key: "0123456789abcdeffedcba9876543210"
	// ip: "0.0.0.0" -> 00000000000000000000ffff00000000 (IPv4-mapped IPv6)
	// tweak: "08e0c289bff23b7c"
	// output: "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"
	// The output is tweak || ciphertext, so ciphertext is the last 16 bytes

	keyHex := "0123456789abcdeffedcba9876543210"
	tweakHex := "08e0c289bff23b7c"
	plaintextHex := "00000000000000000000ffff00000000"
	expectedCiphertextHex := "b349aadfe3bcef56221c384c7c217b16"

	key, _ := hex.DecodeString(keyHex)
	tweak, _ := hex.DecodeString(tweakHex)
	plaintext, _ := hex.DecodeString(plaintextHex)

	var keyArray [16]byte
	var tweakArray [8]byte
	var plaintextArray [16]byte
	copy(keyArray[:], key)
	copy(tweakArray[:], tweak)
	copy(plaintextArray[:], plaintext)

	ctx, err := NewKiasuContext(keyArray)
	if err != nil {
		t.Fatalf("Failed to create KIASU context: %v", err)
	}

	// Test encryption
	ciphertext := ctx.KiasuEncrypt(plaintextArray, tweakArray)
	if hex.EncodeToString(ciphertext[:]) != expectedCiphertextHex {
		t.Errorf("Encryption failed:\nGot:      %x\nExpected: %s", ciphertext, expectedCiphertextHex)
	}

	// Test decryption
	decrypted := ctx.KiasuDecrypt(ciphertext, tweakArray)
	if hex.EncodeToString(decrypted[:]) != plaintextHex {
		t.Errorf("Decryption failed:\nGot:      %x\nExpected: %s", decrypted, plaintextHex)
	}
}

// Additional test vectors from the reference implementation
func TestKiasuMultipleVectors(t *testing.T) {
	testVectors := []struct {
		name       string
		key        string
		tweak      string
		plaintext  string
		ciphertext string
	}{
		{
			name:       "Vector 1: 0.0.0.0",
			key:        "0123456789abcdeffedcba9876543210",
			tweak:      "08e0c289bff23b7c",
			plaintext:  "00000000000000000000ffff00000000",
			ciphertext: "b349aadfe3bcef56221c384c7c217b16",
		},
		{
			name:       "Vector 2: 255.255.255.255",
			key:        "1032547698badcfeefcdab8967452301",
			tweak:      "08e0c289bff23b7c",
			plaintext:  "00000000000000000000ffffffffffff",
			ciphertext: "f602ae8dcfeb47c1fbcb9597b8951b89",
		},
		{
			name:       "Vector 3: 192.0.2.1",
			key:        "2b7e151628aed2a6abf7158809cf4f3c",
			tweak:      "08e0c289bff23b7c",
			plaintext:  "00000000000000000000ffffc0000201",
			ciphertext: "ca25fe3b7f2ca5e50a0deb24ef0469f8",
		},
		{
			name:       "Vector 4: 2001:db8:85a3::8a2e:370:7334",
			key:        "0123456789abcdeffedcba9876543210",
			tweak:      "08e0c289bff23b7c",
			plaintext:  "20010db885a3000000008a2e03707334",
			ciphertext: "dd344485c55026d8b4cfa33b81032aff",
		},
		{
			name:       "Vector 5: 192.0.2.1 (different key)",
			key:        "1032547698badcfeefcdab8967452301",
			tweak:      "08e0c289bff23b7c",
			plaintext:  "00000000000000000000ffffc0000201",
			ciphertext: "18e29f7c1fc75164251238ed9f0bd02a",
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tv.key)
			tweak, _ := hex.DecodeString(tv.tweak)
			plaintext, _ := hex.DecodeString(tv.plaintext)

			var keyArray [16]byte
			var tweakArray [8]byte
			var plaintextArray [16]byte
			copy(keyArray[:], key)
			copy(tweakArray[:], tweak)
			copy(plaintextArray[:], plaintext)

			ctx, err := NewKiasuContext(keyArray)
			if err != nil {
				t.Fatalf("Failed to create KIASU context: %v", err)
			}

			// Test encryption
			ciphertext := ctx.KiasuEncrypt(plaintextArray, tweakArray)
			if hex.EncodeToString(ciphertext[:]) != tv.ciphertext {
				t.Errorf("Encryption failed:\nGot:      %x\nExpected: %s", ciphertext, tv.ciphertext)
			}

			// Test decryption
			decrypted := ctx.KiasuDecrypt(ciphertext, tweakArray)
			if decrypted != plaintextArray {
				t.Errorf("Decryption failed:\nGot:      %x\nExpected: %x", decrypted, plaintextArray)
			}

			// Verify round-trip
			if decrypted != plaintextArray {
				t.Errorf("Round-trip failed: plaintext != decrypt(encrypt(plaintext))")
			}
		})
	}
}

// Test that hardware-accelerated version matches software version
func TestKiasuHardwareMatchesSoftware(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("Hardware acceleration not available")
	}

	key := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ctx, _ := NewKiasuContext(key)

	// Test encryption
	swEncrypt := ctx.KiasuEncrypt(block, tweak)
	hwEncrypt := ctx.KiasuEncryptHW(block, tweak)

	if swEncrypt != hwEncrypt {
		t.Errorf("Hardware encryption doesn't match software:\nSW: %x\nHW: %x", swEncrypt, hwEncrypt)
	}

	// Test decryption
	swDecrypt := ctx.KiasuDecrypt(swEncrypt, tweak)
	hwDecrypt := ctx.KiasuDecryptHW(hwEncrypt, tweak)

	if swDecrypt != hwDecrypt {
		t.Errorf("Hardware decryption doesn't match software:\nSW: %x\nHW: %x", swDecrypt, hwDecrypt)
	}

	// Verify round-trip
	if swDecrypt != block {
		t.Errorf("Software round-trip failed")
	}
	if hwDecrypt != block {
		t.Errorf("Hardware round-trip failed")
	}
}

func BenchmarkKiasuEncrypt(b *testing.B) {
	key := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ctx, _ := NewKiasuContext(key)

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.KiasuEncrypt(block, tweak)
	}
}

func BenchmarkKiasuDecrypt(b *testing.B) {
	key := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ctx, _ := NewKiasuContext(key)

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.KiasuDecrypt(block, tweak)
	}
}

func BenchmarkKiasuEncryptHW(b *testing.B) {
	key := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ctx, _ := NewKiasuContext(key)

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.KiasuEncryptHW(block, tweak)
	}
}

func BenchmarkKiasuDecryptHW(b *testing.B) {
	key := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tweak := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	ctx, _ := NewKiasuContext(key)

	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.KiasuDecryptHW(block, tweak)
	}
}
