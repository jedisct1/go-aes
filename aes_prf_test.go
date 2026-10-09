package aes

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Computed with a separate Python implementation.
func TestAESPRF(t *testing.T) {
	vectors := []struct {
		key, input, output string
	}{
		{"00000000000000000000000000000000", "00000000000000000000000000000000", "cd3b862ad8d09972d8ec5599bfae4171"},
		{"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "4db6a0fb031db7cab61fc2b2f8f69e36"},
		{"000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "37b323f64adfaff1a4ccaca0b2733cc0"},
		{"000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "bab78d59c866c1e3b173c14fd175eaa1"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "881f61cd86fba8e255641527cd765936"},
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "58f113a33dc7f9b0b036e2cdf2253ef4"},
	}
	for _, v := range vectors {
		prf, err := NewAESPRF(hexToBytes(v.key))
		if err != nil {
			t.Fatal(err)
		}
		block := bytesToBlock(hexToBytes(v.input))
		prf.PRF(&block)
		if got := hex.EncodeToString(block[:]); got != v.output {
			t.Errorf("key %s: got %s, want %s", v.key, got, v.output)
		}
	}
}

func BenchmarkAESPRF(b *testing.B) {
	for _, keyLen := range []int{16, 24, 32} {
		b.Run(fmt.Sprintf("AES-%d", keyLen*8), func(b *testing.B) {
			prf, _ := NewAESPRF(make([]byte, keyLen))
			var block Block
			b.SetBytes(16)
			for b.Loop() {
				prf.PRF(&block)
			}
		})
	}
}
