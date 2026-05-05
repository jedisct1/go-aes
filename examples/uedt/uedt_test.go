package uedt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

type mode struct {
	name    string
	encrypt func(MK *aes.Block, N, A, M []byte) ([]byte, [TagSize]byte, error)
	decrypt func(MK *aes.Block, N, A, C []byte, tag [TagSize]byte) ([]byte, error)
}

var modes = []mode{
	{"UEDTDM", EncryptDM, DecryptDM},
	{"UEDTMX", EncryptMX, DecryptMX},
}

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func TestRoundtrip(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			lengths := []int{0, 1, 15, 16, 17, 31, 32, 33, 100, 128 * 16, 128*16 + 1, 256 * 16, 1024}
			var MK aes.Block
			copy(MK[:], mustRand(t, KeySize))

			for _, n := range lengths {
				for _, alen := range []int{0, 1, 16, 33} {
					msg := mustRand(t, n)
					ad := mustRand(t, alen)
					nonce := mustRand(t, NonceSize)

					C, tag, err := m.encrypt(&MK, nonce, ad, msg)
					if err != nil {
						t.Fatalf("encrypt(|M|=%d,|A|=%d): %v", n, alen, err)
					}
					if len(C) != len(msg) {
						t.Fatalf("ciphertext length mismatch: got %d want %d", len(C), len(msg))
					}

					M2, err := m.decrypt(&MK, nonce, ad, C, tag)
					if err != nil {
						t.Fatalf("decrypt(|M|=%d,|A|=%d): %v", n, alen, err)
					}
					if !bytes.Equal(M2, msg) {
						t.Fatalf("plaintext mismatch (|M|=%d,|A|=%d)", n, alen)
					}
				}
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var MK aes.Block
			copy(MK[:], mustRand(t, KeySize))
			N := mustRand(t, NonceSize)
			A := mustRand(t, 24)
			M := mustRand(t, 200)

			C1, T1, err := m.encrypt(&MK, N, A, M)
			if err != nil {
				t.Fatal(err)
			}
			C2, T2, err := m.encrypt(&MK, N, A, M)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(C1, C2) {
				t.Fatalf("ciphertext is not deterministic")
			}
			if T1 != T2 {
				t.Fatalf("tag is not deterministic")
			}
		})
	}
}

func TestTamperDetection(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var MK aes.Block
			copy(MK[:], mustRand(t, KeySize))
			N := mustRand(t, NonceSize)
			A := mustRand(t, 11)
			M := mustRand(t, 50)

			C, tag, err := m.encrypt(&MK, N, A, M)
			if err != nil {
				t.Fatal(err)
			}

			// Flip a bit in the ciphertext.
			Cbad := append([]byte(nil), C...)
			Cbad[0] ^= 0x01
			if _, err := m.decrypt(&MK, N, A, Cbad, tag); !errors.Is(err, ErrAuthFailure) {
				t.Fatalf("expected ErrAuthFailure on flipped ciphertext, got %v", err)
			}

			// Flip a bit in the tag.
			tagBad := tag
			tagBad[0] ^= 0x80
			if _, err := m.decrypt(&MK, N, A, C, tagBad); !errors.Is(err, ErrAuthFailure) {
				t.Fatalf("expected ErrAuthFailure on flipped tag, got %v", err)
			}

			// Flip a bit in the AD.
			Abad := append([]byte(nil), A...)
			Abad[0] ^= 0x10
			if _, err := m.decrypt(&MK, N, Abad, C, tag); !errors.Is(err, ErrAuthFailure) {
				t.Fatalf("expected ErrAuthFailure on flipped AD, got %v", err)
			}

			// Different nonce.
			Nbad := append([]byte(nil), N...)
			Nbad[NonceSize-1] ^= 0x40
			if _, err := m.decrypt(&MK, Nbad, A, C, tag); !errors.Is(err, ErrAuthFailure) {
				t.Fatalf("expected ErrAuthFailure on different nonce, got %v", err)
			}

			// Different key.
			MK2 := MK
			MK2[0] ^= 0x20
			if _, err := m.decrypt(&MK2, N, A, C, tag); !errors.Is(err, ErrAuthFailure) {
				t.Fatalf("expected ErrAuthFailure on wrong key, got %v", err)
			}
		})
	}
}

func TestEmptyMessage(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var MK aes.Block
			copy(MK[:], mustRand(t, KeySize))
			N := mustRand(t, NonceSize)
			A := []byte("metadata")

			C, tag, err := m.encrypt(&MK, N, A, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(C) != 0 {
				t.Fatalf("expected empty ciphertext, got %d bytes", len(C))
			}

			M2, err := m.decrypt(&MK, N, A, C, tag)
			if err != nil {
				t.Fatal(err)
			}
			if len(M2) != 0 {
				t.Fatalf("expected empty plaintext, got %d bytes", len(M2))
			}
		})
	}
}

func TestNonceLength(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var MK aes.Block
			if _, _, err := m.encrypt(&MK, make([]byte, NonceSize-1), nil, []byte("x")); err == nil {
				t.Fatal("expected error for short nonce")
			}
			if _, _, err := m.encrypt(&MK, make([]byte, NonceSize+1), nil, []byte("x")); err == nil {
				t.Fatal("expected error for long nonce")
			}
		})
	}
}

func TestChunkBoundary(t *testing.T) {
	// Exercise messages that straddle the omega = 128 chunk boundary so the
	// fk re-keying logic is exercised.
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var MK aes.Block
			copy(MK[:], mustRand(t, KeySize))
			N := mustRand(t, NonceSize)
			A := mustRand(t, 5)

			for _, blocks := range []int{127, 128, 129, 256, 257} {
				M := mustRand(t, blocks*blockSize+3)
				C, tag, err := m.encrypt(&MK, N, A, M)
				if err != nil {
					t.Fatalf("blocks=%d: %v", blocks, err)
				}
				M2, err := m.decrypt(&MK, N, A, C, tag)
				if err != nil {
					t.Fatalf("blocks=%d: %v", blocks, err)
				}
				if !bytes.Equal(M, M2) {
					t.Fatalf("blocks=%d: plaintext mismatch", blocks)
				}
			}
		})
	}
}

// TestMJHDistinct is a smoke test that MJH does not collapse distinct inputs.
func TestMJHDistinct(t *testing.T) {
	var g, h, w1, w2 aes.Block
	w1[0] = 1
	w2[0] = 2
	g1, h1 := mjhCompress(&g, &h, &w1)
	g2, h2 := mjhCompress(&g, &h, &w2)
	if g1 == g2 && h1 == h2 {
		t.Fatalf("MJH collapsed distinct inputs")
	}
}

func TestGfDoubleNonZero(t *testing.T) {
	var x aes.Block
	x[15] = 1
	gfDouble(&x)
	expected := aes.Block{}
	expected[15] = 2
	if x != expected {
		t.Fatalf("2 * 1 in GF(2^128): got % x want % x", x, expected)
	}

	// Carry case: top bit set must reduce by 0x87 in the LSB.
	var y aes.Block
	y[0] = 0x80
	gfDouble(&y)
	expected = aes.Block{}
	expected[15] = 0x87
	if y != expected {
		t.Fatalf("2 * x^127 reduction: got % x want % x", y, expected)
	}
}

func benchmarkEncrypt(b *testing.B, enc func(MK *aes.Block, N, A, M []byte) ([]byte, [TagSize]byte, error), size int) {
	var MK aes.Block
	_, _ = rand.Read(MK[:])
	N := make([]byte, NonceSize)
	_, _ = rand.Read(N)
	M := make([]byte, size)
	_, _ = rand.Read(M)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = enc(&MK, N, nil, M)
	}
}

func BenchmarkEncryptDM_1KB(b *testing.B) { benchmarkEncrypt(b, EncryptDM, 1024) }
func BenchmarkEncryptMX_1KB(b *testing.B) { benchmarkEncrypt(b, EncryptMX, 1024) }
func BenchmarkEncryptDM_8KB(b *testing.B) { benchmarkEncrypt(b, EncryptDM, 8192) }
func BenchmarkEncryptMX_8KB(b *testing.B) { benchmarkEncrypt(b, EncryptMX, 8192) }
