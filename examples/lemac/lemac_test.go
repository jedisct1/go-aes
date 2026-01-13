package lemac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestLeMacBasic(t *testing.T) {
	// Test vector from reference implementation
	key := [16]byte{}     // All zeros
	nonce := [16]byte{}   // All zeros
	message := [16]byte{} // All zeros

	ctx := NewLeMacContext(key)
	tag := LeMac(ctx, message[:], nonce)

	expected := [16]byte{
		0x26, 0xfa, 0x47, 0x1b, 0x77, 0xfa, 0xcc, 0x73,
		0xec, 0x2f, 0x9b, 0x50, 0xbb, 0x1a, 0xf8, 0x64,
	}

	if !bytes.Equal(tag[:], expected[:]) {
		t.Errorf("LeMac basic test failed\nGot:      %x\nExpected: %x", tag, expected)
	}
}

func TestLeMacEmpty(t *testing.T) {
	// Test vector for empty message
	key := [16]byte{}   // All zeros
	nonce := [16]byte{} // All zeros

	ctx := NewLeMacContext(key)
	tag := LeMac(ctx, []byte{}, nonce)

	expected := [16]byte{
		0x52, 0x28, 0x2e, 0x85, 0x3c, 0x9c, 0xfe, 0xb5,
		0x53, 0x7d, 0x33, 0xfb, 0x91, 0x6a, 0x34, 0x1f,
	}

	if !bytes.Equal(tag[:], expected[:]) {
		t.Errorf("LeMac empty message test failed\nGot:      %x\nExpected: %x", tag, expected)
	}
}

func TestLeMac65Bytes(t *testing.T) {
	// Test vector for 65-byte message
	var key [16]byte
	var nonce [16]byte
	var message [65]byte

	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		nonce[i] = byte(i)
	}
	for i := 0; i < 65; i++ {
		message[i] = byte(i)
	}

	ctx := NewLeMacContext(key)
	tag := LeMac(ctx, message[:], nonce)

	expected := [16]byte{
		0xd5, 0x8d, 0xfd, 0xbe, 0x8b, 0x02, 0x24, 0xe1,
		0xd5, 0x10, 0x6a, 0xc4, 0xd7, 0x75, 0xbe, 0xef,
	}

	if !bytes.Equal(tag[:], expected[:]) {
		t.Errorf("LeMac 65-byte test failed\nGot:      %x\nExpected: %x", tag, expected)
	}
}

func TestLeMacDeterministic(t *testing.T) {
	// Verify that the same input produces the same output
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}
	message := []byte("Hello, World! This is a test message for LeMac.")

	ctx := NewLeMacContext(key)
	tag1 := LeMac(ctx, message, nonce)
	tag2 := LeMac(ctx, message, nonce)

	if !bytes.Equal(tag1[:], tag2[:]) {
		t.Errorf("LeMac is not deterministic:\nTag1: %x\nTag2: %x", tag1, tag2)
	}
}

func TestLeMacDifferentMessages(t *testing.T) {
	// Verify that different messages produce different tags
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}
	message1 := []byte("Message 1")
	message2 := []byte("Message 2")

	ctx := NewLeMacContext(key)
	tag1 := LeMac(ctx, message1, nonce)
	tag2 := LeMac(ctx, message2, nonce)

	if bytes.Equal(tag1[:], tag2[:]) {
		t.Errorf("Different messages produced the same tag: %x", tag1)
	}
}

func TestLeMacDifferentKeys(t *testing.T) {
	// Verify that different keys produce different tags
	key1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key2 := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	nonce := [16]byte{}
	message := []byte("Test message")

	ctx1 := NewLeMacContext(key1)
	ctx2 := NewLeMacContext(key2)

	tag1 := LeMac(ctx1, message, nonce)
	tag2 := LeMac(ctx2, message, nonce)

	if bytes.Equal(tag1[:], tag2[:]) {
		t.Errorf("Different keys produced the same tag: %x", tag1)
	}
}

func TestLeMacDifferentNonces(t *testing.T) {
	// Verify that different nonces produce different tags
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce1 := [16]byte{1}
	nonce2 := [16]byte{2}
	message := []byte("Test message")

	ctx := NewLeMacContext(key)
	tag1 := LeMac(ctx, message, nonce1)
	tag2 := LeMac(ctx, message, nonce2)

	if bytes.Equal(tag1[:], tag2[:]) {
		t.Errorf("Different nonces produced the same tag: %x", tag1)
	}
}

func TestLeMacVariousLengths(t *testing.T) {
	// Test various message lengths to ensure padding works correctly
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}

	ctx := NewLeMacContext(key)

	lengths := []int{0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 200}
	tags := make([][16]byte, len(lengths))

	for i, length := range lengths {
		message := make([]byte, length)
		for j := 0; j < length; j++ {
			message[j] = byte(j)
		}
		tags[i] = LeMac(ctx, message, nonce)
	}

	// Verify all tags are different
	for i := 0; i < len(tags); i++ {
		for j := i + 1; j < len(tags); j++ {
			if bytes.Equal(tags[i][:], tags[j][:]) {
				t.Errorf("Messages of length %d and %d produced the same tag: %x",
					lengths[i], lengths[j], tags[i])
			}
		}
	}
}

func BenchmarkLeMacInit(b *testing.B) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewLeMacContext(key)
	}
}

func BenchmarkLeMac64B(b *testing.B) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}
	message := make([]byte, 64)

	ctx := NewLeMacContext(key)

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LeMac(ctx, message, nonce)
	}
}

func BenchmarkLeMac256B(b *testing.B) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}
	message := make([]byte, 256)

	ctx := NewLeMacContext(key)

	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LeMac(ctx, message, nonce)
	}
}

func BenchmarkLeMac1KB(b *testing.B) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}
	message := make([]byte, 1024)

	ctx := NewLeMacContext(key)

	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LeMac(ctx, message, nonce)
	}
}

func BenchmarkLeMac8KB(b *testing.B) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [16]byte{}
	message := make([]byte, 8*1024)

	ctx := NewLeMacContext(key)

	b.SetBytes(8 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LeMac(ctx, message, nonce)
	}
}

// HMAC-SHA256 benchmarks for comparison

func BenchmarkHMACSHA256_64B(b *testing.B) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	message := make([]byte, 64)

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(message)
		_ = h.Sum(nil)
	}
}

func BenchmarkHMACSHA256_256B(b *testing.B) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	message := make([]byte, 256)

	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(message)
		_ = h.Sum(nil)
	}
}

func BenchmarkHMACSHA256_1KB(b *testing.B) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	message := make([]byte, 1024)

	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(message)
		_ = h.Sum(nil)
	}
}

func BenchmarkHMACSHA256_8KB(b *testing.B) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	message := make([]byte, 8*1024)

	b.SetBytes(8 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(message)
		_ = h.Sum(nil)
	}
}
