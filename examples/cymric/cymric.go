// Package cymric implements Cymric1 and Cymric2 lightweight authenticated encryption.
//
// Cymric is an AEAD scheme using two independent AES-128 keys, designed for
// short messages with minimal overhead. It provides 128-bit authentication tags.
//
// Two variants are provided:
//   - Cymric1: |msg| + |nonce| <= 16, |nonce| + |ad| <= 15
//   - Cymric2: |msg| <= 16, |nonce| + |ad| <= 15
package cymric

import (
	"crypto/subtle"
	"errors"

	aes "github.com/jedisct1/go-aes"
)

// Constants
const (
	KeyBytes      = 32 // Two AES-128 keys (16 + 16)
	NonceMaxBytes = 12
	BlockBytes    = 16
	TagBytes      = 16
)

// Errors
var (
	ErrInvalidInputLength   = errors.New("cymric: invalid input length")
	ErrAuthenticationFailed = errors.New("cymric: authentication failed")
)

// Context holds the round keys for Cymric authenticated encryption.
// It uses two independent AES-128 key schedules with pre-computed round key arrays.
type Context struct {
	key0_1 aes.Block        // Initial key for ks1
	key0_2 aes.Block        // Initial key for ks2
	keys1  aes.RoundKeys10  // Pre-computed round keys 1-10 for ks1
	keys2  aes.RoundKeys10  // Pre-computed round keys 1-10 for ks2
}

// NewContext creates a new Cymric context from a 32-byte key.
// The key is split into two 16-byte AES-128 keys.
func NewContext(key *[KeyBytes]byte) *Context {
	ks1, _ := aes.NewKeySchedule(key[:16])
	ks2, _ := aes.NewKeySchedule(key[16:])

	ctx := &Context{}
	ctx.key0_1 = *ks1.GetRoundKey(0)
	ctx.key0_2 = *ks2.GetRoundKey(0)

	for i := range 10 {
		ctx.keys1[i] = *ks1.GetRoundKey(i + 1)
		ctx.keys2[i] = *ks2.GetRoundKey(i + 1)
	}

	return ctx
}

// encrypt performs AES-128 encryption using pre-computed round keys.
func encrypt(block *aes.Block, key0 *aes.Block, keys *aes.RoundKeys10) {
	aes.AddRoundKey(block, key0)
	aes.Rounds10WithFinalHW(block, keys)
}

// Cymric1Encrypt encrypts a message using the Cymric1 authenticated encryption scheme.
//
// Constraints:
//   - len(msg) + len(nonce) <= 16
//   - len(nonce) + len(ad) <= 15
//
// Parameters:
//   - out: output buffer for ciphertext (must be at least len(msg) bytes)
//   - tag: output buffer for authentication tag (16 bytes)
//   - msg: plaintext message to encrypt
//   - ad: associated data (authenticated but not encrypted)
//   - nonce: unique nonce (up to 12 bytes)
func (ctx *Context) Cymric1Encrypt(out []byte, tag *[TagBytes]byte, msg, ad, nonce []byte) error {
	if len(msg)+len(nonce) > BlockBytes {
		return ErrInvalidInputLength
	}
	if len(nonce)+len(ad) > BlockBytes-1 {
		return ErrInvalidInputLength
	}

	var y0, y1 aes.Block
	var block aes.Block

	// Determine if |N|+|M| == n (full block)
	var b byte
	if len(msg)+len(nonce) == BlockBytes {
		b = 0x80
	}

	// Prepare first block: Y0 <- E_K1(padn(N||A||b0))
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(ad)], ad)
	block[len(nonce)+len(ad)] = b | 0x20

	y0 = block
	encrypt(&y0, &ctx.key0_1, &ctx.keys1)

	// Prepare second block: Y1 <- E_K1(padn(N||A||b1))
	block[len(nonce)+len(ad)] = b | 0x60

	y1 = block
	encrypt(&y1, &ctx.key0_1, &ctx.keys1)

	// C <- M ^ Y0 ^ Y1
	var mask aes.Block
	aes.XorBlock(&mask, &y0, &y1)
	for i := range len(msg) {
		out[i] = msg[i] ^ mask[i]
	}

	// T <- E_K2(N||M||pad ^ Y0)
	block = aes.Block{} // zero
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(msg)], msg)
	if len(nonce)+len(msg) != BlockBytes {
		block[len(nonce)+len(msg)] = 0x80
	}

	aes.XorBlock(&block, &block, &y0)
	encrypt(&block, &ctx.key0_2, &ctx.keys2)

	copy(tag[:], block[:])
	return nil
}

// Cymric1Decrypt decrypts a message using the Cymric1 authenticated encryption scheme.
//
// Constraints:
//   - len(cipher) + len(nonce) <= 16
//   - len(nonce) + len(ad) <= 15
//
// Parameters:
//   - out: output buffer for plaintext (must be at least len(cipher) bytes)
//   - cipher: ciphertext to decrypt
//   - tag: authentication tag to verify (16 bytes)
//   - ad: associated data
//   - nonce: nonce used during encryption
//
// Returns ErrAuthenticationFailed if the tag verification fails.
// On failure, the output buffer is zeroed.
func (ctx *Context) Cymric1Decrypt(out []byte, cipher []byte, tag *[TagBytes]byte, ad, nonce []byte) error {
	if len(cipher)+len(nonce) > BlockBytes {
		return ErrInvalidInputLength
	}
	if len(nonce)+len(ad) > BlockBytes-1 {
		return ErrInvalidInputLength
	}

	var y0, y1 aes.Block
	var block aes.Block

	// Determine if |N|+|C| == n (full block)
	var b byte
	if len(cipher)+len(nonce) == BlockBytes {
		b = 0x80
	}

	// Prepare first block: Y0 <- E_K1(padn(N||A||b0))
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(ad)], ad)
	block[len(nonce)+len(ad)] = b | 0x20

	y0 = block
	encrypt(&y0, &ctx.key0_1, &ctx.keys1)

	// Prepare second block: Y1 <- E_K1(padn(N||A||b1))
	block[len(nonce)+len(ad)] = b | 0x60

	y1 = block
	encrypt(&y1, &ctx.key0_1, &ctx.keys1)

	// M <- C ^ Y0 ^ Y1
	var mask aes.Block
	aes.XorBlock(&mask, &y0, &y1)
	for i := range len(cipher) {
		out[i] = cipher[i] ^ mask[i]
	}

	// Compute expected tag: T <- E_K2(N||M||pad ^ Y0)
	block = aes.Block{} // zero
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(cipher)], out[:len(cipher)])
	if len(nonce)+len(cipher) != BlockBytes {
		block[len(nonce)+len(cipher)] = 0x80
	}

	aes.XorBlock(&block, &block, &y0)
	encrypt(&block, &ctx.key0_2, &ctx.keys2)

	if subtle.ConstantTimeCompare(block[:], tag[:]) != 1 {
		// Zero output on failure
		for i := range len(cipher) {
			out[i] = 0
		}
		return ErrAuthenticationFailed
	}

	return nil
}

// Cymric2Encrypt encrypts a message using the Cymric2 authenticated encryption scheme.
//
// Constraints:
//   - len(msg) <= 16
//   - len(nonce) + len(ad) <= 15
//
// Parameters:
//   - out: output buffer for ciphertext (must be at least len(msg) bytes)
//   - tag: output buffer for authentication tag (16 bytes)
//   - msg: plaintext message to encrypt
//   - ad: associated data (authenticated but not encrypted)
//   - nonce: unique nonce (up to 12 bytes)
func (ctx *Context) Cymric2Encrypt(out []byte, tag *[TagBytes]byte, msg, ad, nonce []byte) error {
	if len(msg) > BlockBytes {
		return ErrInvalidInputLength
	}
	if len(nonce)+len(ad) > BlockBytes-1 {
		return ErrInvalidInputLength
	}

	var y0, y1 aes.Block
	var block aes.Block

	// Determine if |M| == n (full block)
	var b byte
	if len(msg) == BlockBytes {
		b = 0x80
	}

	// Prepare first block: Y0 <- E_K1(padn(N||A||b0))
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(ad)], ad)
	block[len(nonce)+len(ad)] = b | 0x20

	y0 = block
	encrypt(&y0, &ctx.key0_1, &ctx.keys1)

	// Prepare second block: Y1 <- E_K1(padn(N||A||b1))
	block[len(nonce)+len(ad)] = b | 0x60

	y1 = block
	encrypt(&y1, &ctx.key0_1, &ctx.keys1)

	// C <- M ^ Y0 ^ Y1
	var mask aes.Block
	aes.XorBlock(&mask, &y0, &y1)
	for i := range len(msg) {
		out[i] = msg[i] ^ mask[i]
	}

	// T <- E_K2(pad(M) ^ Y0)
	block = aes.Block{} // zero
	copy(block[:len(msg)], msg)
	if len(msg) != BlockBytes {
		block[len(msg)] = 0x80
	}

	aes.XorBlock(&block, &block, &y0)
	encrypt(&block, &ctx.key0_2, &ctx.keys2)

	copy(tag[:], block[:])
	return nil
}

// Cymric2Decrypt decrypts a message using the Cymric2 authenticated encryption scheme.
//
// Constraints:
//   - len(cipher) <= 16
//   - len(nonce) + len(ad) <= 15
//
// Parameters:
//   - out: output buffer for plaintext (must be at least len(cipher) bytes)
//   - cipher: ciphertext to decrypt
//   - tag: authentication tag to verify (16 bytes)
//   - ad: associated data
//   - nonce: nonce used during encryption
//
// Returns ErrAuthenticationFailed if the tag verification fails.
// On failure, the output buffer is zeroed.
func (ctx *Context) Cymric2Decrypt(out []byte, cipher []byte, tag *[TagBytes]byte, ad, nonce []byte) error {
	if len(cipher) > BlockBytes {
		return ErrInvalidInputLength
	}
	if len(nonce)+len(ad) > BlockBytes-1 {
		return ErrInvalidInputLength
	}

	var y0, y1 aes.Block
	var block aes.Block

	// Determine if |C| == n (full block)
	var b byte
	if len(cipher) == BlockBytes {
		b = 0x80
	}

	// Prepare first block: Y0 <- E_K1(padn(N||A||b0))
	copy(block[:len(nonce)], nonce)
	copy(block[len(nonce):len(nonce)+len(ad)], ad)
	block[len(nonce)+len(ad)] = b | 0x20

	y0 = block
	encrypt(&y0, &ctx.key0_1, &ctx.keys1)

	// Prepare second block: Y1 <- E_K1(padn(N||A||b1))
	block[len(nonce)+len(ad)] = b | 0x60

	y1 = block
	encrypt(&y1, &ctx.key0_1, &ctx.keys1)

	// M <- C ^ Y0 ^ Y1
	var mask aes.Block
	aes.XorBlock(&mask, &y0, &y1)
	for i := range len(cipher) {
		out[i] = cipher[i] ^ mask[i]
	}

	// Compute expected tag: T <- E_K2(pad(M) ^ Y0)
	block = aes.Block{} // zero
	copy(block[:len(cipher)], out[:len(cipher)])
	if len(cipher) != BlockBytes {
		block[len(cipher)] = 0x80
	}

	aes.XorBlock(&block, &block, &y0)
	encrypt(&block, &ctx.key0_2, &ctx.keys2)

	if subtle.ConstantTimeCompare(block[:], tag[:]) != 1 {
		// Zero output on failure
		for i := range len(cipher) {
			out[i] = 0
		}
		return ErrAuthenticationFailed
	}

	return nil
}
