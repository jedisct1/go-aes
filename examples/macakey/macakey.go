// Package macakey implements KeyMacaKey, a keyed sponge PRF and MAC built on the Areion512 permutation.
//
// KeyMacaKey absorbs 64 bytes and outputs 64 bytes per permutation call. It fixes MacaKey, which has a four-query forgery. The IV is public and identifies a user or a context. It is not a nonce.
//
// KeyMacaKey: Bhaumik, Chakraborty and Dhar, "Breaking and Fixing MacaKey", ToSC 2026(1), https://eprint.iacr.org/2025/2038
//
// MacaKey: Lefevre and Marhuenda Beltrán, "MacaKey: Full-State Keyed Sponge Meets the Summation-Truncation Hybrid", https://eprint.iacr.org/2025/893
package macakey

import (
	"crypto/subtle"
	"errors"

	aes "github.com/jedisct1/go-aes"
)

const (
	// KeySize is the key size in bytes.
	KeySize = 32
	// IVSize is the IV size in bytes.
	IVSize = 32
	// BlockSize is the number of bytes absorbed or output per permutation call.
	BlockSize = 64

	rateSize     = 32
	capacitySize = 32
)

var (
	// ErrWriteAfterRead is returned by Write once output was read.
	ErrWriteAfterRead = errors.New("macakey: cannot write after reading")
	// ErrInvalidKey is returned when the key is not 32 bytes long.
	ErrInvalidKey = errors.New("macakey: key must be 32 bytes")
	// ErrInvalidIV is returned when the IV is not 32 bytes long.
	ErrInvalidIV = errors.New("macakey: IV must be 32 bytes")
)

var zeroIV [IVSize]byte

// KeyMacaKeyContext computes KeyMacaKey incrementally.
type KeyMacaKeyContext struct {
	state   aes.Areion512
	initial aes.Areion512
	key     [KeySize]byte

	buffer [BlockSize]byte
	bufLen int

	squeezing bool
	out       [BlockSize]byte
	outPos    int
}

// NewKeyMacaKeyContext creates a context with an all-zero IV.
func NewKeyMacaKeyContext(key []byte) (*KeyMacaKeyContext, error) {
	return NewKeyMacaKeyContextWithIV(key, zeroIV[:])
}

// NewKeyMacaKeyContextWithIV creates a context with the given IV.
func NewKeyMacaKeyContextWithIV(key, iv []byte) (*KeyMacaKeyContext, error) {
	ctx := &KeyMacaKeyContext{}
	if err := ctx.setup(key, iv); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (ctx *KeyMacaKeyContext) setup(key, iv []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}
	if len(iv) != IVSize {
		return ErrInvalidIV
	}
	copy(ctx.key[:], key)
	copy(ctx.initial[:], key)
	copy(ctx.initial[KeySize:], iv)
	ctx.initial.Permute()
	ctx.Reset()
	return nil
}

// Reset forgets the message and the output, and keeps the key and IV.
func (ctx *KeyMacaKeyContext) Reset() {
	ctx.state = ctx.initial
	ctx.bufLen = 0
	ctx.squeezing = false
}

// Clone returns an independent copy, for example to get several outputs from a shared message prefix.
func (ctx *KeyMacaKeyContext) Clone() *KeyMacaKeyContext {
	clone := *ctx
	return &clone
}

// Write absorbs more message data. It fails once output was read.
func (ctx *KeyMacaKeyContext) Write(data []byte) (int, error) {
	if ctx.squeezing {
		return 0, ErrWriteAfterRead
	}
	n := len(data)

	// Padding always adds a byte, so a full block is never the last block. We can absorb it right away.
	if ctx.bufLen > 0 {
		copied := copy(ctx.buffer[ctx.bufLen:], data)
		ctx.bufLen += copied
		data = data[copied:]
		if ctx.bufLen < BlockSize {
			return n, nil
		}
		ctx.absorbBlock(ctx.buffer[:])
	}
	for len(data) >= BlockSize {
		ctx.absorbBlock(data[:BlockSize])
		data = data[BlockSize:]
	}
	ctx.bufLen = copy(ctx.buffer[:], data)

	return n, nil
}

func (ctx *KeyMacaKeyContext) absorbBlock(block []byte) {
	subtle.XORBytes(ctx.state[:], ctx.state[:], block)
	ctx.state.Permute()
}

// Adding the key to the last block is the KeyMacaKey fix. Without it, a longer message could continue from a state that an earlier output revealed.
func (ctx *KeyMacaKeyContext) finalize() {
	subtle.XORBytes(ctx.state[:], ctx.state[:], ctx.buffer[:ctx.bufLen])
	ctx.state[ctx.bufLen] ^= 0x80
	subtle.XORBytes(ctx.state[BlockSize-KeySize:], ctx.state[BlockSize-KeySize:], ctx.key[:])
	ctx.permuteAndOutput()
	ctx.squeezing = true
}

// The inner half of each output block mixes the state from before and after the permutation. This lets us output the whole block without revealing the state.
func (ctx *KeyMacaKeyContext) permuteAndOutput() {
	copy(ctx.out[:capacitySize], ctx.state[rateSize:])
	ctx.state.Permute()
	subtle.XORBytes(ctx.out[:capacitySize], ctx.out[:capacitySize], ctx.state[rateSize:])
	copy(ctx.out[capacitySize:], ctx.state[:rateSize])
	ctx.outPos = 0
}

// Read fills out with the next output bytes. The first call ends the message.
func (ctx *KeyMacaKeyContext) Read(out []byte) (int, error) {
	if !ctx.squeezing {
		ctx.finalize()
	}
	n := 0
	for n < len(out) {
		if ctx.outPos == BlockSize {
			ctx.permuteAndOutput()
		}
		copied := copy(out[n:], ctx.out[ctx.outPos:])
		ctx.outPos += copied
		n += copied
	}
	return n, nil
}

// Sum returns the next outputLen bytes, or nil if outputLen is not positive. Like Read, it moves forward in the output. Call Clone first to get the same bytes again.
func (ctx *KeyMacaKeyContext) Sum(outputLen int) []byte {
	if outputLen <= 0 {
		return nil
	}
	out := make([]byte, outputLen)
	ctx.Read(out)
	return out
}

// KeyMacaKey returns outputLen bytes of output for message, with an all-zero IV.
func KeyMacaKey(key, message []byte, outputLen int) ([]byte, error) {
	return KeyMacaKeyWithIV(key, zeroIV[:], message, outputLen)
}

// KeyMacaKeyWithIV returns outputLen bytes of output for message.
func KeyMacaKeyWithIV(key, iv, message []byte, outputLen int) ([]byte, error) {
	var ctx KeyMacaKeyContext
	if err := ctx.setup(key, iv); err != nil {
		return nil, err
	}
	ctx.Write(message)
	return ctx.Sum(outputLen), nil
}
