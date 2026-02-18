package spongef

import (
	"errors"

	aes "github.com/jedisct1/go-aes"
)

const (
	// StateSize is the Areion512 state size in bytes (b = 512 bits).
	StateSize = 64
	// RateSize is the outer sponge size in bytes (r = 256 bits).
	RateSize = 32
	// CapacitySize is the inner sponge size in bytes (c = 256 bits).
	CapacitySize = 32
	// SqueezeSize is the per-permutation output size in bytes (r' = 256 bits).
	SqueezeSize = 32
	// MinOutputSize is the fixed hash output size in bytes (h = 256 bits).
	MinOutputSize = 32
	// IVSize is the Sponge-F IV size in bytes.
	IVSize = CapacitySize
)

// /x31 = 0^(c-1) || 1, injected in the last absorbed block.
const finalDomainByte = 0x01

var (
	// DefaultIV is the public IV used by the default construction.
	DefaultIV [IVSize]byte

	// ErrWriteAfterRead is returned when absorbing after squeezing started.
	ErrWriteAfterRead = errors.New("spongef: cannot write after reading")
	// ErrInvalidIV is returned when the IV size is incorrect.
	ErrInvalidIV = errors.New("spongef: IV must be 32 bytes")
	// ErrOutputTooShort is returned when requested output is shorter than h.
	ErrOutputTooShort = errors.New("spongef: output length must be at least 32 bytes")
)

// SpongeFContext is an incremental Sponge-F state using Areion512.
type SpongeFContext struct {
	state aes.Areion512

	buffer [RateSize]byte
	bufLen int

	squeezing bool
	outBuffer []byte
	iv        [IVSize]byte
}

// NewSpongeFContext creates a new context with the default IV.
func NewSpongeFContext() *SpongeFContext {
	ctx := &SpongeFContext{iv: DefaultIV}
	ctx.initialize()
	return ctx
}

// NewSpongeFContextWithIV creates a new context with a custom IV.
func NewSpongeFContextWithIV(iv []byte) (*SpongeFContext, error) {
	if len(iv) != IVSize {
		return nil, ErrInvalidIV
	}
	ctx := &SpongeFContext{}
	copy(ctx.iv[:], iv)
	ctx.initialize()
	return ctx, nil
}

func (ctx *SpongeFContext) initialize() {
	clear(ctx.state[:RateSize])
	copy(ctx.state[RateSize:], ctx.iv[:])

	ctx.bufLen = 0
	ctx.squeezing = false
	ctx.outBuffer = nil
}

// Reset resets the context to its initial state.
func (ctx *SpongeFContext) Reset() {
	ctx.initialize()
}

// Clone returns a deep copy of the context.
func (ctx *SpongeFContext) Clone() *SpongeFContext {
	clone := &SpongeFContext{
		state:     ctx.state,
		buffer:    ctx.buffer,
		bufLen:    ctx.bufLen,
		squeezing: ctx.squeezing,
		iv:        ctx.iv,
	}
	if ctx.outBuffer != nil {
		clone.outBuffer = make([]byte, len(ctx.outBuffer))
		copy(clone.outBuffer, ctx.outBuffer)
	}
	return clone
}

// Write absorbs message bytes.
func (ctx *SpongeFContext) Write(data []byte) (int, error) {
	if ctx.squeezing {
		return 0, ErrWriteAfterRead
	}

	total := len(data)
	offset := 0

	if ctx.bufLen > 0 {
		n := copy(ctx.buffer[ctx.bufLen:], data)
		ctx.bufLen += n
		offset += n

		if ctx.bufLen == RateSize {
			ctx.absorbBlock(ctx.buffer[:], false)
			ctx.bufLen = 0
		}
	}

	for offset+RateSize <= total {
		ctx.absorbBlock(data[offset:offset+RateSize], false)
		offset += RateSize
	}

	if offset < total {
		ctx.bufLen = copy(ctx.buffer[:], data[offset:])
	}

	return total, nil
}

func (ctx *SpongeFContext) absorbBlock(block []byte, isFinal bool) {
	var s [CapacitySize]byte
	copy(s[:], ctx.state[RateSize:])

	for i := range RateSize {
		ctx.state[i] ^= block[i]
	}
	if isFinal {
		ctx.state[StateSize-1] ^= finalDomainByte
	}

	ctx.state.Permute()

	for i := range CapacitySize {
		ctx.state[RateSize+i] ^= s[i]
	}
}

func (ctx *SpongeFContext) finalize() {
	ctx.buffer[ctx.bufLen] = 0x80
	ctx.bufLen++
	for i := ctx.bufLen; i < RateSize; i++ {
		ctx.buffer[i] = 0
	}
	ctx.absorbBlock(ctx.buffer[:], true)
	ctx.bufLen = 0
	ctx.squeezing = true
}

func (ctx *SpongeFContext) squeezeBlock() []byte {
	out := make([]byte, SqueezeSize)
	copy(out, ctx.state[RateSize:])

	var s [SqueezeSize]byte
	copy(s[:], ctx.state[StateSize-SqueezeSize:])

	ctx.state.Permute()

	for i := range SqueezeSize {
		ctx.state[StateSize-SqueezeSize+i] ^= s[i]
	}

	return out
}

// Read squeezes output bytes from the sponge stream.
func (ctx *SpongeFContext) Read(out []byte) (int, error) {
	if !ctx.squeezing {
		ctx.finalize()
	}

	n := 0
	for n < len(out) {
		if len(ctx.outBuffer) > 0 {
			copied := copy(out[n:], ctx.outBuffer)
			n += copied
			ctx.outBuffer = ctx.outBuffer[copied:]
			continue
		}

		ctx.outBuffer = ctx.squeezeBlock()
	}

	return n, nil
}

// Sum finalizes (if needed) and returns outputLen bytes.
func (ctx *SpongeFContext) Sum(outputLen int) []byte {
	if outputLen <= 0 {
		return nil
	}
	out := make([]byte, outputLen)
	_, _ = ctx.Read(out)
	return out
}

// SpongeF computes Sponge-F with the default IV.
func SpongeF(message []byte, outputLen int) ([]byte, error) {
	return SpongeFWithIV(DefaultIV[:], message, outputLen)
}

// SpongeFWithIV computes Sponge-F with an explicit IV.
func SpongeFWithIV(iv, message []byte, outputLen int) ([]byte, error) {
	if outputLen < MinOutputSize {
		return nil, ErrOutputTooShort
	}
	ctx, err := NewSpongeFContextWithIV(iv)
	if err != nil {
		return nil, err
	}
	_, err = ctx.Write(message)
	if err != nil {
		return nil, err
	}
	return ctx.Sum(outputLen), nil
}

// Hash computes the 256-bit full-inner-squeezing variant (h = c = 256).
func Hash(message []byte) [MinOutputSize]byte {
	ctx := NewSpongeFContext()
	_, _ = ctx.Write(message)
	sum := ctx.Sum(MinOutputSize)
	var out [MinOutputSize]byte
	copy(out[:], sum)
	return out
}
