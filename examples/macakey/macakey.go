package macakey

import (
	"errors"

	aes "github.com/jedisct1/go-aes"
)

// Size constants
const (
	KeySize    = 32 // 256-bit key
	IVSize     = 32 // 256-bit IV
	StateSize  = 64 // 512-bit state
	AbsorbSize = 64 // Full-state 512-bit absorption
	RateSize   = 32 // 256-bit rate (outer part for squeeze)
	CapSize    = 32 // 256-bit capacity (inner part for squeeze)
)

// Domain separation via NCP (Non-Cryptographic Permutation).
// Instead of reserving bits/bytes, we XOR a constant into the capacity
// before squeeze permutations. This satisfies Constraint 1 from the
// ToSC 2025 paper: π^p(x) ≠ π^f(x) and x ≠ π^f(x) for any x.
// Absorb uses identity NCP (no change), squeeze XORs this constant.
const squeezeDomainByte = 0x01

// ErrWriteAfterRead is returned when Write is called after Read/Sum.
var ErrWriteAfterRead = errors.New("macakey: cannot write after reading")

// MacakeyContext holds state for incremental MacaKey operation.
type MacakeyContext struct {
	state     aes.Areion512    // 512-bit state
	yr        [CapSize]byte    // Previous inner part for summation-truncation
	buffer    [AbsorbSize]byte // Partial block buffer for absorption
	bufLen    int              // Bytes in buffer
	squeezing bool             // True once Read/Sum called
	key       [KeySize]byte    // Stored for Reset
	iv        [IVSize]byte     // Stored for Reset
	outBuffer []byte           // Buffered squeeze output not yet returned
}

// NewMacakeyContext creates a new MacaKey context with the given key.
// Key must be exactly 32 bytes. IV is set to all zeros.
func NewMacakeyContext(key []byte) (*MacakeyContext, error) {
	return NewMacakeyContextWithIV(key, make([]byte, IVSize))
}

// NewMacakeyContextWithIV creates a new MacaKey context with explicit key and IV.
// Both key and IV must be exactly 32 bytes.
func NewMacakeyContextWithIV(key, iv []byte) (*MacakeyContext, error) {
	if len(key) != KeySize {
		return nil, errors.New("macakey: key must be 32 bytes")
	}
	if len(iv) != IVSize {
		return nil, errors.New("macakey: IV must be 32 bytes")
	}

	ctx := &MacakeyContext{}
	copy(ctx.key[:], key)
	copy(ctx.iv[:], iv)
	ctx.initialize()
	return ctx, nil
}

// initialize sets up the initial state from key and IV.
func (ctx *MacakeyContext) initialize() {
	// S = K || IV (full 64 bytes)
	copy(ctx.state[0:KeySize], ctx.key[:])
	copy(ctx.state[KeySize:StateSize], ctx.iv[:])

	// Initial permutation
	ctx.state.Permute()

	// Reset other state
	ctx.bufLen = 0
	ctx.squeezing = false
	ctx.outBuffer = nil
	clear(ctx.yr[:])
}

// Reset clears the context for reuse with the same key/IV.
func (ctx *MacakeyContext) Reset() {
	ctx.initialize()
}

// Write absorbs message data into the sponge.
// Returns error if squeezing has already started.
func (ctx *MacakeyContext) Write(data []byte) (int, error) {
	if ctx.squeezing {
		return 0, ErrWriteAfterRead
	}

	total := len(data)
	offset := 0

	// Fill partial buffer first
	if ctx.bufLen > 0 {
		n := copy(ctx.buffer[ctx.bufLen:], data)
		ctx.bufLen += n
		offset += n

		if ctx.bufLen == AbsorbSize {
			ctx.absorbBlock(ctx.buffer[:])
			ctx.bufLen = 0
		}
	}

	// Process full blocks directly from input (no copy)
	for offset+AbsorbSize <= total {
		ctx.absorbBlock(data[offset : offset+AbsorbSize])
		offset += AbsorbSize
	}

	// Buffer remainder
	if offset < total {
		ctx.bufLen = copy(ctx.buffer[:], data[offset:])
	}

	return total, nil
}

// absorbBlock processes one 64-byte block (full-state absorption).
// Uses identity NCP for absorb phase (no domain transformation).
func (ctx *MacakeyContext) absorbBlock(block []byte) {
	// YR = inner_c(S) - capture inner BEFORE XOR and permutation
	copy(ctx.yr[:], ctx.state[RateSize:StateSize])

	// S = S ⊕ block (full 64-byte XOR)
	for i := range AbsorbSize {
		ctx.state[i] ^= block[i]
	}

	// Absorb uses identity NCP (no transformation)
	ctx.state.Permute()
}

// finalize pads remaining data and transitions to squeeze phase.
func (ctx *MacakeyContext) finalize() {
	// Apply 10* padding to fill current block
	// Append 0x80, then zeros to fill AbsorbSize
	ctx.buffer[ctx.bufLen] = 0x80
	ctx.bufLen++
	for i := ctx.bufLen; i < AbsorbSize; i++ {
		ctx.buffer[i] = 0
	}
	ctx.absorbBlock(ctx.buffer[:])
	ctx.bufLen = 0

	ctx.squeezing = true
}

// squeezeBlock extracts one block of output (64 bytes: 32 from ZL + 32 from ZR).
func (ctx *MacakeyContext) squeezeBlock() []byte {
	out := make([]byte, StateSize)

	// ZL = outer_r(S) - first 32 bytes
	copy(out[0:RateSize], ctx.state[0:RateSize])

	// ZR = inner_c(S) ⊕ YR - XOR current inner with previous
	for i := range CapSize {
		out[RateSize+i] = ctx.state[RateSize+i] ^ ctx.yr[i]
	}

	// Update YR for next iteration
	copy(ctx.yr[:], ctx.state[RateSize:StateSize])

	// Apply squeeze NCP: XOR constant into capacity before permutation.
	// This ensures squeeze permutation inputs differ from absorb inputs.
	ctx.state[StateSize-1] ^= squeezeDomainByte

	// Permute for next squeeze
	ctx.state.Permute()

	return out
}

// Read extracts output bytes from the sponge.
// First call finalizes absorption and transitions to squeezing.
// Subsequent calls to Write will return an error.
// Each call advances the output stream.
func (ctx *MacakeyContext) Read(out []byte) (int, error) {
	if !ctx.squeezing {
		ctx.finalize()
	}

	n := 0
	for n < len(out) {
		// Use buffered output first
		if len(ctx.outBuffer) > 0 {
			copied := copy(out[n:], ctx.outBuffer)
			n += copied
			ctx.outBuffer = ctx.outBuffer[copied:]
			continue
		}

		// Squeeze a new block
		ctx.outBuffer = ctx.squeezeBlock()
	}

	return n, nil
}

// Sum finalizes and returns outputLen bytes.
// WARNING: Sum advances the stream - it is NOT idempotent.
// Calling Sum(32) twice returns different bytes (0-31, then 32-63).
// Use Clone() before Sum() for repeatable hash-like behavior.
// Returns nil if outputLen is negative.
func (ctx *MacakeyContext) Sum(outputLen int) []byte {
	if outputLen <= 0 {
		return nil
	}
	out := make([]byte, outputLen)
	ctx.Read(out)
	return out
}

// Clone returns a deep copy of the context.
// Use this to snapshot state before Sum/Read for repeatable outputs
// or multiple derivations from the same absorption point.
func (ctx *MacakeyContext) Clone() *MacakeyContext {
	clone := &MacakeyContext{
		state:     ctx.state,
		yr:        ctx.yr,
		buffer:    ctx.buffer,
		bufLen:    ctx.bufLen,
		squeezing: ctx.squeezing,
		key:       ctx.key,
		iv:        ctx.iv,
	}
	if ctx.outBuffer != nil {
		clone.outBuffer = make([]byte, len(ctx.outBuffer))
		copy(clone.outBuffer, ctx.outBuffer)
	}
	return clone
}

// Macakey computes a MAC/PRF with variable output length.
// Key must be 32 bytes. Returns outputLen bytes of PRF output.
// Returns nil output if outputLen is not positive.
func Macakey(key, message []byte, outputLen int) ([]byte, error) {
	ctx, err := NewMacakeyContext(key)
	if err != nil {
		return nil, err
	}
	ctx.Write(message)
	return ctx.Sum(outputLen), nil
}

// MacakeyWithIV computes a MAC/PRF with explicit IV.
// Key and IV must each be 32 bytes. Returns outputLen bytes of PRF output.
// Returns nil output if outputLen is not positive.
func MacakeyWithIV(key, iv, message []byte, outputLen int) ([]byte, error) {
	ctx, err := NewMacakeyContextWithIV(key, iv)
	if err != nil {
		return nil, err
	}
	ctx.Write(message)
	return ctx.Sum(outputLen), nil
}
