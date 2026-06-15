// Package butterrng demonstrates a fast-key-erasure RNG built from ButterKnife.
//
// After each refill the retired state, the expanded subtweakeys, and the
// consumed output bytes are all wiped, so a later memory compromise cannot
// reconstruct earlier output. The RNG keeps a single ButterKnife context and
// re-keys it in place, so a refill allocates nothing.
//
// This is an example construction, not a production RNG. It does not handle
// process forks, thread safety, or reseeding policy, and Go gives no guarantee
// that wiping a stack-local leaves no copy behind (no explicit_bzero), so the
// transient key schedule built during a refill is only best-effort erased.
package butterrng

import (
	"errors"
	"io"
	"runtime"

	aes "github.com/jedisct1/go-aes"
)

const (
	// SeedSize is the size of the initial RNG seed in bytes.
	SeedSize = 32
	// CallsPerRefill is the number of ButterKnife inputs evaluated per refill.
	CallsPerRefill = 8
	// BufferSize is the number of random bytes served from each refill.
	BufferSize = (CallsPerRefill*8 - 2) * 16
)

var ErrInvalidSeedSize = errors.New("butterrng: seed must be 32 bytes")

// RNG is a deterministic fast-key-erasure random byte generator.
//
// Each refill evaluates ButterKnife under the current 256-bit state key on
// inputs 0..CallsPerRefill-1. The first two branches of input 0 become the next
// state key; every other branch is buffered as random output. Bytes copied from
// the buffer are cleared immediately.
type RNG struct {
	key aes.Tweakey256
	ctx aes.ButterKnifeContextHW

	buffer [BufferSize]byte
	off    int
	n      int
}

// New creates an RNG from a 32-byte seed.
func New(seed []byte) (*RNG, error) {
	if len(seed) != SeedSize {
		return nil, ErrInvalidSeedSize
	}
	rng := &RNG{}
	copy(rng.key[:], seed)
	return rng, nil
}

// NewFromReader creates an RNG by reading a 32-byte seed from r.
func NewFromReader(r io.Reader) (*RNG, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	rng, err := New(seed[:])
	zero(seed[:])
	return rng, err
}

// Read fills out with random bytes and always returns len(out), nil.
func (rng *RNG) Read(out []byte) (int, error) {
	rng.Fill(out)
	return len(out), nil
}

// Fill writes random bytes into out.
func (rng *RNG) Fill(out []byte) {
	for len(out) > 0 {
		if rng.off == rng.n {
			rng.refill()
		}

		copied := copy(out, rng.buffer[rng.off:rng.n])
		zero(rng.buffer[rng.off : rng.off+copied])
		rng.off += copied
		out = out[copied:]

		if rng.off == rng.n {
			rng.off = 0
			rng.n = 0
		}
	}
}

func (rng *RNG) refill() {
	var oldKey aes.Tweakey256
	copy(oldKey[:], rng.key[:])

	rng.ctx.Reset(&oldKey)

	rng.off = 0
	rng.n = 0

	var out aes.ButterKnifeOutput
	for inputNum := 0; inputNum < CallsPerRefill; inputNum++ {
		var input aes.Block
		input[15] = byte(inputNum)

		rng.ctx.EvalHWInto(&input, &out)
		if inputNum == 0 {
			copy(rng.key[0:16], out[0][:])
			copy(rng.key[16:32], out[1][:])
			for branch := 2; branch < 8; branch++ {
				rng.appendBranch(&out[branch])
			}
		} else {
			for branch := 0; branch < 8; branch++ {
				rng.appendBranch(&out[branch])
			}
		}
	}

	for branch := range out {
		zero(out[branch][:])
	}
	rng.ctx.Zero()
	zero(oldKey[:])
}

func (rng *RNG) appendBranch(branch *aes.Block) {
	copy(rng.buffer[rng.n:rng.n+16], branch[:])
	rng.n += 16
}

func zero(buf []byte) {
	clear(buf)
	runtime.KeepAlive(buf)
}
