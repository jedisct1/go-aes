package uedt

import (
	"encoding/binary"

	aes "github.com/jedisct1/go-aes"
)

// iota128 is the fixed non-zero constant ι used to break symmetry between the
// upper and lower BC calls of a chunk. Any non-zero value works; we pick the
// canonical one with a single bit set in the LSB.
var iota128 = aes.Block{15: 1}

// fk derives the public, partially-fixed key used by the i-th block-cipher
// pair when encrypting under nonce N:
//
//	fk(N, i) = [floor((i-1)/omega)]_{n/4} || N
//
// The chunk size omega is fixed to n = 128, so a fresh AES-128 key schedule
// is needed only once every omega blocks.
func fk(N []byte, i int) aes.Block {
	var key aes.Block
	chunk := uint32((i - 1) / omega)
	binary.BigEndian.PutUint32(key[0:4], chunk)
	copy(key[4:16], N)
	return key
}

// chunkKey caches the AES round keys for the current omega-sized chunk so the
// per-block hot path can call Rounds10WithFinalHW directly without
// re-extracting round keys on every invocation.
type chunkKey struct {
	N    []byte
	last int
	rk0  aes.Block
	rk   aes.RoundKeys10
}

func newChunkKey(N []byte) chunkKey { return chunkKey{N: N, last: -1} }

// at refreshes the cached round keys whenever block index i crosses a chunk
// boundary, then returns pointers to the initial AddRoundKey value and the
// remaining 10 round keys.
func (c *chunkKey) at(i int) (*aes.Block, *aes.RoundKeys10) {
	chunkIdx := (i - 1) / omega
	if chunkIdx != c.last {
		key := fk(c.N, i)
		ks, _ := aes.NewKeySchedule(key[:])
		c.rk0 = *ks.GetRoundKey(0)
		for r := range 10 {
			c.rk[r] = *ks.GetRoundKey(r + 1)
		}
		c.last = chunkIdx
	}
	return &c.rk0, &c.rk
}

// aesEnc applies AES-128 in place using pre-extracted round keys.
func aesEnc(b *aes.Block, rk0 *aes.Block, rk *aes.RoundKeys10) {
	aes.AddRoundKey(b, rk0)
	aes.Rounds10WithFinalHW(b, rk)
}

// psvdmCrypt runs the PSVDM stream over data. Since PSVDM XORs a deterministic
// keystream into the message, the same routine performs both encryption and
// decryption.
//
// The last (possibly partial) block follows Fig. 6 (Left) line 11: the
// ciphertext bytes are XORed with the *rightmost* |M[ell]| bytes of z_ell.
func psvdmCrypt(N []byte, S0 *aes.Block, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	nBlocks := (len(data) + blockSize - 1) / blockSize

	state := *S0
	ck := newChunkKey(N)

	for i := 1; i < nBlocks; i++ {
		rk0, rk := ck.at(i)

		enc := state
		aesEnc(&enc, rk0, rk)
		var nextState aes.Block
		aes.XorBlock(&nextState, &enc, &state)

		var sbar aes.Block
		aes.XorBlock(&sbar, &state, &iota128)
		z := sbar
		aesEnc(&z, rk0, rk)
		aes.XorBlock(&z, &z, &sbar)

		off := (i - 1) * blockSize
		for j := 0; j < blockSize; j++ {
			out[off+j] = data[off+j] ^ z[j]
		}
		state = nextState
	}

	rk0, rk := ck.at(nBlocks)
	var sbar aes.Block
	aes.XorBlock(&sbar, &state, &iota128)
	z := sbar
	aesEnc(&z, rk0, rk)
	aes.XorBlock(&z, &z, &sbar)

	off := (nBlocks - 1) * blockSize
	rem := len(data) - off
	base := 0
	if rem < blockSize {
		base = blockSize - rem
	}
	for j := 0; j < rem; j++ {
		out[off+j] = data[off+j] ^ z[base+j]
	}
	return out
}

// psvmxCrypt runs the PSVMX stream. The mixing layer D is the 2x2 GF(2^n)
// matrix [[2, 1], [1, 1]], applied as
//
//	(S_i, z_i) = D(y_{i,1}, y_{i,2}) = (2*y_{i,1} XOR y_{i,2}, y_{i,1} XOR y_{i,2})
//
// where the doubling is the same theta = 2 multiplication used by MJH.
//
// Unlike PSVDM, PSVMX has no input feed-forward: the state evolves purely
// through D. For the (potentially partial) last block, we XOR with the
// leftmost bytes of z_i; Fig. 6 (Right) does not specify a special truncation
// rule, so the natural left-aligned reading is used.
func psvmxCrypt(N []byte, S0 *aes.Block, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	nBlocks := (len(data) + blockSize - 1) / blockSize

	state := *S0
	ck := newChunkKey(N)

	for i := 1; i <= nBlocks; i++ {
		rk0, rk := ck.at(i)

		y1 := state
		aesEnc(&y1, rk0, rk)

		y2 := state
		aes.XorBlock(&y2, &y2, &iota128)
		aesEnc(&y2, rk0, rk)

		nextState := y1
		gfDouble(&nextState)
		aes.XorBlock(&nextState, &nextState, &y2)
		var z aes.Block
		aes.XorBlock(&z, &y1, &y2)

		off := (i - 1) * blockSize
		rem := len(data) - off
		take := blockSize
		if rem < blockSize {
			take = rem
		}
		for j := 0; j < take; j++ {
			out[off+j] = data[off+j] ^ z[j]
		}

		state = nextState
	}
	return out
}
