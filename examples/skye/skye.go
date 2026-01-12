package skye

import (
	"errors"
	"fmt"

	aes "github.com/jedisct1/go-aes"
)

// Skye KDF from https://eprint.iacr.org/2024/781
// Uses DExtLsb extraction + FExp expansion with ButterKnife.

// SkyeInfo is the 256-bit context information (Signal's "info" string).
type SkyeInfo [32]byte

// DExtLsb extracts a 128-bit key from 3 or 4 DH samples (X3DH outputs).
// Uses msb_248 (first 31 bytes) of each sample.
func DExtLsb(samples [][]byte) (*aes.Block, error) {
	v := len(samples)
	if v < 3 || v > 4 {
		return nil, errors.New("DExtLsb requires 3 or 4 samples")
	}

	for i, s := range samples {
		if len(s) < 31 {
			return nil, fmt.Errorf("sample %d too short: need at least 31 bytes, got %d", i, len(s))
		}
	}

	var result aes.Block
	const k = 128

	if v == 3 {
		// α1 = ⌈k/2⌉ = 64, α2 = k - α1 = 64
		// Both are byte-aligned, so we can use simple byte operations
		const α1 = 64
		const α2 = 64

		// XOR msb_248 of samples[0] and samples[1], take lsb_64
		// lsb_64 of 248 bits = last 8 bytes of 31 bytes = bytes[23:31]
		for j := 0; j < 8; j++ {
			result[j] = samples[0][23+j] ^ samples[1][23+j]
		}

		// XOR msb_248 of samples[1] and samples[2], take lsb_64
		for j := 0; j < 8; j++ {
			result[8+j] = samples[1][23+j] ^ samples[2][23+j]
		}
	} else {
		// v == 4
		// α1 = ⌈k/3⌉ = 43, α2 = 43, α3 = k - 2*43 = 42
		// Not byte-aligned, need bit manipulation
		const α1 = 43
		const α2 = 43
		const α3 = 42

		// XOR pairs and extract LSBs
		var xor1, xor2, xor3 [31]byte
		for j := 0; j < 31; j++ {
			xor1[j] = samples[0][j] ^ samples[1][j]
			xor2[j] = samples[1][j] ^ samples[2][j]
			xor3[j] = samples[2][j] ^ samples[3][j]
		}

		// Extract LSBs and concatenate into result
		bitOffset := 0
		bitOffset = extractLsbBits(&result, bitOffset, xor1[:], α1)
		bitOffset = extractLsbBits(&result, bitOffset, xor2[:], α2)
		extractLsbBits(&result, bitOffset, xor3[:], α3)
	}

	return &result, nil
}

// extractLsbBits extracts nBits LSBs from src into dst at dstBitOffset.
func extractLsbBits(dst *aes.Block, dstBitOffset int, src []byte, nBits int) int {
	srcBits := len(src) * 8
	srcBitStart := srcBits - nBits

	for i := 0; i < nBits; i++ {
		srcByteIdx := (srcBitStart + i) / 8
		srcBitIdx := 7 - ((srcBitStart + i) % 8)

		dstByteIdx := (dstBitOffset + i) / 8
		dstBitIdx := 7 - ((dstBitOffset + i) % 8)

		bit := (src[srcByteIdx] >> srcBitIdx) & 1
		dst[dstByteIdx] |= bit << dstBitIdx
	}

	return dstBitOffset + nBits
}

// FExp expands a 128-bit key to arbitrary length using ButterKnife counter mode.
func FExp(key *aes.Block, info *SkyeInfo, length int) []byte {
	if length <= 0 {
		return nil
	}

	const blockSize = 16
	const blocksPerCall = 8

	numBlocks := (length + blockSize - 1) / blockSize

	// Construct tweakey for ButterKnife: key || info[0:16]
	var tweakey aes.Tweakey256
	copy(tweakey[0:16], key[:])
	copy(tweakey[16:32], info[0:16])

	// First input: info[16:32]
	var input aes.Block
	copy(input[:], info[16:32])

	// First ButterKnife call
	output := aes.ButterKnife(&tweakey, &input)

	// Store K1 and K2 for subsequent calls
	K1 := output[0]
	K2 := output[1]

	// Build result
	result := make([]byte, 0, numBlocks*blockSize)

	blocksToAdd := numBlocks
	if blocksToAdd > blocksPerCall {
		blocksToAdd = blocksPerCall
	}
	for i := 0; i < blocksToAdd; i++ {
		result = append(result, output[i][:]...)
	}

	if numBlocks <= blocksPerCall {
		return result[:length]
	}

	// Generate additional blocks
	blocksRemaining := numBlocks - blocksPerCall
	counter := 0

	for blocksRemaining > 0 {
		// Update tweakey: key || K1
		copy(tweakey[16:32], K1[:])

		// Input: K2 ⊕ ⟨counter⟩ (big-endian encoding)
		var counterInput aes.Block
		copy(counterInput[:], K2[:])
		counterInput[15] ^= byte(counter)
		counterInput[14] ^= byte(counter >> 8)
		counterInput[13] ^= byte(counter >> 16)
		counterInput[12] ^= byte(counter >> 24)

		output = aes.ButterKnife(&tweakey, &counterInput)

		blocksToAdd = blocksRemaining
		if blocksToAdd > blocksPerCall {
			blocksToAdd = blocksPerCall
		}
		for i := 0; i < blocksToAdd; i++ {
			result = append(result, output[i][:]...)
		}

		blocksRemaining -= blocksToAdd
		counter++
	}

	return result[:length]
}

// Skye derives key material from DH samples (DExtLsb + FExp).
func Skye(samples [][]byte, info *SkyeInfo, length int) ([]byte, error) {
	key, err := DExtLsb(samples)
	if err != nil {
		return nil, err
	}
	return FExp(key, info, length), nil
}

// SkyeContext holds pre-extracted key for multiple expansions.
type SkyeContext struct {
	extractedKey aes.Block
}

// NewSkyeContext extracts from DH samples; use Expand for derivations.
func NewSkyeContext(samples [][]byte) (*SkyeContext, error) {
	key, err := DExtLsb(samples)
	if err != nil {
		return nil, err
	}
	return &SkyeContext{extractedKey: *key}, nil
}

// Expand derives key material using the pre-extracted key.
func (ctx *SkyeContext) Expand(info *SkyeInfo, length int) []byte {
	return FExp(&ctx.extractedKey, info, length)
}

// FExpContext holds a key for multiple FExp expansions (for KDF2/KDF3 style calls).
type FExpContext struct {
	tweakeyBase aes.Tweakey256
}

// NewFExpContext creates an FExp context from a 128-bit key.
func NewFExpContext(key *aes.Block) *FExpContext {
	ctx := &FExpContext{}
	copy(ctx.tweakeyBase[0:16], key[:])
	return ctx
}

// Expand derives key material using the pre-configured key.
func (ctx *FExpContext) Expand(info *SkyeInfo, length int) []byte {
	return FExp((*aes.Block)(ctx.tweakeyBase[0:16]), info, length)
}

// ExpandFromKey derives key material directly from a 128-bit pseudorandom key.
func ExpandFromKey(key *aes.Block, info *SkyeInfo, length int) []byte {
	return FExp(key, info, length)
}
