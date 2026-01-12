// Package aes provides low-level AES (Advanced Encryption Standard) operations
// with hardware acceleration support for Intel AES-NI (amd64), ARM Crypto
// Extensions (arm64), and VAES (Vector AES) for parallel block processing.
//
// This package exposes individual AES round functions, transformations, and
// key schedules rather than providing a complete block cipher implementation.
// It is designed for building custom cryptographic constructions that need
// direct access to AES primitives.
//
// # Core Features
//
// Low-level AES Operations:
//   - SubBytes/InvSubBytes - S-box transformations
//   - ShiftRows/InvShiftRows - Row permutations
//   - MixColumns/InvMixColumns - Column mixing in GF(2^8)
//   - AddRoundKey - XOR with round key
//   - Round/InvRound - Complete encryption/decryption rounds
//
// Parallel Processing:
//   - Block2 (32 bytes) - Process 2 AES blocks simultaneously
//   - Block4 (64 bytes) - Process 4 AES blocks simultaneously
//   - Hardware acceleration via VAES (Intel) or ARM Crypto Extensions
//
// Areion Permutations:
//   - Areion256 (32-byte state) - 10-round wide-block permutation
//   - Areion512 (64-byte state) - 15-round wide-block permutation
//   - Suitable for hash functions and authenticated encryption
//
// # Hardware Acceleration
//
// The package automatically detects and uses available CPU features:
//   - Intel AES-NI (AESENC/AESDEC instructions)
//   - ARM Crypto Extensions (AESE/AESD instructions)
//   - VAES (AVX2 for 2 blocks, AVX512 for 4 blocks in parallel)
//
// Hardware-accelerated functions have the "HW" suffix and automatically
// fall back to software implementations when hardware support is unavailable.
//
// # Round Function Variants
//
// The package provides three variants of round functions to support different
// cryptographic constructions:
//
// Standard Rounds (e.g., Round, InvRound):
//   - Key XOR at the end
//   - Matches Intel AES-NI and FIPS-197 semantics
//   - Default choice for most applications
//
// KeyFirst Variants (e.g., RoundKeyFirst, InvRoundKeyFirst):
//   - Key XOR at the beginning
//   - Matches ARM Crypto instruction semantics
//   - More efficient on ARM processors
//
// NoKey Variants (e.g., RoundNoKey, InvRoundNoKey):
//   - No key XOR operation
//   - Used for permutations and custom constructions
//
// # Key Schedules
//
// Key expansion is provided via the KeySchedule type:
//   - Supports AES-128 (16-byte keys, 10 rounds)
//   - Supports AES-192 (24-byte keys, 12 rounds)
//   - Supports AES-256 (32-byte keys, 14 rounds)
//
// # Multi-Round Operations
//
// For better performance, multi-round functions combine multiple rounds
// in a single call, reducing function call overhead and enabling better
// instruction pipelining:
//   - Rounds4/7/10/12/14 - Execute N rounds
//   - RoundsNWithFinal - N-1 full rounds + 1 final round (standard AES)
//   - Hardware-accelerated variants available (e.g., Rounds10HW)
//
// # Example: Basic AES-128 Encryption
//
//	package main
//
//	import (
//	    "fmt"
//	    "github.com/jedisct1/go-aes"
//	)
//
//	func main() {
//	    // Create a key schedule from a 16-byte key (AES-128)
//	    key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//	                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
//	    ks, _ := aes.NewKeySchedule(key)
//
//	    // Prepare a block for encryption
//	    var block aes.Block
//	    copy(block[:], []byte("hello world!!!!"))
//
//	    // Encrypt using the high-level helper
//	    aes.EncryptBlockAES128(&block, ks)
//
//	    fmt.Printf("Encrypted: %x\n", block)
//	}
//
// # Example: Parallel Block Processing
//
//	// Process 2 blocks in parallel with VAES acceleration
//	var blocks aes.Block2
//	copy(blocks[0:16], plaintext1)
//	copy(blocks[16:32], plaintext2)
//
//	// Create per-block round keys
//	var roundKeys aes.Key2
//	roundKeys.SetKey(0, ks.GetRoundKey(1))
//	roundKeys.SetKey(1, ks.GetRoundKey(1))
//
//	// Execute one round on both blocks
//	aes.Round2HW(&blocks, &roundKeys)
//
// # Example: Areion256 Permutation
//
//	var state aes.Areion256
//	copy(state[:], input)
//	state.Permute()
//	// state now contains the permuted output
//
// # Platform Support
//
// The package supports:
//   - amd64 with AES-NI and VAES (Intel/AMD)
//   - arm64 with ARM Crypto Extensions
//   - Pure Go fallback for all platforms
//
// # Performance Considerations
//
// For optimal performance:
//   - Use hardware-accelerated functions (HW suffix) when available
//   - Use multi-round functions instead of calling single rounds repeatedly
//   - Use parallel operations (Block2/Block4) when processing multiple blocks
//   - Check CPU features with the CPU variable to select the best code path
//
// # Security Notes
//
// This package provides low-level AES primitives and does NOT implement:
//   - Authenticated encryption modes (GCM, EAX, etc.)
//   - Block cipher modes of operation (CBC, CTR, etc.)
//   - Key derivation or management
//   - Protection against side-channel attacks beyond hardware instructions
//
// Users are responsible for:
//   - Implementing appropriate modes of operation
//   - Managing keys securely
//   - Using proper nonces and IVs
//   - Ensuring thread safety when needed
//
// This package is intended for cryptography experts building custom
// constructions. For standard AES encryption, consider using Go's crypto/aes
// and crypto/cipher packages instead.
package aes
