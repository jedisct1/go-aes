# go-aes

A Go library that exposes the fundamental building blocks of AES encryption, designed for developers building custom cryptographic primitives. Unlike traditional AES libraries that provide complete encryption/decryption, this package gives you direct access to individual round functions, transformations, and wide-block permutations.

## What makes this different?

Most AES libraries are black boxes: you put plaintext in, get ciphertext out. This library takes a different approach by exposing the internal machinery. You get access to SubBytes, ShiftRows, MixColumns, and complete round functions. This is useful when you're implementing novel cryptographic constructions like hash functions, MACs, or authenticated encryption schemes that use AES rounds as a building block.

The library automatically detects and uses hardware acceleration when available, including Intel AES-NI, ARM Crypto Extensions, and VAES for parallel processing. Everything falls back gracefully to pure Go implementations when hardware support isn't present.

## Installation

```sh
go get github.com/jedisct1/go-aes
```

## Quick Start

Here's a simple example showing how to perform a single AES round:

```go
package main

import (
    "fmt"
    "encoding/hex"
    aes "github.com/jedisct1/go-aes"
)

func main() {
    // Create a 128-bit block and round key
    var block, key [16]byte
    copy(block[:], "Hello, World!...")
    copy(key[:], "SecretKey1234567")

    // Perform one AES forward round
    result := aes.Round(block, key)
    fmt.Printf("After one round: %x\n", result)

    // Hardware acceleration is automatic if available
    if aes.CPU.HasAESNI || aes.CPU.HasARMCrypto {
        result = aes.RoundHW(block, key)
        fmt.Printf("Hardware result: %x\n", result)
    }
}
```

## Core Concepts

### Block Operations

All basic operations work on 128-bit blocks represented as `[16]byte` arrays. The library provides three flavors of round functions to match different use cases:

**Standard rounds** perform the key XOR at the end, matching the FIPS-197 specification and Intel's native instruction semantics. Functions like `Round()`, `InvRound()`, and their hardware variants `RoundHW()` follow this pattern.

**KeyFirst variants** XOR the key at the beginning instead. These functions (`RoundKeyFirst()`, `InvRoundKeyFirst()`, etc.) match ARM's native instruction semantics and can be more efficient on ARM platforms. They're functionally equivalent to standard rounds when used correctly.

**NoKey variants** skip the key XOR entirely, useful when building custom constructions where you want to apply the round transformations without mixing in a key. Functions like `RoundNoKey()` and `InvRoundNoKey()` fall into this category.

### Hardware Acceleration

The package detects your CPU capabilities at runtime and uses the fastest implementation available. On Intel systems with AES-NI, operations run at native speed using dedicated instructions. ARM systems with Crypto Extensions get similar treatment. The library even supports VAES (Vector AES) on modern Intel chips with AVX2 or AVX512, allowing you to process 2 or 4 blocks simultaneously.

Intel and ARM AES instructions have slightly different operation orders. Intel's AESENC puts the key XOR at the end, while ARM's AESE puts it at the beginning. The library handles this transparently, ensuring you get identical results across platforms.

### Parallel Processing

For high-throughput applications, the library provides types and functions for processing multiple blocks at once:

```go
// Process two blocks simultaneously (AVX2)
var blocks aes.Block2  // 32 bytes = 2×16-byte blocks
var keys aes.Key2      // 32 bytes = 2×16-byte keys
result := aes.Round2(blocks, keys)  // Each block uses its own key

// Process four blocks simultaneously (AVX512)
var blocks4 aes.Block4  // 64 bytes = 4×16-byte blocks
var keys4 aes.Key4      // 64 bytes = 4×16-byte keys
result4 := aes.Round4(blocks4, keys4)
```

Each block in a `Block2` or `Block4` is processed with its corresponding key from `Key2` or `Key4`. This is particularly useful for parallel encryption of multiple independent messages or custom constructions requiring per-block keys.

On systems without VAES, these operations still work but fall back to processing blocks sequentially in software. ARM64 systems get optimized assembly implementations that reduce overhead even without VAES.

### Multi-Round Operations

When you need to perform multiple rounds in sequence, the library offers optimized multi-round functions that keep data in registers and eliminate function call overhead:

```go
// Prepare 10 round keys
var keys aes.RoundKeys10
// ... initialize your keys ...

// Perform 10 rounds in a single call (2-3x faster than 10 separate calls)
result := aes.Rounds10(block, keys)
```

Available variants include `Rounds4`, `Rounds6`, `Rounds7`, `Rounds10`, `Rounds12`, and `Rounds14`, along with inverse versions and NoKey variants. Hardware-accelerated versions like `Rounds10HW` are also provided.

For complete AES encryption, use the `WithFinal` variants like `Rounds10WithFinal()` which perform N-1 full rounds plus one final round without MixColumns, matching the standard AES structure.

## Areion Permutations

Beyond basic AES operations, the library includes Areion—a family of wide-block cryptographic permutations built using AES rounds. These are useful for constructing hash functions, authenticated encryption, and other cryptographic primitives.

**Areion256** operates on 32-byte states (two AES blocks) using 10 rounds. **Areion512** processes 64-byte states (four AES blocks) with 15 rounds. Both use round constants derived from the digits of π to prevent symmetry attacks.

```go
// Hash a 32-byte input
var state [32]byte
copy(state[:], yourData)

// Apply the Areion256 permutation
result := aes.Areion256(state)

// Or use the 512-bit variant for higher throughput
var largeState [64]byte
result512 := aes.Areion512(largeState)
```

Hardware acceleration kicks in automatically on both Intel and ARM platforms. Inverse permutations are also available via `InvAreion256()` and `InvAreion512()`.

## AES-PRF

AES-PRF is a pseudorandom function (PRF) construction that uses AES rounds with a feed-forward structure. Unlike standard AES encryption, it applies 4 AES rounds, XORs the result with the original input (feed-forward), then applies 6 more rounds (5 full + 1 final).

This construction is particularly useful for building cryptographic hash functions, message authentication codes (MACs), and key derivation functions. The feed-forward XOR adds non-linearity that makes the function non-invertible without the key.

```go
// Create an AES-PRF instance with a 128-bit key
var key [16]byte
copy(key[:], "SecretPRFKey1234")

prf, err := aes.NewAESPRF(key[:])
if err != nil {
    panic(err)
}

// Apply the PRF to a block (modifies in place)
var block aes.Block
copy(block[:], "Input data here!")
prf.PRF(&block)

fmt.Printf("PRF output: %x\n", block)
```

**Performance:** ~152 ns/op with zero allocations on Apple M4 ARM64. Hardware acceleration (Intel AES-NI, ARM Crypto) is automatically used when available.

**Security:** The 4+6 round configuration with feed-forward at round 4 provides resistance to known cryptanalytic attacks on AES-PRF constructions.

**Key sizes:** Supports AES-128, AES-192, and AES-256 keys (16, 24, or 32 bytes). Regardless of key size, the construction uses a 10-round structure matching AES-128.

## KIASU-BC Tweakable Block Cipher

KIASU-BC is a tweakable block cipher based on AES-128 that incorporates an 8-byte tweak into each round. It extends standard AES by XORing a padded tweak value with each round key, enabling efficient encryption with varying tweaks without recomputing the entire key schedule.

This construction is particularly useful for format-preserving encryption, disk encryption, and other scenarios where you need to encrypt the same data with different tweaks efficiently. KIASU-BC is used in ipcrypt-nd for non-deterministic IP address encryption.

```go
// Create a KIASU-BC context with a 128-bit key
var key [16]byte
copy(key[:], "SecretKey1234567")

ctx, err := aes.NewKiasuContext(key)
if err != nil {
    panic(err)
}

// Encrypt a block with an 8-byte tweak
var plaintext [16]byte
var tweak [8]byte
copy(plaintext[:], "Data to encrypt!")
copy(tweak[:], "Tweak123")

ciphertext := ctx.KiasuEncrypt(plaintext, tweak)

// Decrypt using the same tweak
decrypted := ctx.KiasuDecrypt(ciphertext, tweak)
```

**Tweak format:** The 8-byte tweak is padded to 16 bytes by placing each 2-byte pair at the start of each 4-byte group: `[T0 T1 00 00 T2 T3 00 00 T4 T5 00 00 T6 T7 00 00]`

**Performance:** KIASU-BC encryption and decryption automatically benefit from hardware acceleration through the optimized multi-round functions (`Rounds10WithFinalHW`, `InvRounds10WithFinalHW`).

**Implementation:** KIASU-BC reuses the library's existing AES infrastructure. The tweaked key schedule is created by XORing the base key schedule with the padded tweak, then standard AES-128 encryption/decryption is performed using the tweaked keys.

## Deoxys-BC-256 Tweakable Block Cipher

Deoxys-BC-256 is a tweakable block cipher from the TWEAKEY framework, designed for authenticated encryption and other advanced constructions. It uses a 256-bit tweakey (128-bit key + 128-bit tweak) and performs 14 rounds.

```go
// Create a 256-bit tweakey (key || tweak)
var tweakey aes.Tweakey256
copy(tweakey[0:16], key[:])    // First 128 bits: key
copy(tweakey[16:32], tweak[:]) // Last 128 bits: tweak

// Expand the tweakey into round keys
rk := aes.NewDeoxysBC256(&tweakey)

// Encrypt a block
var plaintext aes.Block
ciphertext := aes.DeoxysBC256Encrypt(rk, &plaintext)

// Decrypt
decrypted := aes.DeoxysBC256Decrypt(rk, &ciphertext)
```

The library also provides low-level Deoxys round functions with domain separation support, useful for building custom constructions:

```go
// Expand tweakey for domain-separated constructions
rtk := aes.DeoxysExpandTweakey256(&tweakey)

// Perform a single Deoxys round with domain separation
var state aes.Block
domain := byte(1)
roundNum := 0
aes.DeoxysRound(&state, rtk, roundNum, domain)
```

**Tweakey schedule:** Uses the h permutation and LFSR2 transformation as specified in the Deoxys v1.41 specification. The standard variant uses GF(2^8) multiplication for TK2 (matching SUPERCOP reference), while domain-separated variants use LFSR2.

## ButterKnife TPRF

ButterKnife is a Tweakable Pseudorandom Function (TPRF) that expands a 128-bit input to 1024-bit output (8 branches of 128 bits each). It's based on the Iterate-Fork-Iterate paradigm and uses Deoxys round functions with domain separation.

This construction is useful for key derivation, wide-block encryption, and other scenarios where you need to expand a small input into a larger pseudorandom output.

```go
// Create a 256-bit tweakey
var tweakey aes.Tweakey256
for i := 0; i < 32; i++ {
    tweakey[i] = byte(i)
}

// Evaluate ButterKnife on a 128-bit input
var input aes.Block
output := aes.ButterKnife(&tweakey, &input)

// Output contains 8 branches (1024 bits total)
for i, branch := range output {
    fmt.Printf("Branch %d: %x\n", i, branch[:])
}
```

For processing multiple inputs with the same tweakey, use the context-based API to avoid repeated tweakey expansion:

```go
ctx := aes.NewButterKnifeContext(&tweakey)

// Evaluate on multiple inputs efficiently
output1 := ctx.Eval(&input1)
output2 := ctx.Eval(&input2)
```

**Structure:** 7 rounds before the fork point (domain 0), then 8 rounds in each of 8 parallel branches (domains 1-8), followed by a feed-forward XOR with the fork state.

**Reference:** Based on "Masked Iterate-Fork-Iterate: A new Design Paradigm for Tweakable Expanding Pseudorandom Function" (ePrint 2021/1534).

## Vistrutah Large-Block Cipher

Vistrutah is a large-block cipher family providing 256-bit and 512-bit block sizes, built using the Generalized Even-Mansour construction with AES round functions. It's designed for applications requiring larger block sizes than standard AES, such as wide-block encryption modes and format-preserving encryption.

**Vistrutah-256** operates on 32-byte blocks with 16 or 32-byte keys:

```go
// Encrypt a 32-byte block
plaintext := make([]byte, 32)
ciphertext := make([]byte, 32)
key := make([]byte, 32) // 16 or 32 bytes

// Use 14 rounds for full security, 10 rounds for HCTR2/ForkCipher applications
aes.Vistrutah256Encrypt(plaintext, ciphertext, key, aes.Vistrutah256RoundsLong)

// Decrypt
aes.Vistrutah256Decrypt(ciphertext, plaintext, key, aes.Vistrutah256RoundsLong)
```

**Vistrutah-512** operates on 64-byte blocks with 32 or 64-byte keys:

```go
plaintext := make([]byte, 64)
ciphertext := make([]byte, 64)
key := make([]byte, 64) // 32 or 64 bytes

// Round options depend on key size:
// - 256-bit key: 10 (short) or 14 (long) rounds
// - 512-bit key: 12 (short) or 18 (long) rounds
aes.Vistrutah512Encrypt(plaintext, ciphertext, key, aes.Vistrutah512RoundsLong512Key)
aes.Vistrutah512Decrypt(ciphertext, plaintext, key, aes.Vistrutah512RoundsLong512Key)
```

**Round configurations:**
- `Vistrutah256RoundsShort` (10) - For HCTR2/ForkCipher applications
- `Vistrutah256RoundsLong` (14) - Full security
- `Vistrutah512RoundsShort256Key` (10), `Vistrutah512RoundsLong256Key` (14) - 256-bit keys
- `Vistrutah512RoundsShort512Key` (12), `Vistrutah512RoundsLong512Key` (18) - 512-bit keys

**Reference:** "Vistrutah: A Large Block Cipher for Disk Encryption" (ePrint 2024/1534).

## Key Schedules

The library includes standard key expansion functions for AES-128, AES-192, and AES-256:

```go
// Expand a 128-bit key into 11 round keys
var masterKey [16]byte
roundKeys := aes.KeyExpansion128(masterKey)

// For AES-256
var masterKey256 [32]byte
roundKeys256 := aes.KeyExpansion256(masterKey256)
```

These key schedules are platform-independent and produce identical results everywhere, which is important for interoperability.

## Examples

The `examples/` directory includes practical cryptographic constructions built using this library.

### LeMac (examples/lemac.go)

LeMac is a high-speed message authentication code that demonstrates how to use AES round functions to build a practical cryptographic construction:

```go
package main

import (
    "fmt"
    lemac "github.com/jedisct1/go-aes/examples"
)

func main() {
    var key [16]byte
    copy(key[:], "SecretMACKey1234")

    ctx := lemac.NewLeMacContext(key)

    message := []byte("Authenticate this message")
    var nonce [16]byte  // Use unique nonces in production!

    tag := ctx.Mac(message, nonce)
    fmt.Printf("MAC tag: %x\n", tag)
}
```

LeMac achieves high performance by processing messages in 64-byte blocks using parallel AES rounds. It provides 128-bit security with unique nonces or 64-bit security with static nonces.

### Skye KDF (examples/skye/)

Skye is a key derivation function following the extract-then-expand paradigm, designed for deriving keys from Diffie-Hellman shared secrets (e.g., X3DH handshakes in Signal Protocol). Based on the paper "Skye: An Expanding PRF based Fast KDF and its Applications" (ePrint 2024/781).

```go
package main

import (
    "fmt"
    "github.com/jedisct1/go-aes/examples/skye"
)

func main() {
    // DH shared secrets from X3DH handshake (3 or 4 samples)
    dh1 := make([]byte, 32) // First DH output
    dh2 := make([]byte, 32) // Second DH output
    dh3 := make([]byte, 32) // Third DH output
    samples := [][]byte{dh1, dh2, dh3}

    // Context/info string (256 bits)
    var info skye.SkyeInfo
    copy(info[:], "Signal Protocol v1.0")

    // Derive 64 bytes of key material
    key, err := skye.Skye(samples, &info, 64)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Derived key: %x\n", key)

    // For multiple derivations from the same DH samples:
    ctx, _ := skye.NewSkyeContext(samples)
    key1 := ctx.Expand(&info, 32)  // First key
    // ... use different info for additional keys
}
```

**Components:**
- `DExtLsb` - Extracts 128-bit key from 3-4 DH samples using LSB extraction
- `FExp` - Expands key using ButterKnife TPRF in counter mode
- `Skye` - Main KDF combining extraction and expansion

## Performance

Hardware acceleration makes a dramatic difference. On an Intel system with AES-NI, a single round operation runs about 10x faster than pure Go. With VAES and AVX512, you can process four blocks in roughly the time it takes to process one, scaling nearly linearly.

Multi-round functions provide another 2-3x speedup over calling single-round functions repeatedly, since they eliminate function call overhead and keep data in registers throughout the operation.

To benchmark on your system:

```sh
go test -bench=.
```

## API Reference

### Basic Round Functions

- `Round(block, key [16]byte) [16]byte` - Forward round (ShiftRows, SubBytes, MixColumns, XOR key)
- `InvRound(block, key [16]byte) [16]byte` - Inverse round
- `RoundKeyFirst(block, key [16]byte) [16]byte` - Key XOR at beginning
- `RoundNoKey(block [16]byte) [16]byte` - No key XOR
- `RoundHW(block, key [16]byte) [16]byte` - Hardware-accelerated forward round

### Individual Transformations

- `SubBytes(block [16]byte) [16]byte` - Apply S-box substitution
- `ShiftRows(block [16]byte) [16]byte` - Rotate rows
- `MixColumns(block [16]byte) [16]byte` - Mix column transformation
- Inverse versions: `InvSubBytes()`, `InvShiftRows()`, `InvMixColumns()`

### Parallel Operations

- `Round2(blocks Block2, keys Key2) Block2` - Process 2 blocks
- `Round4(blocks Block4, keys Key4) Block4` - Process 4 blocks
- Available in standard, KeyFirst, NoKey, and HW variants

### Multi-Round Functions

- `Rounds10(block [16]byte, keys RoundKeys10) [16]byte` - 10 rounds
- Similar functions for 4, 6, 7, 12, and 14 rounds
- `Rounds6/10/12/14WithFinal()` - N-1 full rounds + 1 final round (no MixColumns)
- Inverse, NoKey, and HW variants available

### Areion Permutations

- `Areion256(state [32]byte) [32]byte` - 32-byte permutation
- `Areion512(state [64]byte) [64]byte` - 64-byte permutation
- `InvAreion256()` and `InvAreion512()` for inverse permutations

### AES-PRF

- `NewAESPRF(key []byte) (*AESPRF, error)` - Create AES-PRF instance (16/24/32 byte keys)
- `(*AESPRF).PRF(block *Block)` - Apply PRF construction (modifies block in place)

### KIASU-BC

- `NewKiasuContext(key [16]byte) (*KiasuContext, error)` - Create KIASU-BC context
- `(*KiasuContext).KiasuEncrypt(block [16]byte, tweak [8]byte) [16]byte` - Encrypt with tweak
- `(*KiasuContext).KiasuDecrypt(block [16]byte, tweak [8]byte) [16]byte` - Decrypt with tweak
- `(*KiasuContext).KiasuEncryptHW(...)` / `(*KiasuContext).KiasuDecryptHW(...)` - Hardware-accelerated variants
- `PadTweak(tweak [8]byte) [16]byte` - Pad 8-byte tweak to 16 bytes

### Deoxys-BC-256

- `Tweakey256` - 256-bit tweakey type (key || tweak)
- `NewDeoxysBC256(tweakey *Tweakey256) *DeoxysBC256RoundKeys` - Expand tweakey for standard Deoxys-BC-256
- `DeoxysBC256Encrypt(rk *DeoxysBC256RoundKeys, plaintext *Block) Block` - Encrypt with Deoxys-BC-256
- `DeoxysBC256Decrypt(rk *DeoxysBC256RoundKeys, ciphertext *Block) Block` - Decrypt with Deoxys-BC-256
- `DeoxysExpandTweakey256(tweakey *Tweakey256) *DeoxysRoundTweakeys` - Expand tweakey for domain-separated constructions
- `DeoxysRound(state *Block, rtk *DeoxysRoundTweakeys, roundNum int, domain byte)` - Single Deoxys round with domain separation
- `DeoxysAddRoundTweakey(state *Block, rtk *DeoxysRoundTweakeys, roundNum int, domain byte)` - Add round tweakey only
- `DeoxysRoundConstant(domain byte, roundNum int) Block` - Generate round constant
- `DeoxysPermuteTK(tk *Block)` - Apply h permutation to tweakey state
- `DeoxysLFSR2(tk *Block)` - Apply LFSR2 transformation

### ButterKnife TPRF

- `ButterKnifeOutput` - 8-branch output type (1024 bits)
- `ButterKnife(tweakey *Tweakey256, input *Block) *ButterKnifeOutput` - Evaluate ButterKnife TPRF
- `NewButterKnifeContext(tweakey *Tweakey256) *ButterKnifeContext` - Create context with pre-expanded tweakey
- `(*ButterKnifeContext).Eval(input *Block) *ButterKnifeOutput` - Evaluate with pre-expanded tweakey

### Vistrutah Large-Block Cipher

- `Vistrutah256Encrypt(plaintext, ciphertext, key []byte, rounds int)` - Encrypt 32-byte block
- `Vistrutah256Decrypt(ciphertext, plaintext, key []byte, rounds int)` - Decrypt 32-byte block
- `Vistrutah512Encrypt(plaintext, ciphertext, key []byte, rounds int)` - Encrypt 64-byte block
- `Vistrutah512Decrypt(ciphertext, plaintext, key []byte, rounds int)` - Decrypt 64-byte block
- Round constants: `Vistrutah256RoundsShort` (10), `Vistrutah256RoundsLong` (14)
- Round constants: `Vistrutah512RoundsShort256Key` (10), `Vistrutah512RoundsLong256Key` (14)
- Round constants: `Vistrutah512RoundsShort512Key` (12), `Vistrutah512RoundsLong512Key` (18)

### Skye KDF (examples/skye package)

- `SkyeInfo` - 256-bit auxiliary/context information type
- `DExtLsb(samples [][]byte) (*aes.Block, error)` - Extract 128-bit key from 3-4 DH samples
- `FExp(key *aes.Block, info *SkyeInfo, length int) []byte` - Expand key to arbitrary length
- `Skye(samples [][]byte, info *SkyeInfo, length int) ([]byte, error)` - Main KDF function
- `NewSkyeContext(samples [][]byte) (*SkyeContext, error)` - Create context with pre-extracted key
- `(*SkyeContext).Expand(info *SkyeInfo, length int) []byte` - Expand with pre-extracted key
- `NewFExpContext(key *aes.Block) *FExpContext` - Create FExp-only context
- `ExpandFromKey(key *aes.Block, info *SkyeInfo, length int) []byte` - Direct key expansion

### Key Expansion

- `KeyExpansion128(key [16]byte) [176]byte` - Expand AES-128 key
- `KeyExpansion192(key [24]byte) [208]byte` - Expand AES-192 key
- `KeyExpansion256(key [32]byte) [240]byte` - Expand AES-256 key

### CPU Detection

The `CPU` variable provides feature flags:
- `CPU.HasAESNI` - Intel AES-NI available
- `CPU.HasARMCrypto` - ARM Crypto Extensions available
- `CPU.HasVAES` - Vector AES (VAES) available
- `CPU.HasAVX2` / `CPU.HasAVX512` - Vector extension support

## Testing

The test suite includes FIPS-197 test vectors to verify correctness and cross-platform tests that ensure hardware and software implementations produce identical results:

```sh
# Run all tests
go test -v

# Run a specific test
go test -v -run TestFIPS197
```
