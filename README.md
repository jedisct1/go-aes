# go-aes

A Go library exposing the fundamental building blocks of AES encryption for developers building custom cryptographic primitives. Unlike traditional AES libraries that provide complete encryption/decryption, this package gives you direct access to individual round functions, transformations, and wide-block permutations.

## Table of Contents

- [go-aes](#go-aes)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Core Concepts](#core-concepts)
    - [Block Operations](#block-operations)
    - [Hardware Acceleration](#hardware-acceleration)
    - [Parallel Processing](#parallel-processing)
    - [Multi-Round Operations](#multi-round-operations)
    - [Key Schedules](#key-schedules)
  - [Cryptographic Constructions](#cryptographic-constructions)
    - [Areion Permutations](#areion-permutations)
    - [Areion-EM Block Cipher](#areion-em-block-cipher)
    - [Areion-SoEM PRF](#areion-soem-prf)
    - [AES-PRF](#aes-prf)
    - [Haraka v2](#haraka-v2)
    - [KIASU-BC Tweakable Block Cipher](#kiasu-bc-tweakable-block-cipher)
    - [Deoxys-BC-256 Tweakable Block Cipher](#deoxys-bc-256-tweakable-block-cipher)
    - [ButterKnife TPRF](#butterknife-tprf)
    - [Pholkos Tweakable Block Cipher](#pholkos-tweakable-block-cipher)
    - [Vistrutah Large-Block Cipher](#vistrutah-large-block-cipher)
  - [Examples](#examples)
    - [Cymric](#cymric)
    - [LeMac](#lemac)
    - [Skye KDF](#skye-kdf)
    - [MacaKey](#macakey)
    - [Sponge-F](#sponge-f)
    - [UEDT (UEDTDM, UEDTMX)](#uedt-uedtdm-uedtmx)
  - [Performance](#performance)
  - [API Reference](#api-reference)
    - [Round Functions](#round-functions)
    - [Individual Transformations](#individual-transformations)
    - [Parallel Operations](#parallel-operations)
    - [Multi-Round Functions](#multi-round-functions)
    - [Key Expansion](#key-expansion)
    - [Complete AES Encryption](#complete-aes-encryption)
    - [Constructions](#constructions)
    - [Skye KDF (examples/skye)](#skye-kdf-examplesskye)
  - [Testing](#testing)

## Features

- Low-level AES operations: SubBytes, ShiftRows, MixColumns, and complete round functions
- Hardware acceleration: Intel AES-NI, ARM Crypto Extensions, and VAES for parallel processing
- Parallel block processing: Process 2 or 4 blocks simultaneously with VAES/AVX2/AVX512
- Multi-round functions: Optimized 4/6/7/10/12/14 round operations
- Wide-block permutations: Areion256 (32-byte) and Areion512 (64-byte)
- Keyed block ciphers from permutations: Areion256-EM and Areion512-EM (Even-Mansour construction)
- Beyond-birthday-bound PRF: Areion-SoEM-256 and Areion-SoEM-512 (Sum of Even-Mansour)
- Short fixed-input hashing: Areion256-DM and Areion512-DM (Davies-Meyer construction)
- Keyed short-input hashing: Vistrutah256-MP and Vistrutah512-MP (Miyaguchi-Preneel construction)
- AES-based hashing: Haraka v2 (256-bit and 512-bit input variants)
- Tweakable block ciphers: KIASU-BC, Deoxys-BC-256, Pholkos (256-bit and 512-bit)
- Large-block ciphers: Vistrutah-256 and Vistrutah-512
- Expanding PRF: ButterKnife (128-bit to 1024-bit expansion)
- Leakage-resistant AEAD: UEDTDM and UEDTMX, single-length-key BC modes with rate 1/4 and Grade-3 leakage resistance
- Cross-platform: Identical results on Intel and ARM with automatic fallback to pure Go

## Installation

```sh
go get github.com/jedisct1/go-aes
```

## Quick Start

```go
package main

import (
    "fmt"
    aes "github.com/jedisct1/go-aes"
)

func main() {
    var block, key aes.Block
    copy(block[:], "Hello, World!...")
    copy(key[:], "SecretKey1234567")

    // Perform one AES forward round (modifies block in place)
    aes.Round(&block, &key)
    fmt.Printf("After one round: %x\n", block)

    // Hardware acceleration is automatic
    if aes.CPU.HasAESNI || aes.CPU.HasARMCrypto {
        copy(block[:], "Hello, World!...")
        aes.RoundHW(&block, &key)
        fmt.Printf("Hardware result: %x\n", block)
    }
}
```

## Core Concepts

### Block Operations

All operations work on 128-bit blocks represented as `[16]byte` arrays. Three round function variants accommodate different use cases:

| Variant                        | Key XOR Position | Use Case                 |
| ------------------------------ | ---------------- | ------------------------ |
| Standard (`Round`, `InvRound`) | End              | FIPS-197/Intel semantics |
| KeyFirst (`RoundKeyFirst`)     | Beginning        | ARM-native semantics     |
| NoKey (`RoundNoKey`)           | None             | Custom constructions     |

### Hardware Acceleration

The package detects CPU capabilities at runtime:

```go
aes.CPU.HasAESNI     // Intel AES-NI (single-block)
aes.CPU.HasARMCrypto // ARM Crypto Extensions
aes.CPU.HasVAES      // Intel VAES (parallel)
aes.CPU.HasAVX2      // 2-block parallel with VAES
aes.CPU.HasAVX512    // 4-block parallel with VAES
```

Intel and ARM AES instructions have different operation orders. The library handles this transparently, ensuring identical results across platforms.

### Parallel Processing

For high-throughput applications, process multiple blocks simultaneously:

```go
// Process two blocks (AVX2)
var blocks aes.Block2  // 32 bytes = 2×16-byte blocks
var keys aes.Key2      // 32 bytes = 2×16-byte keys
result := aes.Round2(blocks, keys)

// Process four blocks (AVX512)
var blocks4 aes.Block4  // 64 bytes
var keys4 aes.Key4
result4 := aes.Round4(blocks4, keys4)
```

Each block is processed with its corresponding key. Falls back to sequential processing without VAES.

### Multi-Round Operations

Optimized functions for multiple rounds in a single call (2-3x faster than separate calls):

```go
var keys aes.RoundKeys10
result := aes.Rounds10(block, keys)

// For complete AES encryption (N-1 full rounds + 1 final round without MixColumns)
result := aes.Rounds10WithFinal(block, keys)
```

Available: `Rounds4`, `Rounds6`, `Rounds7`, `Rounds10`, `Rounds12`, `Rounds14`, plus inverse and NoKey variants.

### Key Schedules

Standard key expansion for AES-128, AES-192, and AES-256:

```go
var masterKey [16]byte
roundKeys := aes.KeyExpansion128(masterKey)

// Or use the KeySchedule type
ks, _ := aes.NewKeySchedule(masterKey[:])
roundKey := ks.GetRoundKey(0)
```

## Cryptographic Constructions

### Areion Permutations

Wide-block cryptographic permutations built using AES rounds, useful for hash functions and authenticated encryption.

- Areion256: 32-byte state, 10 rounds
- Areion512: 64-byte state, 15 rounds

```go
var state aes.Areion256
copy(state[:], yourData)
state.Permute()

// Inverse permutation
state.InversePermute()

// 512-bit variant
var largeState aes.Areion512
largeState.Permute()
```

**Areion-DM**: Short fixed-input hash functions using the Davies-Meyer construction (h = P(m) XOR m).

- Areion256-DM: 32-byte input, 32-byte output
- Areion512-DM: 64-byte input, 32-byte output (truncated)

```go
var input32 [32]byte
hash256 := aes.Areion256DM(&input32)   // [32]byte

var input64 [64]byte
hash512 := aes.Areion512DM(&input64)   // [32]byte
```

### Areion-EM Block Cipher

Keyed block ciphers using the single-key Even-Mansour construction: `E_k(m) = P(m XOR k) XOR k`, where P is an Areion permutation. Provides a simple way to turn the Areion permutation into a keyed primitive.

- Areion256-EM: 32-byte key, 32-byte block
- Areion512-EM: 64-byte key, 64-byte block

```go
var key [32]byte
var block [32]byte
ciphertext := aes.Areion256EM(&key, &block)       // Encrypt
plaintext := aes.Areion256EMDecrypt(&key, &ciphertext) // Decrypt

// 512-bit variant
var key64 [64]byte
var block64 [64]byte
ct512 := aes.Areion512EM(&key64, &block64)
pt512 := aes.Areion512EMDecrypt(&key64, &ct512)
```

### Areion-SoEM PRF

Beyond-birthday-bound PRF using Sum of Even-Mansour with Areion permutations: `F(k1, k2, m) = P(m XOR k1) XOR P(m XOR k2 XOR d)`, where `d` is a domain separation constant. Two independent subkeys push PRF security to ~2n/3 bits, well beyond the n/2-bit birthday bound of single-call constructions.

- Areion-SoEM-256: 64-byte key (2x32), 32-byte input/output, ~170-bit PRF security
- Areion-SoEM-512: 128-byte key (2x64), 64-byte input/output, ~341-bit PRF security

```go
var key256 [64]byte   // two independent 32-byte subkeys
var input256 [32]byte
output256 := aes.AreionSoEM256(&key256, &input256)

var key512 [128]byte  // two independent 64-byte subkeys
var input512 [64]byte
output512 := aes.AreionSoEM512(&key512, &input512)
```

### AES-PRF

Pseudorandom function using AES rounds with feed-forward structure: 4 rounds, XOR with input, then 6 more rounds (5 full + 1 final).

```go
prf, _ := aes.NewAESPRF(key[:])  // 16, 24, or 32 bytes

var block aes.Block
copy(block[:], "Input data here!")
prf.PRF(&block)  // Modifies in place
```

Performance: ~152 ns/op with zero allocations on Apple M4 ARM64.

### Haraka v2

AES-based cryptographic hash function designed for short inputs. Uses AES rounds with round constants derived from the digits of pi.

- Haraka-256: 32-byte input, 32-byte output, 5 rounds
- Haraka-512: 64-byte input, 32-byte output (truncated), 5 rounds

```go
// Hash a 32-byte input
var input [32]byte
copy(input[:], yourData)
hash := aes.Haraka256(&input)

// Hash a 64-byte input
var largeInput [64]byte
hash512 := aes.Haraka512(&largeInput)

// Convenience: get single 16-byte block output
block := aes.Haraka256ToBlock(&input)
```

### KIASU-BC Tweakable Block Cipher

AES-128 with 8-byte tweak XORed into each round. Used in ipcrypt-nd for non-deterministic IP address encryption.

```go
ctx, _ := aes.NewKiasuContext(key)

var plaintext [16]byte
var tweak [8]byte
ciphertext := ctx.KiasuEncrypt(plaintext, tweak)
decrypted := ctx.KiasuDecrypt(ciphertext, tweak)
```

Tweak format: Padded to 16 bytes as `[T0 T1 00 00 T2 T3 00 00 T4 T5 00 00 T6 T7 00 00]`

### Deoxys-BC-256 Tweakable Block Cipher

From the TWEAKEY framework: 256-bit tweakey (128-bit key + 128-bit tweak), 14 rounds.

```go
var tweakey aes.Tweakey256
copy(tweakey[0:16], key[:])
copy(tweakey[16:32], tweak[:])

rk := aes.NewDeoxysBC256(&tweakey)
ciphertext := aes.DeoxysBC256Encrypt(rk, &plaintext)
```

Low-level round functions with domain separation are also available for custom constructions.

### ButterKnife TPRF

Tweakable PRF expanding 128-bit input to 1024-bit output (8 branches). Based on the Iterate-Fork-Iterate paradigm.

```go
var tweakey aes.Tweakey256
var input aes.Block
output := aes.ButterKnife(&tweakey, &input)

// For multiple evaluations, use context
ctx := aes.NewButterKnifeContext(&tweakey)
output1 := ctx.Eval(&input1)
output2 := ctx.Eval(&input2)
```

Structure: 7 rounds before fork (domain 0), then 8 rounds in 8 parallel branches (domains 1-8), with feed-forward XOR.

Reference: ePrint 2021/1534

### Pholkos Tweakable Block Cipher

Large-state tweakable block cipher family based on AES rounds, designed for high security and high performance. Follows the design strategy of Haraka and AESQ with two-round steps.

Variants:

- Pholkos-256-256: 256-bit block, 256-bit key, 128-bit tweak, 8 steps
- Pholkos-512-256: 512-bit block, 256-bit key, 128-bit tweak, 10 steps
- Pholkos-512-512: 512-bit block, 512-bit key, 128-bit tweak, 10 steps

```go
// Pholkos-256 (32-byte block, 32-byte key)
var block aes.Pholkos256Block
var key aes.Pholkos256Key
var tweak aes.PholkosTweak
copy(block[:], plaintext)
copy(key[:], keyBytes)
copy(tweak[:], tweakBytes)

ctx := aes.NewPholkos256Context(&key, &tweak)
ctx.Encrypt(&block)
ctx.Decrypt(&block)

// Pholkos-512 with 256-bit key
var block512 aes.Pholkos512Block
ctx512 := aes.NewPholkos512Context(&key, &tweak)
ctx512.Encrypt(&block512)

// Pholkos-512 with 512-bit key
var key512 aes.Pholkos512Key
ctx512_512 := aes.NewPholkos512Context512(&key512, &tweak)
ctx512_512.Encrypt(&block512)
```

For single-block operations, convenience functions are available: `Pholkos256Encrypt`, `Pholkos256Decrypt`, `Pholkos512Encrypt`, `Pholkos512Decrypt`, `Pholkos512Encrypt512`, `Pholkos512Decrypt512`.

### Vistrutah Large-Block Cipher

Large-block cipher family using Generalized Even-Mansour construction.

Vistrutah-256 (32-byte blocks):

```go
plaintext := make([]byte, 32)
ciphertext := make([]byte, 32)
key := make([]byte, 32)  // 16 or 32 bytes

aes.Vistrutah256Encrypt(plaintext, ciphertext, key, aes.Vistrutah256RoundsLong)
aes.Vistrutah256Decrypt(ciphertext, plaintext, key, aes.Vistrutah256RoundsLong)
```

Vistrutah-512 (64-byte blocks):

```go
plaintext := make([]byte, 64)
ciphertext := make([]byte, 64)
key := make([]byte, 64)  // 32 or 64 bytes

aes.Vistrutah512Encrypt(plaintext, ciphertext, key, aes.Vistrutah512RoundsLong512Key)
```

Round options:

| Variant                     | Short | Long |
| --------------------------- | ----- | ---- |
| Vistrutah-256               | 10    | 14   |
| Vistrutah-512 (256-bit key) | 10    | 14   |
| Vistrutah-512 (512-bit key) | 12    | 18   |

Reference: ePrint 2024/1534

**Vistrutah-MP**: Keyed fixed-input hash functions using the Miyaguchi-Preneel construction (`h = E(k, X) XOR k XOR X`), one of the 12 provably secure PGV compression functions (Black-Rogaway-Shrimpton, CRYPTO 2002).

```go
var input [32]byte
var key [32]byte
hash256 := aes.Vistrutah256MP(&input, key[:], aes.Vistrutah256RoundsLong)  // [32]byte

var input64 [64]byte
var key64 [64]byte
hash512 := aes.Vistrutah512MP(&input64, key64[:], aes.Vistrutah512RoundsLong512Key)  // [64]byte
```

## Examples

### Cymric

Lightweight authenticated encryption (AEAD) using two AES-128 keys. Located in `examples/cymric/`.

Two variants:

- Cymric1: |msg| + |nonce| <= 16, |nonce| + |ad| <= 15
- Cymric2: |msg| <= 16, |nonce| + |ad| <= 15

```go
import "github.com/jedisct1/go-aes/examples/cymric"

var key [32]byte
copy(key[:], keyBytes)
ctx := cymric.NewContext(&key)

// Encrypt
nonce := make([]byte, 12)
msg := []byte("Hi!")
ad := []byte("v1")
ctext := make([]byte, len(msg))
var tag [16]byte
ctx.Cymric1Encrypt(ctext, &tag, msg, ad, nonce)

// Decrypt
ptext := make([]byte, len(ctext))
err := ctx.Cymric1Decrypt(ptext, ctext, &tag, ad, nonce)
```

Features: 256-bit key, 128-bit tag, constant-time verification, zero allocations.

### LeMac

High-speed MAC using parallel AES rounds. Located in `examples/lemac/`.

```go
import "github.com/jedisct1/go-aes/examples/lemac"

var key [16]byte
var nonce [16]byte
copy(key[:], "SecretMACKey1234")

ctx := lemac.NewLeMacContext(key)
tag := lemac.LeMac(ctx, []byte("Authenticate this"), nonce)
```

Provides 128-bit security with unique nonces, 64-bit with static nonces.

### Skye KDF

Key derivation function for DH shared secrets (e.g., X3DH handshakes). Located in `examples/skye/`.

```go
import "github.com/jedisct1/go-aes/examples/skye"

samples := [][]byte{dh1, dh2, dh3}  // 3-4 DH secrets (32 bytes each)
var info skye.SkyeInfo
copy(info[:], "Signal Protocol v1.0")

key, _ := skye.Skye(samples, &info, 64)

// For multiple derivations
ctx, _ := skye.NewSkyeContext(samples)
key1 := ctx.Expand(&info1, 32)
key2 := ctx.Expand(&info2, 32)
```

Reference: ePrint 2024/781

### MacaKey

Full-state keyed sponge PRF/MAC using Areion512. Located in `examples/macakey/`.

```go
import "github.com/jedisct1/go-aes/examples/macakey"

var key [32]byte
copy(key[:], keyBytes)

// One-shot MAC
mac, _ := macakey.Macakey(key[:], message, 32)

// Streaming
ctx, _ := macakey.NewMacakeyContext(key[:])
ctx.Write(chunk1)
ctx.Write(chunk2)
mac := ctx.Sum(32)

// With explicit IV (32 bytes)
mac, _ := macakey.MacakeyWithIV(key[:], iv, message, 32)
```

Based on MacaKey V2 with NCP-based domain separation. Provides 128-bit security.

### Sponge-F

Sponge construction with feed-forward using Areion512 as the underlying permutation. Located in `examples/spongef/`.

Unlike a standard sponge, Sponge-F XORs the pre-permutation capacity back into the post-permutation state during both absorption and squeezing. This feed-forward makes the construction secure even when the permutation is not ideal, requiring only unpredictability rather than indifferentiability from a random permutation.

```go
import "github.com/jedisct1/go-aes/examples/spongef"

// One-shot hash (256-bit output)
hash := spongef.Hash(message)

// Variable-length output (XOF-style)
out, _ := spongef.SpongeF(message, 64)  // 64 bytes

// With custom IV
out, _ := spongef.SpongeFWithIV(iv, message, 64)

// Streaming
ctx := spongef.NewSpongeFContext()
ctx.Write(chunk1)
ctx.Write(chunk2)
hash := ctx.Sum(32)
```

Parameters: rate r = 256 bits, capacity c = 256 bits, Areion512 permutation (b = 512 bits). Minimum output size is 32 bytes.

Reference: ePrint 2025/1006

### UEDT (UEDTDM, UEDTMX)

Leakage-resistant AEAD modes built from a single-length-key block cipher (AES-128). Both modes follow the UEDT framework: a partially-fixed-key one-time encryption pass, an MJH double-block-length hash, and a Hirose-like finalization, combined Encrypt-then-MAC. Located in `examples/uedt/`.

- UEDTDM uses the Davies-Meyer-based one-time encryption (PSVDM)
- UEDTMX uses the mixing-layer-based one-time encryption (PSVMX, with `D = [[2, 1], [1, 1]]` over GF(2^128))

Both are rate-1/4 with a 128-bit master key, 96-bit nonce, and 128-bit tag, achieving Grade-3 leakage resistance (CIML2 + CCAmL2) and birthday-bound CMT4 committing security under the assumed MJH collision bound.

```go
import "github.com/jedisct1/go-aes/examples/uedt"

var MK aes.Block
copy(MK[:], keyBytes)
nonce := make([]byte, uedt.NonceSize)  // 12 bytes
ad := []byte("metadata")
msg := []byte("plaintext")

// UEDTDM
ct, tag, _ := uedt.EncryptDM(&MK, nonce, ad, msg)
pt, err := uedt.DecryptDM(&MK, nonce, ad, ct, tag)

// UEDTMX
ct, tag, _ = uedt.EncryptMX(&MK, nonce, ad, msg)
pt, err = uedt.DecryptMX(&MK, nonce, ad, ct, tag)
```

`DecryptDM` / `DecryptMX` return `uedt.ErrAuthFailure` on tag mismatch, with a constant-time tag comparison.

Reference: Guo, Khairallah, Minematsu — *Better Usability: Leakage-Resistant AEADs from Single-length key Blockciphers*

## Performance

Hardware acceleration provides ~10x speedup over pure Go. VAES with AVX512 processes four blocks in roughly the time of one. Multi-round functions add another 2-3x improvement.

```sh
go test -bench=.
```

## API Reference

### Round Functions

| Function                           | Description                    |
| ---------------------------------- | ------------------------------ |
| `Round(block, key *Block)`         | Forward round (key XOR at end) |
| `InvRound(block, key *Block)`      | Inverse round                  |
| `FinalRound(block, key *Block)`    | Final round (no MixColumns)    |
| `RoundKeyFirst(block, key *Block)` | Key XOR at beginning           |
| `RoundNoKey(block *Block)`         | No key XOR                     |
| `RoundHW(block, key *Block)`       | Hardware-accelerated           |

### Individual Transformations

`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey` and their inverse variants.

### Parallel Operations

| Function                      | Description      |
| ----------------------------- | ---------------- |
| `Round2(Block2, Key2) Block2` | Process 2 blocks |
| `Round4(Block4, Key4) Block4` | Process 4 blocks |

Available in standard, KeyFirst, NoKey, and HW variants.

### Multi-Round Functions

`Rounds4`, `Rounds6`, `Rounds7`, `Rounds10`, `Rounds12`, `Rounds14` with inverse, NoKey, HW, and `WithFinal` variants.

### Key Expansion

| Function                                       | Description           |
| ---------------------------------------------- | --------------------- |
| `KeyExpansion128([16]byte) [176]byte`          | AES-128 key expansion |
| `KeyExpansion192([24]byte) [208]byte`          | AES-192 key expansion |
| `KeyExpansion256([32]byte) [240]byte`          | AES-256 key expansion |
| `NewKeySchedule([]byte) (*KeySchedule, error)` | Create key schedule   |

### Complete AES Encryption

`EncryptBlockAES128`, `EncryptBlockAES192`, `EncryptBlockAES256`, `EncryptBlockAES` for full block encryption.

### Constructions

| Construction  | Key Functions                                                               |
| ------------- | --------------------------------------------------------------------------- |
| Areion        | `Areion256.Permute/InversePermute`, `Areion512.Permute/InversePermute`, `Areion256DM`, `Areion512DM`, `Areion256EM/EMDecrypt`, `Areion512EM/EMDecrypt`, `AreionSoEM256`, `AreionSoEM512` |
| AES-PRF       | `NewAESPRF`, `(*AESPRF).PRF`                                                |
| Haraka        | `Haraka256`, `Haraka512`, `Haraka256ToBlock`, `Haraka512ToBlock`            |
| KIASU-BC      | `NewKiasuContext`, `KiasuEncrypt`, `KiasuDecrypt`                           |
| Deoxys-BC-256 | `NewDeoxysBC256`, `DeoxysBC256Encrypt`, `DeoxysBC256Decrypt`                |
| ButterKnife   | `ButterKnife`, `NewButterKnifeContext`, `(*ButterKnifeContext).Eval`        |
| Pholkos       | `NewPholkos256Context`, `NewPholkos512Context`, `Pholkos256Encrypt/Decrypt` |
| Vistrutah     | `Vistrutah256Encrypt/Decrypt`, `Vistrutah512Encrypt/Decrypt`, `Vistrutah256MP`, `Vistrutah512MP` |

### Skye KDF (examples/skye)

`Skye`, `NewSkyeContext`, `DExtLsb`, `FExp`

## Testing

```sh
go test -v              # Run all tests
go test -v -run TestName  # Run specific test
go test -bench=.        # Run benchmarks
```

The test suite includes FIPS-197 test vectors and cross-platform tests ensuring hardware and software implementations produce identical results.
