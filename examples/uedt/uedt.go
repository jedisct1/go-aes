// Package uedt implements the UEDTDM and UEDTMX leakage-resistant AEAD modes
// from "Better Usability: Leakage-Resistant AEADs from Single-length key
// Blockciphers" by Guo, Khairallah and Minematsu (ePrint 2025/...). Both
// modes follow the UEDT framework of Section 3 with parameters fixed in
// Section 5: AES-128 as the single-length-key block cipher, MJH as the
// double-block-length collision-resistant hash, and a Hirose-like
// finalization plugged on top of MJH to feed the tag-generation step.
//
// Two one-time encryption schemes are exposed -- PSVDM (Davies-Meyer-based)
// and PSVMX (mixing-layer-based) -- both built from the partially-fixed-key
// AES of Section 4 with chunk size omega = n = 128.
//
// This implementation targets correctness and clarity. It treats AES-128 as
// an ideal cipher, makes no attempt at constant-time leakage hiding, and is
// not a drop-in replacement for a hardened leakage-resistant implementation.
package uedt

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	aes "github.com/jedisct1/go-aes"
)

const (
	// blockSize is n/8 in bytes, with n = 128 fixed by AES-128.
	blockSize = 16

	// HashSize is the byte length of MJH's 2n-bit chaining value.
	HashSize = 2 * blockSize

	// NonceSize is the AEAD nonce size (3n/4 bits = 12 bytes).
	NonceSize = 12

	// TagSize is the AEAD authentication tag size (n bits).
	TagSize = blockSize

	// KeySize is the AEAD master key size (n bits).
	KeySize = blockSize

	// omega is the partial-fixed-key chunk size, set to n as in Section 5
	// so that an AES key schedule is recomputed only once every 128 blocks.
	omega = 128
)

// ErrAuthFailure is returned by Decrypt when the tag does not verify. The
// caller must not use the returned plaintext (it is always nil in that case).
var ErrAuthFailure = errors.New("uedt: authentication failed")

var errBadNonce = errors.New("uedt: nonce must be 12 bytes")

// ipadn appends "10*" style length padding so that the total length is a
// multiple of n bits. The last byte encodes |X|_8 mod n/8, exactly matching
// Romulus-T's byte-oriented injective padding (see Section 2.1 of the paper).
//
//	ipadn(X) := X || 0^{n - (|X| mod n) - 8} || [|X|_8 mod n/8]_8
func ipadn(x []byte) []byte {
	rem := len(x) % blockSize
	pad := blockSize - rem
	out := make([]byte, len(x)+pad)
	copy(out, x)
	out[len(out)-1] = byte(rem)
	return out
}

// ipadStarN behaves like ipadn except an empty input maps to an empty output.
func ipadStarN(x []byte) []byte {
	if len(x) == 0 {
		return nil
	}
	return ipadn(x)
}

// padNAC applies the encoded padding pad(N, A, C) used by UEDT:
//
//	pad(N, A, C) = ipadn( ipadStarN(A) || ipadStarN(C) || N || [|C|_n]_{n/2} )
//
// The trailing length field is 8 bytes (n/2 bits) holding the number of
// n-bit blocks in C, with the convention |C|_n >= 1 even when C is empty.
func padNAC(N, A, C []byte) []byte {
	a := ipadStarN(A)
	c := ipadStarN(C)

	cBlocks := uint64(len(C)+blockSize-1) / blockSize
	if cBlocks == 0 {
		cBlocks = 1
	}

	buf := make([]byte, 0, len(a)+len(c)+len(N)+8)
	buf = append(buf, a...)
	buf = append(buf, c...)
	buf = append(buf, N...)
	var lenEnc [8]byte
	binary.BigEndian.PutUint64(lenEnc[:], cBlocks)
	buf = append(buf, lenEnc[:]...)
	return ipadn(buf)
}

// hashAndFinalize evaluates H^E on pad(N, A, C) using MJH and runs the
// Hirose-like finalization function. It returns:
//
//	W_in = 1 || U,  where U = chop(E_R(L) XOR L)
//	V    = E_R(sigma(L)) XOR sigma(L)
//
// Both quantities are 128 bits (W_in is what is fed into E_MK to derive the
// per-tag key W; V is then encrypted under W to produce the tag).
func hashAndFinalize(N, A, C []byte) (wIn, V aes.Block) {
	padded := padNAC(N, A, C)
	L, R := mjhHash(padded)

	rKS, _ := aes.NewKeySchedule(R[:])

	// Upper Hirose call: U = chop(E_R(L) XOR L), then prepend the bit "1".
	encL := L
	aes.EncryptBlockAES128(&encL, rKS)
	var X aes.Block
	aes.XorBlock(&X, &encL, &L)
	wIn = X
	wIn[0] = (wIn[0] & 0x7f) | 0x80

	// Lower Hirose call: V = E_R(sigma(L)) XOR sigma(L).
	sigmaL := L
	sigma(&sigmaL)
	encSL := sigmaL
	aes.EncryptBlockAES128(&encSL, rKS)
	aes.XorBlock(&V, &encSL, &sigmaL)
	return
}

// kdfBlock returns the 128-bit AES input "0 || phi(N)" used to derive the
// one-time encryption seed S = E_MK(0 || phi(N)).
//
// With phi(N) = [0]_{n/4-1} || N and a leading zero bit, the full input is
// 32 zero bits followed by the 96-bit nonce, i.e. four zero bytes followed
// by the 12-byte nonce.
func kdfBlock(N []byte) aes.Block {
	var b aes.Block
	copy(b[4:], N)
	return b
}

// otpFunc is the signature shared by PSVDM and PSVMX one-time encryption.
// Both produce a deterministic keystream from (N, S) and XOR it into the
// data buffer, so encryption and decryption use the exact same routine.
type otpFunc func(N []byte, S *aes.Block, data []byte) []byte

func encrypt(MK *aes.Block, N, A, M []byte, otp otpFunc) ([]byte, [TagSize]byte, error) {
	if len(N) != NonceSize {
		return nil, [TagSize]byte{}, errBadNonce
	}

	mkKS, _ := aes.NewKeySchedule(MK[:])

	var C []byte
	if len(M) > 0 {
		S := kdfBlock(N)
		aes.EncryptBlockAES128(&S, mkKS)
		C = otp(N, &S, M)
	}

	wIn, V := hashAndFinalize(N, A, C)

	W := wIn
	aes.EncryptBlockAES128(&W, mkKS)

	wKS, _ := aes.NewKeySchedule(W[:])
	T := V
	aes.EncryptBlockAES128(&T, wKS)

	var tag [TagSize]byte
	copy(tag[:], T[:])
	return C, tag, nil
}

func decrypt(MK *aes.Block, N, A, C []byte, tag [TagSize]byte, otp otpFunc) ([]byte, error) {
	if len(N) != NonceSize {
		return nil, errBadNonce
	}

	mkKS, _ := aes.NewKeySchedule(MK[:])

	wIn, V := hashAndFinalize(N, A, C)

	W := wIn
	aes.EncryptBlockAES128(&W, mkKS)

	// Re-encrypt V under W and compare with the supplied tag. This avoids
	// implementing AES-128 decryption since the verification only needs the
	// forward direction of E_W.
	wKS, _ := aes.NewKeySchedule(W[:])
	expected := V
	aes.EncryptBlockAES128(&expected, wKS)

	if subtle.ConstantTimeCompare(expected[:], tag[:]) != 1 {
		return nil, ErrAuthFailure
	}

	if len(C) == 0 {
		return nil, nil
	}

	S := kdfBlock(N)
	aes.EncryptBlockAES128(&S, mkKS)

	return otp(N, &S, C), nil
}

// EncryptDM authenticates and encrypts (M, A) under master key MK and nonce
// N using the UEDTDM mode (Davies-Meyer one-time encryption).
//
// The returned ciphertext has the same length as the plaintext; the 16-byte
// tag is returned separately. The nonce must be exactly NonceSize bytes; the
// master key must be exactly KeySize bytes. Encrypt is deterministic in all
// of (MK, N, A, M).
func EncryptDM(MK *aes.Block, N, A, M []byte) ([]byte, [TagSize]byte, error) {
	return encrypt(MK, N, A, M, psvdmCrypt)
}

// DecryptDM verifies the tag and decrypts (C, A) under master key MK and
// nonce N. It returns ErrAuthFailure if the tag does not match, in which
// case the returned plaintext is nil.
func DecryptDM(MK *aes.Block, N, A, C []byte, tag [TagSize]byte) ([]byte, error) {
	return decrypt(MK, N, A, C, tag, psvdmCrypt)
}

// EncryptMX is the UEDTMX counterpart of EncryptDM, using the mixing-layer
// one-time encryption PSVMX. The interface is identical to EncryptDM.
func EncryptMX(MK *aes.Block, N, A, M []byte) ([]byte, [TagSize]byte, error) {
	return encrypt(MK, N, A, M, psvmxCrypt)
}

// DecryptMX is the UEDTMX counterpart of DecryptDM.
func DecryptMX(MK *aes.Block, N, A, C []byte, tag [TagSize]byte) ([]byte, error) {
	return decrypt(MK, N, A, C, tag, psvmxCrypt)
}
