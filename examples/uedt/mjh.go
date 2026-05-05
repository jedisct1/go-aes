package uedt

import (
	aes "github.com/jedisct1/go-aes"
)

// gfDouble multiplies x by the polynomial alpha = 2 in GF(2^128) using the
// reduction polynomial x^128 + x^7 + x^2 + x + 1 (the same as AES-XTS / GCM).
// This serves as the constant theta != 0, 1 used by the MJH compression.
func gfDouble(x *aes.Block) {
	carry := (x[0] >> 7) & 1
	for i := 0; i < 15; i++ {
		x[i] = (x[i] << 1) | (x[i+1] >> 7)
	}
	x[15] = (x[15] << 1) ^ (carry * 0x87)
}

// sigma is the involution sigma(x) = x XOR (0^{n-1} || 1). It has no fixed
// point, as required by MJH and the Hirose-like finalization.
func sigma(b *aes.Block) {
	b[15] ^= 0x01
}

// mjhCompress runs one MJH compression step over a 2n-bit chaining value
// (g, h) and an n-bit message block w, returning the new chaining value.
//
// Following the original Lee-Stam definition for a single-length-key BC:
//
//	g' = E_h(g XOR w) XOR (g XOR w)
//	h' = theta * (E_h(sigma(g XOR w)) XOR sigma(g XOR w)) XOR (g XOR w) XOR w
//
// Both block-cipher calls share the key h, so the AES-128 round keys are
// expanded once per call and reused for both encryptions.
func mjhCompress(g, h, w *aes.Block) (gp, hp aes.Block) {
	var x aes.Block
	aes.XorBlock(&x, g, w)

	ks, _ := aes.NewKeySchedule(h[:])
	rk0 := *ks.GetRoundKey(0)
	var rk aes.RoundKeys10
	for r := range 10 {
		rk[r] = *ks.GetRoundKey(r + 1)
	}

	y1 := x
	aesEnc(&y1, &rk0, &rk)
	aes.XorBlock(&gp, &y1, &x)

	sx := x
	sigma(&sx)
	y2 := sx
	aesEnc(&y2, &rk0, &rk)

	var t aes.Block
	aes.XorBlock(&t, &y2, &sx)
	gfDouble(&t)
	aes.XorBlock(&t, &t, &x)
	aes.XorBlock(&hp, &t, w)
	return
}

// mjhHash applies MJH iteratively to a byte string whose length is a multiple
// of the AES block size, returning a 2n-bit digest as (L, R).
//
// The input must already be padded by an injective padding such as padNAC; no
// extra Merkle-Damgard length appending is performed here, since the
// surrounding UEDT framework relies on the padding to inject the length.
func mjhHash(message []byte) (l, r aes.Block) {
	var g, h aes.Block
	for i := 0; i < len(message); i += blockSize {
		w := *(*aes.Block)(message[i : i+blockSize])
		g, h = mjhCompress(&g, &h, &w)
	}
	return g, h
}
