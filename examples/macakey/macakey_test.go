package macakey

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

var testKey = make([]byte, KeySize)
var testIV = make([]byte, IVSize)

func init() {
	for i := range testKey {
		testKey[i] = byte(i)
	}
	for i := range testIV {
		testIV[i] = byte(0x80 + i)
	}
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out
}

func pad(m []byte) []byte {
	p := append(bytes.Clone(m), 0x80)
	for len(p)%BlockSize != 0 {
		p = append(p, 0)
	}
	return p
}

func tag(t *testing.T, msg []byte, n int) []byte {
	t.Helper()
	out, err := KeyMacaKey(testKey, msg, n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newContext(t *testing.T) *KeyMacaKeyContext {
	t.Helper()
	ctx, err := NewKeyMacaKeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

// reference is a direct transcription of Algorithm 2 of ePrint 2025/2038, written separately from the streaming code. Without addKey, it computes MacaKey instead.
func reference(key, iv, message []byte, n int, addKey bool) []byte {
	p := func(input []byte) (y, z []byte) {
		var s aes.Areion512
		copy(s[:], input)
		s.Permute()
		return bytes.Clone(s[:rateSize]), bytes.Clone(s[rateSize:])
	}

	y, z := p(slices.Concat(key, iv))

	padded := pad(message)
	m := len(padded) / BlockSize

	var w []byte
	for j := 1; j <= m; j++ {
		mj := padded[(j-1)*BlockSize : j*BlockSize]
		if j == m && addKey {
			mj = xorBytes(mj, slices.Concat(make([]byte, BlockSize-KeySize), key))
		}
		var x []byte
		x, w = xorBytes(y, mj[:rateSize]), xorBytes(z, mj[rateSize:])
		y, z = p(slices.Concat(x, w))
	}

	t := slices.Concat(xorBytes(w, z), y)
	l := (n + BlockSize - 1) / BlockSize
	for range l {
		w = z
		y, z = p(slices.Concat(y, z))
		t = slices.Concat(t, xorBytes(w, z), y)
	}
	return t[:n]
}

func TestMatchesReference(t *testing.T) {
	msgLens := []int{0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 200, 1000}
	outLens := []int{1, 16, 31, 32, 33, 63, 64, 65, 100, 128, 129, 300}
	for _, msgLen := range msgLens {
		msg := make([]byte, msgLen)
		for i := range msg {
			msg[i] = byte(i*7 + 3)
		}
		for _, outLen := range outLens {
			got, err := KeyMacaKeyWithIV(testKey, testIV, msg, outLen)
			if err != nil {
				t.Fatal(err)
			}
			if want := reference(testKey, testIV, msg, outLen, true); !bytes.Equal(got, want) {
				t.Fatalf("msgLen=%d outLen=%d\ngot:  %x\nwant: %x", msgLen, outLen, got, want)
			}
		}
	}
}

// These outputs were recorded once the code matched the reference. They catch accidental changes.
func TestRegressionVectors(t *testing.T) {
	vectors := []struct {
		msg  string
		iv   []byte
		want string
	}{
		{"", zeroIV[:], "f1cdca78a899ba742deb23951cf760438de59aec98cf391e98a6eee79be50cfd98c6e5a87f09bce95928c1bb0bf0f8662d2d842777213c6092c4aee398565328df249fd83aff7c34e0b0efedc4f98b78376c769a67bf3d4e86b10550db8516ed"},
		{"KeyMacaKey with Areion512", testIV, "15173392a682968d3ad285ca622025d31bd745f69d14435b54dc263359ff5d498eddb984fc4d76d44b9c86c02feee1681c49d985a89d31b8cd6e350eb574f812d6dde598b54581be75548069b89c2fc00dd79ac4e35a142dbf2cc610bb9eb69b"},
	}
	for _, v := range vectors {
		got, err := KeyMacaKeyWithIV(testKey, v.iv, []byte(v.msg), 96)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != v.want {
			t.Errorf("msg=%q\ngot:  %x\nwant: %s", v.msg, got, v.want)
		}
	}
}

// fourQueryForgery runs the attack from Section 3.2 of ePrint 2025/2038, and reports whether it forged a tag.
func fourQueryForgery(mac func(message []byte, n int) []byte) bool {
	m1 := []byte{}
	m2 := []byte("a different one-block message")
	p1, p2 := pad(m1), pad(m2)

	t1, t2 := mac(m1, BlockSize), mac(m2, BlockSize)
	tr1, tl1 := t1[:capacitySize], t1[capacitySize:]
	tr2, tl2 := t2[:capacitySize], t2[capacitySize:]

	// TR1 ^ TR2 also includes the inner halves of the padded blocks. They are public, so we cancel them.
	d := xorBytes(xorBytes(tr1, tr2), xorBytes(p1[rateSize:], p2[rateSize:]))
	mPrime := bytes.Repeat([]byte{0x5a}, capacitySize)

	m3 := slices.Concat(p1, tl2, mPrime)
	m4 := slices.Concat(p2, tl1, xorBytes(mPrime, d))
	return bytes.Equal(mac(m3, BlockSize), mac(m4, BlockSize))
}

// extensionForgery absorbs a zero block to replay a squeezing call, and reports whether it forged a tag. It works when both phases share one permutation, unless the last block is keyed.
func extensionForgery(mac func(message []byte, n int) []byte) bool {
	out := mac(nil, 2*BlockSize)
	y1, y2 := out[capacitySize:BlockSize], out[BlockSize+capacitySize:]
	stateDiff := slices.Concat(xorBytes(y1, y2), out[BlockSize:BlockSize+capacitySize])

	x := bytes.Repeat([]byte{0xa5}, BlockSize)
	b := slices.Concat(pad(nil), x)
	c := slices.Concat(pad(nil), make([]byte, BlockSize), xorBytes(x, stateDiff))
	return bytes.Equal(mac(b, BlockSize), mac(c, BlockSize))
}

func TestAttacksFail(t *testing.T) {
	keyMacaKey := func(message []byte, n int) []byte { return tag(t, message, n) }
	macaKey := func(message []byte, n int) []byte { return reference(testKey, zeroIV[:], message, n, false) }

	if !fourQueryForgery(macaKey) || !extensionForgery(macaKey) {
		t.Fatal("the attacks should forge tags when the last block is not keyed")
	}
	if fourQueryForgery(keyMacaKey) {
		t.Error("four-query attack forged a KeyMacaKey tag")
	}
	if extensionForgery(keyMacaKey) {
		t.Error("extension attack forged a KeyMacaKey tag")
	}
}

func TestStreamingWrite(t *testing.T) {
	msg := make([]byte, 300)
	for i := range msg {
		msg[i] = byte(i)
	}
	want := tag(t, msg, 100)

	for _, chunkSize := range []int{1, 7, 63, 64, 65, 128, 299} {
		ctx := newContext(t)
		for chunk := range slices.Chunk(msg, chunkSize) {
			ctx.Write(chunk)
		}
		if !bytes.Equal(ctx.Sum(100), want) {
			t.Errorf("chunkSize=%d: writing in pieces changed the output", chunkSize)
		}
	}
}

func TestStreamingRead(t *testing.T) {
	msg := []byte("test message for streaming read")
	want := tag(t, msg, 200)

	ctx := newContext(t)
	ctx.Write(msg)
	var got []byte
	for _, n := range []int{1, 15, 16, 32, 0, 63} {
		chunk := make([]byte, n)
		ctx.Read(chunk)
		got = append(got, chunk...)
	}
	got = append(got, ctx.Sum(73)...)
	if !bytes.Equal(got, want) {
		t.Error("reading in pieces changed the output")
	}
}

func TestClone(t *testing.T) {
	ctx := newContext(t)
	ctx.Write([]byte("prefix"))
	beforeRead := ctx.Clone()
	branch := ctx.Clone()

	out := ctx.Sum(40)
	if !bytes.Equal(beforeRead.Sum(40), out) {
		t.Error("a clone should give the same output")
	}
	midStream := ctx.Clone()
	if !bytes.Equal(midStream.Sum(40), ctx.Sum(40)) {
		t.Error("a clone made while reading should continue the same output")
	}
	branch.Write([]byte("suffix"))
	if bytes.Equal(branch.Sum(40), out) {
		t.Error("a clone should absorb data on its own")
	}
}

func TestWriteAfterRead(t *testing.T) {
	ctx := newContext(t)
	ctx.Sum(32)
	if _, err := ctx.Write([]byte("more")); err != ErrWriteAfterRead {
		t.Errorf("expected ErrWriteAfterRead, got %v", err)
	}
}

func TestReset(t *testing.T) {
	msg := []byte("test message")
	want := tag(t, msg, 32)

	ctx := newContext(t)
	ctx.Write([]byte("data to forget"))
	ctx.Sum(32)
	ctx.Reset()
	if _, err := ctx.Write(msg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Sum(32), want) {
		t.Error("Reset should go back to the initial state")
	}
}

func TestKeyAndIVValidation(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := NewKeyMacaKeyContext(make([]byte, n)); err != ErrInvalidKey {
			t.Errorf("key of %d bytes: expected ErrInvalidKey, got %v", n, err)
		}
		if _, err := KeyMacaKeyWithIV(testKey, make([]byte, n), nil, 32); err != ErrInvalidIV {
			t.Errorf("IV of %d bytes: expected ErrInvalidIV, got %v", n, err)
		}
	}
}

// The reference uses the same padding, so this checks that the padding itself keeps messages apart.
func TestPaddingIsInjective(t *testing.T) {
	seen := map[string]int{}
	for _, n := range []int{0, 63, 64, 65, 128} {
		out := string(tag(t, make([]byte, n), 32))
		if prev, ok := seen[out]; ok {
			t.Errorf("%d and %d zero bytes give the same output", prev, n)
		}
		seen[out] = n
	}
}

func TestNonPositiveOutputLen(t *testing.T) {
	for _, n := range []int{-1, 0} {
		if out := tag(t, []byte("test"), n); out != nil {
			t.Errorf("outputLen=%d should return nil", n)
		}
	}
}

func BenchmarkKeyMacaKey(b *testing.B) {
	for _, size := range []int{64, 1024, 4096} {
		msg := make([]byte, size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				KeyMacaKey(testKey, msg, 32)
			}
		})
	}
}

func BenchmarkKeyMacaKeyOutput1KB(b *testing.B) {
	msg := make([]byte, 64)
	b.SetBytes(1024)
	for b.Loop() {
		KeyMacaKey(testKey, msg, 1024)
	}
}
