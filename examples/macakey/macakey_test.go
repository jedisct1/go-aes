package macakey

import (
	"bytes"
	"testing"
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

func TestEmptyMessage(t *testing.T) {
	out, err := Macakey(testKey, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}

	out2, err := Macakey(testKey, []byte{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Error("nil and empty slice should produce same output")
	}
}

func TestExactAbsorbSize(t *testing.T) {
	msg := make([]byte, AbsorbSize)
	for i := range msg {
		msg[i] = byte(i)
	}

	out, err := Macakey(testKey, msg, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}

	out2, err := Macakey(testKey, msg, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Error("same input should produce same output")
	}
}

func TestMultiBlock(t *testing.T) {
	msg := make([]byte, 3*AbsorbSize+17)
	for i := range msg {
		msg[i] = byte(i * 7)
	}

	out, err := Macakey(testKey, msg, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(out))
	}
}

func TestStreamingWrite(t *testing.T) {
	msg := make([]byte, 200)
	for i := range msg {
		msg[i] = byte(i)
	}

	oneShot, err := Macakey(testKey, msg, 32)
	if err != nil {
		t.Fatal(err)
	}

	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write(msg[:50])
	ctx.Write(msg[50:120])
	ctx.Write(msg[120:])
	streamed := ctx.Sum(32)

	if !bytes.Equal(oneShot, streamed) {
		t.Error("streaming write should produce same result as one-shot")
	}
}

func TestStreamingRead(t *testing.T) {
	msg := []byte("test message for streaming read")

	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write(msg)

	out1 := make([]byte, 16)
	ctx.Read(out1)
	out2 := make([]byte, 16)
	ctx.Read(out2)

	fullCtx, _ := NewMacakeyContext(testKey)
	fullCtx.Write(msg)
	full := fullCtx.Sum(32)

	combined := append(out1, out2...)
	if !bytes.Equal(full, combined) {
		t.Error("streaming read should produce same bytes as full read")
	}
}

func TestSumAdvancesStream(t *testing.T) {
	msg := []byte("test message")

	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write(msg)

	first := ctx.Sum(32)
	second := ctx.Sum(32)

	if bytes.Equal(first, second) {
		t.Error("consecutive Sum calls should return different bytes (stream advances)")
	}

	full, _ := Macakey(testKey, msg, 64)
	if !bytes.Equal(first, full[:32]) {
		t.Error("first Sum should match first 32 bytes")
	}
	if !bytes.Equal(second, full[32:64]) {
		t.Error("second Sum should match bytes 32-63")
	}
}

func TestCloneSnapshot(t *testing.T) {
	msg := []byte("test message for cloning")

	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write(msg)

	clone := ctx.Clone()

	origOut := ctx.Sum(32)
	cloneOut := clone.Sum(32)

	if !bytes.Equal(origOut, cloneOut) {
		t.Error("clone should produce same output as original at clone point")
	}

	ctx.Sum(32)
	cloneOut2 := clone.Sum(32)

	if bytes.Equal(origOut, cloneOut2) {
		t.Error("clone should advance independently")
	}
}

func TestCloneBeforeWrite(t *testing.T) {
	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write([]byte("prefix"))

	clone := ctx.Clone()

	ctx.Write([]byte("suffix1"))
	clone.Write([]byte("suffix2"))

	out1 := ctx.Sum(32)
	out2 := clone.Sum(32)

	if bytes.Equal(out1, out2) {
		t.Error("different suffixes should produce different outputs")
	}
}

func TestWriteAfterReadError(t *testing.T) {
	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write([]byte("message"))
	ctx.Sum(32)

	_, writeErr := ctx.Write([]byte("more"))
	if writeErr != ErrWriteAfterRead {
		t.Errorf("expected ErrWriteAfterRead, got %v", writeErr)
	}
}

func TestReset(t *testing.T) {
	msg := []byte("test message")

	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write(msg)
	first := ctx.Sum(32)

	ctx.Reset()
	ctx.Write(msg)
	second := ctx.Sum(32)

	if !bytes.Equal(first, second) {
		t.Error("reset should allow reproducing same output")
	}
}

func TestResetAfterRead(t *testing.T) {
	ctx, err := NewMacakeyContext(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Write([]byte("message"))
	ctx.Sum(32)

	if !ctx.squeezing {
		t.Error("should be squeezing after Sum")
	}

	ctx.Reset()

	if ctx.squeezing {
		t.Error("should not be squeezing after Reset")
	}

	_, err = ctx.Write([]byte("new message"))
	if err != nil {
		t.Error("should be able to write after Reset")
	}
}

func TestWithIV(t *testing.T) {
	msg := []byte("test message")

	out1, err := MacakeyWithIV(testKey, testIV, msg, 32)
	if err != nil {
		t.Fatal(err)
	}

	zeroIV := make([]byte, IVSize)
	out2, err := MacakeyWithIV(testKey, zeroIV, msg, 32)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(out1, out2) {
		t.Error("different IVs should produce different outputs")
	}

	out3, _ := Macakey(testKey, msg, 32)
	if !bytes.Equal(out2, out3) {
		t.Error("zero IV should match default (no IV) behavior")
	}
}

func TestLargeOutput(t *testing.T) {
	msg := []byte("short message")
	outputLen := 1024

	out, err := Macakey(testKey, msg, outputLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != outputLen {
		t.Errorf("expected %d bytes, got %d", outputLen, len(out))
	}

	allZero := true
	for _, b := range out {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("output should not be all zeros")
	}
}

func TestKeyValidation(t *testing.T) {
	_, err := NewMacakeyContext(make([]byte, 16))
	if err == nil {
		t.Error("should reject 16-byte key")
	}

	_, err = NewMacakeyContext(make([]byte, 64))
	if err == nil {
		t.Error("should reject 64-byte key")
	}
}

func TestIVValidation(t *testing.T) {
	_, err := NewMacakeyContextWithIV(testKey, make([]byte, 16))
	if err == nil {
		t.Error("should reject 16-byte IV")
	}
}

func TestDifferentMessages(t *testing.T) {
	out1, _ := Macakey(testKey, []byte("message1"), 32)
	out2, _ := Macakey(testKey, []byte("message2"), 32)

	if bytes.Equal(out1, out2) {
		t.Error("different messages should produce different outputs")
	}
}

func TestDifferentKeys(t *testing.T) {
	key2 := make([]byte, KeySize)
	copy(key2, testKey)
	key2[0] ^= 1

	msg := []byte("test message")
	out1, _ := Macakey(testKey, msg, 32)
	out2, _ := Macakey(key2, msg, 32)

	if bytes.Equal(out1, out2) {
		t.Error("different keys should produce different outputs")
	}
}

func TestPaddingEdgeCases(t *testing.T) {
	msg62 := make([]byte, AbsorbSize-1)
	msg63 := make([]byte, AbsorbSize)
	msg64 := make([]byte, AbsorbSize+1)

	out62, _ := Macakey(testKey, msg62, 32)
	out63, _ := Macakey(testKey, msg63, 32)
	out64, _ := Macakey(testKey, msg64, 32)

	if bytes.Equal(out62, out63) || bytes.Equal(out63, out64) || bytes.Equal(out62, out64) {
		t.Error("different length messages should produce different outputs")
	}
}

func TestNegativeOutputLen(t *testing.T) {
	out, err := Macakey(testKey, []byte("test"), -1)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("negative outputLen should return nil")
	}

	out, _ = Macakey(testKey, []byte("test"), 0)
	if out != nil {
		t.Error("zero outputLen should return nil")
	}
}

func TestDomainSeparationNoCollision(t *testing.T) {
	// With NCP-based domain separation, full 64-byte absorption is preserved.
	// Squeeze permutation inputs have XOR'd constant in capacity, making them
	// distinct from absorb permutation inputs.

	msg1 := make([]byte, 64)
	msg2 := make([]byte, 64)
	for i := range msg1 {
		msg1[i] = byte(i)
		msg2[i] = byte(i)
	}
	// Messages are identical - should produce same output
	out1, _ := Macakey(testKey, msg1, 32)
	out2, _ := Macakey(testKey, msg2, 32)
	if !bytes.Equal(out1, out2) {
		t.Error("identical messages should produce identical output")
	}

	// Different messages (including byte 63) should produce different output
	msg2[63] ^= 1
	out3, _ := Macakey(testKey, msg2, 32)
	if bytes.Equal(out1, out3) {
		t.Error("different messages should produce different output")
	}
}

func TestFullIVUsage(t *testing.T) {
	// Verify that all 32 bytes of IV are used, including the last byte.
	// This was a bug when reserved-bit domain separation used only 31 bytes.
	msg := []byte("test message")

	iv1 := make([]byte, IVSize)
	iv2 := make([]byte, IVSize)
	for i := range iv1 {
		iv1[i] = byte(i)
		iv2[i] = byte(i)
	}
	// IVs differ only in the last byte
	iv2[31] ^= 1

	out1, _ := MacakeyWithIV(testKey, iv1, msg, 32)
	out2, _ := MacakeyWithIV(testKey, iv2, msg, 32)

	if bytes.Equal(out1, out2) {
		t.Error("IVs differing only in last byte should produce different outputs")
	}
}

func TestStreamingMemoryEfficiency(t *testing.T) {
	// Verify that Write processes blocks directly without buffering all data.
	// We can't directly test memory, but we can verify the buffer never
	// exceeds AbsorbSize.
	ctx, _ := NewMacakeyContext(testKey)

	// Write more than one block in pieces
	chunk := make([]byte, 100)
	for range 10 {
		ctx.Write(chunk)
		if ctx.bufLen >= AbsorbSize {
			t.Errorf("buffer should never reach AbsorbSize, got %d", ctx.bufLen)
		}
	}
}

func BenchmarkMacakey64B(b *testing.B) {
	msg := make([]byte, 64)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for b.Loop() {
		Macakey(testKey, msg, 32)
	}
}

func BenchmarkMacakey1KB(b *testing.B) {
	msg := make([]byte, 1024)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for b.Loop() {
		Macakey(testKey, msg, 32)
	}
}

func BenchmarkMacakey4KB(b *testing.B) {
	msg := make([]byte, 4096)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for b.Loop() {
		Macakey(testKey, msg, 32)
	}
}

func BenchmarkMacakeyOutput1KB(b *testing.B) {
	msg := make([]byte, 64)
	b.SetBytes(1024)
	b.ResetTimer()
	for b.Loop() {
		Macakey(testKey, msg, 1024)
	}
}

func BenchmarkMacakeyStreaming(b *testing.B) {
	chunks := make([][]byte, 16)
	for i := range chunks {
		chunks[i] = make([]byte, 64)
	}
	b.SetBytes(int64(16 * 64))
	b.ResetTimer()
	for b.Loop() {
		ctx, _ := NewMacakeyContext(testKey)
		for _, chunk := range chunks {
			ctx.Write(chunk)
		}
		ctx.Sum(32)
	}
}
