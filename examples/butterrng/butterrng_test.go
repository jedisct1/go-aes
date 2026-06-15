package butterrng

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

var _ io.Reader = (*RNG)(nil)

func testSeed(delta byte) [SeedSize]byte {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i) + delta
	}
	return seed
}

func mustNew(t testing.TB, seed [SeedSize]byte) *RNG {
	t.Helper()
	rng, err := New(seed[:])
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return rng
}

func hasNonZero(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return true
		}
	}
	return false
}

func TestNewRejectsWrongSeedSize(t *testing.T) {
	if _, err := New(make([]byte, SeedSize-1)); !errors.Is(err, ErrInvalidSeedSize) {
		t.Fatalf("expected ErrInvalidSeedSize for short seed, got %v", err)
	}
	if _, err := New(make([]byte, SeedSize+1)); !errors.Is(err, ErrInvalidSeedSize) {
		t.Fatalf("expected ErrInvalidSeedSize for long seed, got %v", err)
	}
}

func TestDeterministicFromSeed(t *testing.T) {
	seed := testSeed(0)
	rng1 := mustNew(t, seed)
	rng2 := mustNew(t, seed)

	out1 := make([]byte, BufferSize*2+37)
	out2 := make([]byte, len(out1))
	rng1.Fill(out1)
	rng2.Fill(out2)

	if !bytes.Equal(out1, out2) {
		t.Fatal("same seed produced different streams")
	}
	if !hasNonZero(out1) {
		t.Fatal("stream is all zero")
	}
}

func TestKnownFirstBytes(t *testing.T) {
	rng := mustNew(t, testSeed(0))
	out := make([]byte, 64)
	rng.Fill(out)

	want, err := hex.DecodeString("845b731136a82171af96d89f3524e36052090a61092c9286f7ffd4d837b9419d93a5377fdda939516ca70744a505bd0398f9b487a9d6fe41084cba4ecac9bec3")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("first output bytes changed\ngot:  %x\nwant: %x", out, want)
	}
}

func TestDifferentSeedsProduceDifferentStreams(t *testing.T) {
	rng1 := mustNew(t, testSeed(0))
	rng2 := mustNew(t, testSeed(1))

	out1 := make([]byte, 128)
	out2 := make([]byte, len(out1))
	rng1.Fill(out1)
	rng2.Fill(out2)

	if bytes.Equal(out1, out2) {
		t.Fatal("different seeds produced the same stream")
	}
}

func TestChunkedReadsMatchSingleRead(t *testing.T) {
	seed := testSeed(3)
	rng1 := mustNew(t, seed)
	rng2 := mustNew(t, seed)

	want := make([]byte, BufferSize*2+129)
	got := make([]byte, len(want))
	rng1.Fill(want)

	chunks := []int{1, 7, 31, 128, 3, BufferSize - 11, 64, 513}
	offset := 0
	for offset < len(got) {
		size := chunks[offset%len(chunks)]
		if size > len(got)-offset {
			size = len(got) - offset
		}
		rng2.Fill(got[offset : offset+size])
		offset += size
	}

	if !bytes.Equal(got, want) {
		t.Fatal("chunked reads differ from single read")
	}
}

func TestReadImplementsReader(t *testing.T) {
	rng := mustNew(t, testSeed(5))
	out := make([]byte, 257)

	n, err := io.ReadFull(rng, out)
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if n != len(out) {
		t.Fatalf("ReadFull returned %d bytes, want %d", n, len(out))
	}
	if !hasNonZero(out) {
		t.Fatal("Read returned all-zero output")
	}
}

func TestNewFromReader(t *testing.T) {
	seed := testSeed(9)
	rng, err := NewFromReader(bytes.NewReader(seed[:]))
	if err != nil {
		t.Fatalf("NewFromReader failed: %v", err)
	}

	out := make([]byte, 64)
	rng.Fill(out)
	if !hasNonZero(out) {
		t.Fatal("NewFromReader stream is all zero")
	}

	if _, err := NewFromReader(bytes.NewReader(seed[:SeedSize-1])); err == nil {
		t.Fatal("expected an error for a short reader")
	}
}

func TestConsumedBufferBytesAreCleared(t *testing.T) {
	rng := mustNew(t, testSeed(11))
	out := make([]byte, 31)
	rng.Fill(out)

	if rng.n != BufferSize {
		t.Fatalf("buffer length = %d, want %d", rng.n, BufferSize)
	}
	if rng.off != len(out) {
		t.Fatalf("buffer offset = %d, want %d", rng.off, len(out))
	}
	if hasNonZero(rng.buffer[:len(out)]) {
		t.Fatal("consumed buffer bytes were not cleared")
	}
	if !hasNonZero(rng.buffer[len(out):rng.n]) {
		t.Fatal("unconsumed buffer unexpectedly all zero")
	}
}

func TestRefillRekeys(t *testing.T) {
	seed := testSeed(13)
	rng := mustNew(t, seed)

	out := make([]byte, BufferSize)
	rng.Fill(out)

	if bytes.Equal(rng.key[:], seed[:]) {
		t.Fatal("state key did not change after refill")
	}
	if rng.off != 0 || rng.n != 0 {
		t.Fatalf("buffer state after exact refill drain = off %d n %d, want 0 0", rng.off, rng.n)
	}
	if hasNonZero(rng.buffer[:]) {
		t.Fatal("buffer was not cleared after exact drain")
	}
}

func benchmarkFill(b *testing.B, size int) {
	rng := mustNew(b, testSeed(17))
	out := make([]byte, size)

	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rng.Fill(out)
	}
}

func BenchmarkFill32(b *testing.B)   { benchmarkFill(b, 32) }
func BenchmarkFill1024(b *testing.B) { benchmarkFill(b, 1024) }
func BenchmarkFill64K(b *testing.B)  { benchmarkFill(b, 64*1024) }
