package spongef

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSpongeFVectors(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		len  int
		want string
	}{
		{
			name: "empty-32",
			msg:  []byte{},
			len:  32,
			want: "9ae8e7b2d2f8ece36356bc363c5dce3cf73259fee9277f9f4e1cf4683be1bcb3",
		},
		{
			name: "abc-32",
			msg:  []byte("abc"),
			len:  32,
			want: "e05c6dabaa3d0415d6865b224f7740946072a276ffb35ac288f6ce006c781b34",
		},
		{
			name: "abc-64",
			msg:  []byte("abc"),
			len:  64,
			want: "e05c6dabaa3d0415d6865b224f7740946072a276ffb35ac288f6ce006c781b3499fb094d9da09639795f4a528a3d31cf1097901b35edf9678d7cb60c6e06199a",
		},
	}

	for _, tc := range tests {
		out, err := SpongeF(tc.msg, tc.len)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		want, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatalf("%s: bad test vector: %v", tc.name, err)
		}
		if !bytes.Equal(out, want) {
			t.Fatalf("%s: output mismatch\ngot  %x\nwant %x", tc.name, out, want)
		}
	}
}

func TestSpongeFOutputLengthValidation(t *testing.T) {
	_, err := SpongeF([]byte("abc"), MinOutputSize-1)
	if err != ErrOutputTooShort {
		t.Fatalf("expected ErrOutputTooShort, got %v", err)
	}
}

func TestSpongeFIVValidation(t *testing.T) {
	_, err := NewSpongeFContextWithIV(make([]byte, IVSize-1))
	if err != ErrInvalidIV {
		t.Fatalf("expected ErrInvalidIV, got %v", err)
	}
}

func TestSpongeFDeterministic(t *testing.T) {
	msg := []byte("abc")
	out1, err := SpongeF(msg, 64)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := SpongeF(msg, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("SpongeF should be deterministic")
	}
}

func TestSpongeFStreamingMatchesOneShot(t *testing.T) {
	msg := make([]byte, 200)
	for i := range msg {
		msg[i] = byte(i)
	}

	oneShot, err := SpongeF(msg, 96)
	if err != nil {
		t.Fatal(err)
	}

	ctx := NewSpongeFContext()
	if _, err := ctx.Write(msg[:17]); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Write(msg[17:93]); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Write(msg[93:]); err != nil {
		t.Fatal(err)
	}
	streamed := ctx.Sum(96)

	if !bytes.Equal(oneShot, streamed) {
		t.Fatal("streaming and one-shot outputs should match")
	}
}

func TestSpongeFStreamingRead(t *testing.T) {
	msg := []byte("test message for incremental reads")

	full, err := SpongeF(msg, 80)
	if err != nil {
		t.Fatal(err)
	}

	ctx := NewSpongeFContext()
	if _, err := ctx.Write(msg); err != nil {
		t.Fatal(err)
	}

	var chunked [80]byte
	if _, err := ctx.Read(chunked[0:13]); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Read(chunked[13:47]); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Read(chunked[47:]); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(full, chunked[:]) {
		t.Fatal("chunked reads should match one-shot output")
	}
}

func TestWriteAfterRead(t *testing.T) {
	ctx := NewSpongeFContext()
	if _, err := ctx.Write([]byte("message")); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := ctx.Write([]byte("more")); err != ErrWriteAfterRead {
		t.Fatalf("expected ErrWriteAfterRead, got %v", err)
	}
}

func TestClone(t *testing.T) {
	ctx := NewSpongeFContext()
	if _, err := ctx.Write([]byte("prefix")); err != nil {
		t.Fatal(err)
	}

	clone := ctx.Clone()

	if _, err := ctx.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := clone.Write([]byte("B")); err != nil {
		t.Fatal(err)
	}

	out1 := ctx.Sum(64)
	out2 := clone.Sum(64)

	if bytes.Equal(out1, out2) {
		t.Fatal("cloned contexts should evolve independently")
	}
}

func TestIVChangesOutput(t *testing.T) {
	msg := []byte("same message")

	out1, err := SpongeF(msg, 64)
	if err != nil {
		t.Fatal(err)
	}

	customIV := make([]byte, IVSize)
	for i := range customIV {
		customIV[i] = byte(i + 1)
	}
	out2, err := SpongeFWithIV(customIV, msg, 64)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(out1, out2) {
		t.Fatal("different IVs should produce different outputs")
	}
}
