//go:build ignore

package main

import (
	"bytes"
	"fmt"

	"github.com/jedisct1/go-aes/examples/butterrng"
)

func main() {
	fmt.Println("=== ButterKnife Fast-Key-Erasure RNG ===")

	var seed [butterrng.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	rng, err := butterrng.New(seed[:])
	if err != nil {
		panic(err)
	}

	out := make([]byte, 64)
	rng.Fill(out)

	fmt.Printf("Seed size:          %d bytes\n", butterrng.SeedSize)
	fmt.Printf("Refill output:      %d bytes\n", butterrng.BufferSize)
	fmt.Printf("First 64 bytes:     %x\n", out)

	chunked, err := butterrng.New(seed[:])
	if err != nil {
		panic(err)
	}
	a := make([]byte, 17)
	b := make([]byte, 47)
	chunked.Fill(a)
	chunked.Fill(b)

	fmt.Printf("Chunked matches:    %v\n", bytes.Equal(out, append(a, b...)))
}
