package aes

import "unsafe"

// Block represents a 128-bit AES block (16 bytes)
type Block [16]byte

// Pointers to S-box arrays for bounds-check-free access
var (
	sboxPtr    = unsafe.Pointer(&sbox[0])
	invSboxPtr = unsafe.Pointer(&invSbox[0])
)

// AES S-box (SubBytes transformation)
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// Inverse S-box (InvSubBytes transformation)
var invSbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Round constants for key expansion
var rcon = [11]byte{0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

func gfMul2(b byte) byte {
	return (b << 1) ^ (0x1b & -((b >> 7) & 1))
}

func gfMul3(b byte) byte {
	return gfMul2(b) ^ b
}

func gfMul4(b byte) byte {
	return gfMul2(gfMul2(b))
}

func gfMul8(b byte) byte {
	return gfMul2(gfMul4(b))
}

func gfMul9(b byte) byte {
	return gfMul8(b) ^ b
}

func gfMul11(b byte) byte {
	return gfMul8(b) ^ gfMul2(b) ^ b
}

func gfMul13(b byte) byte {
	return gfMul8(b) ^ gfMul4(b) ^ b
}

func gfMul14(b byte) byte {
	return gfMul8(b) ^ gfMul4(b) ^ gfMul2(b)
}

// SubBytes applies the AES S-box substitution to each byte.
func SubBytes(block *Block) {
	p := unsafe.Pointer(block)
	for i := uintptr(0); i < 16; i++ {
		bp := (*byte)(unsafe.Add(p, i))
		*bp = *(*byte)(unsafe.Add(sboxPtr, uintptr(*bp)))
	}
}

// InvSubBytes applies the inverse AES S-box substitution.
func InvSubBytes(block *Block) {
	p := unsafe.Pointer(block)
	for i := uintptr(0); i < 16; i++ {
		bp := (*byte)(unsafe.Add(p, i))
		*bp = *(*byte)(unsafe.Add(invSboxPtr, uintptr(*bp)))
	}
}

// ShiftRows cyclically shifts bytes in each row (0,1,2,3 bytes respectively).
func ShiftRows(block *Block) {
	block[1], block[5], block[9], block[13] = block[5], block[9], block[13], block[1]
	block[2], block[6], block[10], block[14] = block[10], block[14], block[2], block[6]
	block[3], block[7], block[11], block[15] = block[15], block[3], block[7], block[11]
}

// InvShiftRows is the inverse of ShiftRows.
func InvShiftRows(block *Block) {
	block[1], block[5], block[9], block[13] = block[13], block[1], block[5], block[9]
	block[2], block[6], block[10], block[14] = block[10], block[14], block[2], block[6]
	block[3], block[7], block[11], block[15] = block[7], block[11], block[15], block[3]
}

// MixColumns mixes bytes within each column using GF(2^8) multiplication.
func MixColumns(block *Block) {
	s0, s1, s2, s3 := block[0], block[1], block[2], block[3]
	block[0] = gfMul2(s0) ^ gfMul3(s1) ^ s2 ^ s3
	block[1] = s0 ^ gfMul2(s1) ^ gfMul3(s2) ^ s3
	block[2] = s0 ^ s1 ^ gfMul2(s2) ^ gfMul3(s3)
	block[3] = gfMul3(s0) ^ s1 ^ s2 ^ gfMul2(s3)
	s0, s1, s2, s3 = block[4], block[5], block[6], block[7]
	block[4] = gfMul2(s0) ^ gfMul3(s1) ^ s2 ^ s3
	block[5] = s0 ^ gfMul2(s1) ^ gfMul3(s2) ^ s3
	block[6] = s0 ^ s1 ^ gfMul2(s2) ^ gfMul3(s3)
	block[7] = gfMul3(s0) ^ s1 ^ s2 ^ gfMul2(s3)
	s0, s1, s2, s3 = block[8], block[9], block[10], block[11]
	block[8] = gfMul2(s0) ^ gfMul3(s1) ^ s2 ^ s3
	block[9] = s0 ^ gfMul2(s1) ^ gfMul3(s2) ^ s3
	block[10] = s0 ^ s1 ^ gfMul2(s2) ^ gfMul3(s3)
	block[11] = gfMul3(s0) ^ s1 ^ s2 ^ gfMul2(s3)
	s0, s1, s2, s3 = block[12], block[13], block[14], block[15]
	block[12] = gfMul2(s0) ^ gfMul3(s1) ^ s2 ^ s3
	block[13] = s0 ^ gfMul2(s1) ^ gfMul3(s2) ^ s3
	block[14] = s0 ^ s1 ^ gfMul2(s2) ^ gfMul3(s3)
	block[15] = gfMul3(s0) ^ s1 ^ s2 ^ gfMul2(s3)
}

// InvMixColumns is the inverse of MixColumns.
func InvMixColumns(block *Block) {
	s0, s1, s2, s3 := block[0], block[1], block[2], block[3]
	block[0] = gfMul14(s0) ^ gfMul11(s1) ^ gfMul13(s2) ^ gfMul9(s3)
	block[1] = gfMul9(s0) ^ gfMul14(s1) ^ gfMul11(s2) ^ gfMul13(s3)
	block[2] = gfMul13(s0) ^ gfMul9(s1) ^ gfMul14(s2) ^ gfMul11(s3)
	block[3] = gfMul11(s0) ^ gfMul13(s1) ^ gfMul9(s2) ^ gfMul14(s3)
	s0, s1, s2, s3 = block[4], block[5], block[6], block[7]
	block[4] = gfMul14(s0) ^ gfMul11(s1) ^ gfMul13(s2) ^ gfMul9(s3)
	block[5] = gfMul9(s0) ^ gfMul14(s1) ^ gfMul11(s2) ^ gfMul13(s3)
	block[6] = gfMul13(s0) ^ gfMul9(s1) ^ gfMul14(s2) ^ gfMul11(s3)
	block[7] = gfMul11(s0) ^ gfMul13(s1) ^ gfMul9(s2) ^ gfMul14(s3)
	s0, s1, s2, s3 = block[8], block[9], block[10], block[11]
	block[8] = gfMul14(s0) ^ gfMul11(s1) ^ gfMul13(s2) ^ gfMul9(s3)
	block[9] = gfMul9(s0) ^ gfMul14(s1) ^ gfMul11(s2) ^ gfMul13(s3)
	block[10] = gfMul13(s0) ^ gfMul9(s1) ^ gfMul14(s2) ^ gfMul11(s3)
	block[11] = gfMul11(s0) ^ gfMul13(s1) ^ gfMul9(s2) ^ gfMul14(s3)
	s0, s1, s2, s3 = block[12], block[13], block[14], block[15]
	block[12] = gfMul14(s0) ^ gfMul11(s1) ^ gfMul13(s2) ^ gfMul9(s3)
	block[13] = gfMul9(s0) ^ gfMul14(s1) ^ gfMul11(s2) ^ gfMul13(s3)
	block[14] = gfMul13(s0) ^ gfMul9(s1) ^ gfMul14(s2) ^ gfMul11(s3)
	block[15] = gfMul11(s0) ^ gfMul13(s1) ^ gfMul9(s2) ^ gfMul14(s3)
}

// AddRoundKey XORs the block with the round key.
func AddRoundKey(block *Block, roundKey *Block) {
	b := (*[2]uint64)(unsafe.Pointer(block))
	k := (*[2]uint64)(unsafe.Pointer(roundKey))
	b[0] ^= k[0]
	b[1] ^= k[1]
}

// Round performs SubBytes, ShiftRows, MixColumns, AddRoundKey.
func Round(block *Block, roundKey *Block) {
	SubBytes(block)
	ShiftRows(block)
	MixColumns(block)
	AddRoundKey(block, roundKey)
}

// FinalRound performs SubBytes, ShiftRows, AddRoundKey (no MixColumns).
func FinalRound(block *Block, roundKey *Block) {
	SubBytes(block)
	ShiftRows(block)
	AddRoundKey(block, roundKey)
}

// InvRound performs InvShiftRows, InvSubBytes, InvMixColumns, AddRoundKey.
func InvRound(block *Block, roundKey *Block) {
	InvShiftRows(block)
	InvSubBytes(block)
	InvMixColumns(block)
	AddRoundKey(block, roundKey)
}

// InvFinalRound performs InvShiftRows, InvSubBytes, AddRoundKey (no InvMixColumns).
func InvFinalRound(block *Block, roundKey *Block) {
	InvShiftRows(block)
	InvSubBytes(block)
	AddRoundKey(block, roundKey)
}

// RoundKeyFirst performs AddRoundKey, SubBytes, ShiftRows, MixColumns.
func RoundKeyFirst(block *Block, roundKey *Block) {
	AddRoundKey(block, roundKey)
	SubBytes(block)
	ShiftRows(block)
	MixColumns(block)
}

// FinalRoundKeyFirst performs AddRoundKey, SubBytes, ShiftRows (no MixColumns).
func FinalRoundKeyFirst(block *Block, roundKey *Block) {
	AddRoundKey(block, roundKey)
	SubBytes(block)
	ShiftRows(block)
}

// InvRoundKeyFirst performs InvMixColumns, InvShiftRows, InvSubBytes, AddRoundKey.
func InvRoundKeyFirst(block *Block, roundKey *Block) {
	InvMixColumns(block)
	InvShiftRows(block)
	InvSubBytes(block)
	AddRoundKey(block, roundKey)
}

// InvFinalRoundKeyFirst performs InvShiftRows, InvSubBytes, AddRoundKey.
func InvFinalRoundKeyFirst(block *Block, roundKey *Block) {
	InvShiftRows(block)
	InvSubBytes(block)
	AddRoundKey(block, roundKey)
}

// RoundNoKey performs SubBytes, ShiftRows, MixColumns (no key XOR).
func RoundNoKey(block *Block) {
	SubBytes(block)
	ShiftRows(block)
	MixColumns(block)
}

// FinalRoundNoKey performs SubBytes, ShiftRows (no key XOR or MixColumns).
func FinalRoundNoKey(block *Block) {
	SubBytes(block)
	ShiftRows(block)
}

// InvRoundNoKey performs InvMixColumns, InvShiftRows, InvSubBytes.
func InvRoundNoKey(block *Block) {
	InvMixColumns(block)
	InvShiftRows(block)
	InvSubBytes(block)
}

// InvFinalRoundNoKey performs InvShiftRows, InvSubBytes.
func InvFinalRoundNoKey(block *Block) {
	InvShiftRows(block)
	InvSubBytes(block)
}

// EncryptBlockAES128 performs complete AES-128 encryption.
func EncryptBlockAES128(block *Block, ks *KeySchedule) {
	if ks.Rounds() != 10 {
		panic("EncryptBlockAES128 requires AES-128 key schedule (10 rounds)")
	}

	// Initial AddRoundKey
	AddRoundKey(block, ks.GetRoundKey(0))

	// 9 full rounds + 1 final round using optimized multi-round
	var keys RoundKeys10
	for i := range 10 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}
	Rounds10WithFinalHW(block, &keys)
}

// EncryptBlockAES192 performs complete AES-192 encryption.
func EncryptBlockAES192(block *Block, ks *KeySchedule) {
	if ks.Rounds() != 12 {
		panic("EncryptBlockAES192 requires AES-192 key schedule (12 rounds)")
	}

	// Initial AddRoundKey
	AddRoundKey(block, ks.GetRoundKey(0))

	// 11 full rounds + 1 final round using optimized multi-round
	var keys RoundKeys12
	for i := range 12 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}
	Rounds12WithFinalHW(block, &keys)
}

// EncryptBlockAES256 performs complete AES-256 encryption.
func EncryptBlockAES256(block *Block, ks *KeySchedule) {
	if ks.Rounds() != 14 {
		panic("EncryptBlockAES256 requires AES-256 key schedule (14 rounds)")
	}

	// Initial AddRoundKey
	AddRoundKey(block, ks.GetRoundKey(0))

	// 13 full rounds + 1 final round using optimized multi-round
	var keys RoundKeys14
	for i := range 14 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}
	Rounds14WithFinalHW(block, &keys)
}

// EncryptBlockAES performs AES encryption with automatic key size detection.
func EncryptBlockAES(block *Block, ks *KeySchedule) {
	switch ks.Rounds() {
	case 10:
		EncryptBlockAES128(block, ks)
	case 12:
		EncryptBlockAES192(block, ks)
	case 14:
		EncryptBlockAES256(block, ks)
	default:
		panic("invalid key schedule rounds")
	}
}

// EncryptBlocksAES128 encrypts multiple blocks with AES-128.
func EncryptBlocksAES128(blocks []Block, ks *KeySchedule) {
	if ks.Rounds() != 10 {
		panic("EncryptBlocksAES128 requires AES-128 key schedule (10 rounds)")
	}

	n := len(blocks)
	if n == 0 {
		return
	}

	// Pre-compute round keys
	key0 := ks.GetRoundKey(0)
	var keys RoundKeys10
	for i := range 10 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}

	// Process 4 blocks at a time
	i := 0
	for ; i+4 <= n; i += 4 {
		// Cast slice to Block4 pointer
		block4 := (*Block4)(unsafe.Pointer(&blocks[i]))
		b0, b1, b2, b3 := block4Ptrs(block4)

		// Initial AddRoundKey
		AddRoundKey(b0, key0)
		AddRoundKey(b1, key0)
		AddRoundKey(b2, key0)
		AddRoundKey(b3, key0)

		// Apply rounds
		Rounds10WithFinal_4HW(block4, &keys)
	}

	// Process remaining blocks individually
	for ; i < n; i++ {
		AddRoundKey(&blocks[i], key0)
		Rounds10WithFinalHW(&blocks[i], &keys)
	}
}

// EncryptBlocksAES192 encrypts multiple blocks with AES-192.
func EncryptBlocksAES192(blocks []Block, ks *KeySchedule) {
	if ks.Rounds() != 12 {
		panic("EncryptBlocksAES192 requires AES-192 key schedule (12 rounds)")
	}

	n := len(blocks)
	if n == 0 {
		return
	}

	// Pre-compute round keys
	key0 := ks.GetRoundKey(0)
	var keys RoundKeys12
	for i := range 12 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}

	// Process 4 blocks at a time
	i := 0
	for ; i+4 <= n; i += 4 {
		block4 := (*Block4)(unsafe.Pointer(&blocks[i]))
		b0, b1, b2, b3 := block4Ptrs(block4)

		AddRoundKey(b0, key0)
		AddRoundKey(b1, key0)
		AddRoundKey(b2, key0)
		AddRoundKey(b3, key0)

		Rounds12WithFinal_4HW(block4, &keys)
	}

	// Process remaining blocks individually
	for ; i < n; i++ {
		AddRoundKey(&blocks[i], key0)
		Rounds12WithFinalHW(&blocks[i], &keys)
	}
}

// EncryptBlocksAES256 encrypts multiple blocks with AES-256.
func EncryptBlocksAES256(blocks []Block, ks *KeySchedule) {
	if ks.Rounds() != 14 {
		panic("EncryptBlocksAES256 requires AES-256 key schedule (14 rounds)")
	}

	n := len(blocks)
	if n == 0 {
		return
	}

	// Pre-compute round keys
	key0 := ks.GetRoundKey(0)
	var keys RoundKeys14
	for i := range 14 {
		keys[i] = *ks.GetRoundKey(i + 1)
	}

	// Process 4 blocks at a time
	i := 0
	for ; i+4 <= n; i += 4 {
		block4 := (*Block4)(unsafe.Pointer(&blocks[i]))
		b0, b1, b2, b3 := block4Ptrs(block4)

		AddRoundKey(b0, key0)
		AddRoundKey(b1, key0)
		AddRoundKey(b2, key0)
		AddRoundKey(b3, key0)

		Rounds14WithFinal_4HW(block4, &keys)
	}

	// Process remaining blocks individually
	for ; i < n; i++ {
		AddRoundKey(&blocks[i], key0)
		Rounds14WithFinalHW(&blocks[i], &keys)
	}
}

// XorBlock computes dst = a XOR b.
func XorBlock(dst, a, b *Block) {
	aPtr := (*[2]uint64)(unsafe.Pointer(a))
	bPtr := (*[2]uint64)(unsafe.Pointer(b))
	dstPtr := (*[2]uint64)(unsafe.Pointer(dst))
	dstPtr[0] = aPtr[0] ^ bPtr[0]
	dstPtr[1] = aPtr[1] ^ bPtr[1]
}

// XorBlock2 computes dst = a XOR b for Block2.
func XorBlock2(dst, a, b *Block2) {
	aPtr := (*[4]uint64)(unsafe.Pointer(a))
	bPtr := (*[4]uint64)(unsafe.Pointer(b))
	dstPtr := (*[4]uint64)(unsafe.Pointer(dst))
	dstPtr[0] = aPtr[0] ^ bPtr[0]
	dstPtr[1] = aPtr[1] ^ bPtr[1]
	dstPtr[2] = aPtr[2] ^ bPtr[2]
	dstPtr[3] = aPtr[3] ^ bPtr[3]
}

// XorBlock4 computes dst = a XOR b for Block4.
func XorBlock4(dst, a, b *Block4) {
	aPtr := (*[8]uint64)(unsafe.Pointer(a))
	bPtr := (*[8]uint64)(unsafe.Pointer(b))
	dstPtr := (*[8]uint64)(unsafe.Pointer(dst))
	dstPtr[0] = aPtr[0] ^ bPtr[0]
	dstPtr[1] = aPtr[1] ^ bPtr[1]
	dstPtr[2] = aPtr[2] ^ bPtr[2]
	dstPtr[3] = aPtr[3] ^ bPtr[3]
	dstPtr[4] = aPtr[4] ^ bPtr[4]
	dstPtr[5] = aPtr[5] ^ bPtr[5]
	dstPtr[6] = aPtr[6] ^ bPtr[6]
	dstPtr[7] = aPtr[7] ^ bPtr[7]
}
