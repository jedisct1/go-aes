//go:build !purego && !amd64 && !arm64

package aes

// EncryptHW uses software implementation (no HW on this platform).
func (ctx *Pholkos256Context) EncryptHW(block *Pholkos256Block) {
	ctx.Encrypt(block)
}

// DecryptHW uses software implementation (no HW on this platform).
func (ctx *Pholkos256Context) DecryptHW(block *Pholkos256Block) {
	ctx.Decrypt(block)
}

// EncryptHW uses software implementation (no HW on this platform).
func (ctx *Pholkos512Context) EncryptHW(block *Pholkos512Block) {
	ctx.Encrypt(block)
}

// DecryptHW uses software implementation (no HW on this platform).
func (ctx *Pholkos512Context) DecryptHW(block *Pholkos512Block) {
	ctx.Decrypt(block)
}
