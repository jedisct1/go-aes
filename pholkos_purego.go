//go:build purego

package aes

// EncryptHW uses software implementation (purego build).
func (ctx *Pholkos256Context) EncryptHW(block *Pholkos256Block) {
	ctx.Encrypt(block)
}

// DecryptHW uses software implementation (purego build).
func (ctx *Pholkos256Context) DecryptHW(block *Pholkos256Block) {
	ctx.Decrypt(block)
}

// EncryptHW uses software implementation (purego build).
func (ctx *Pholkos512Context) EncryptHW(block *Pholkos512Block) {
	ctx.Encrypt(block)
}

// DecryptHW uses software implementation (purego build).
func (ctx *Pholkos512Context) DecryptHW(block *Pholkos512Block) {
	ctx.Decrypt(block)
}
