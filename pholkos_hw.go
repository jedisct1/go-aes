//go:build !purego && (amd64 || arm64)

package aes

// EncryptHW encrypts using hardware acceleration if available.
func (ctx *Pholkos256Context) EncryptHW(block *Pholkos256Block) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		pholkos256EncryptAsm(block, &ctx.rtk)
	} else {
		ctx.Encrypt(block)
	}
}

// DecryptHW decrypts using hardware acceleration if available.
func (ctx *Pholkos256Context) DecryptHW(block *Pholkos256Block) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		pholkos256DecryptAsm(block, &ctx.rtk)
	} else {
		ctx.Decrypt(block)
	}
}

// EncryptHW encrypts using hardware acceleration if available.
func (ctx *Pholkos512Context) EncryptHW(block *Pholkos512Block) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		pholkos512EncryptAsm(block, &ctx.rtk)
	} else {
		ctx.Encrypt(block)
	}
}

// DecryptHW decrypts using hardware acceleration if available.
func (ctx *Pholkos512Context) DecryptHW(block *Pholkos512Block) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		pholkos512DecryptAsm(block, &ctx.rtk)
	} else {
		ctx.Decrypt(block)
	}
}
