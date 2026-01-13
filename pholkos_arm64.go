//go:build !purego

package aes

//go:noescape
func pholkos256EncryptAsm(block *Pholkos256Block, rtk *[17][2]Block)

//go:noescape
func pholkos256DecryptAsm(block *Pholkos256Block, rtk *[17][2]Block)

//go:noescape
func pholkos512EncryptAsm(block *Pholkos512Block, rtk *[21][4]Block)

//go:noescape
func pholkos512DecryptAsm(block *Pholkos512Block, rtk *[21][4]Block)
