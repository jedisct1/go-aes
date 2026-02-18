//go:build !purego

package aes

//go:noescape
func areion256PermuteAsm(state *Areion256)

//go:noescape
func areion256InversePermuteAsm(state *Areion256)

//go:noescape
func areion512PermuteAsm(state *Areion512)

//go:noescape
func areion512InversePermuteAsm(state *Areion512)
