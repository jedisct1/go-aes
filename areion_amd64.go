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

func areion256Permute2(state1, state2 *Areion256) {
	if CPU.HasAESNI {
		areion256PermuteAsm(state1)
		areion256PermuteAsm(state2)
	} else {
		areion256PermuteSoftware(state1)
		areion256PermuteSoftware(state2)
	}
}

func areion512Permute2(state1, state2 *Areion512) {
	if CPU.HasAESNI {
		areion512PermuteAsm(state1)
		areion512PermuteAsm(state2)
	} else {
		areion512PermuteSoftware(state1)
		areion512PermuteSoftware(state2)
	}
}
