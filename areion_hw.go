//go:build !purego

package aes

// areion256Permute dispatches to hardware or software implementation
func areion256Permute(state *Areion256) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion256PermuteAsm(state)
	} else {
		areion256PermuteSoftware(state)
	}
}

// areion256InversePermute dispatches to hardware or software implementation
func areion256InversePermute(state *Areion256) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion256InversePermuteAsm(state)
	} else {
		areion256InversePermuteSoftware(state)
	}
}

// areion512Permute dispatches to hardware or software implementation
func areion512Permute(state *Areion512) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion512PermuteAsm(state)
	} else {
		areion512PermuteSoftware(state)
	}
}

// areion512InversePermute dispatches to hardware or software implementation
func areion512InversePermute(state *Areion512) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion512InversePermuteAsm(state)
	} else {
		areion512InversePermuteSoftware(state)
	}
}
