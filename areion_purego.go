//go:build purego

package aes

// Pure Go implementations (no hardware acceleration)

func areion256Permute(state *Areion256) {
	areion256PermuteSoftware(state)
}

func areion256InversePermute(state *Areion256) {
	areion256InversePermuteSoftware(state)
}

func areion512Permute(state *Areion512) {
	areion512PermuteSoftware(state)
}

func areion512InversePermute(state *Areion512) {
	areion512InversePermuteSoftware(state)
}
