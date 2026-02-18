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

func areion256Permute2(state1, state2 *Areion256) {
	areion256PermuteSoftware(state1)
	areion256PermuteSoftware(state2)
}

func areion512Permute2(state1, state2 *Areion512) {
	areion512PermuteSoftware(state1)
	areion512PermuteSoftware(state2)
}
