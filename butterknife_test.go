package aes

import (
	"encoding/hex"
	"testing"
)

// TestButterKnifeZeroInputs tests ButterKnife with zero key and zero input
func TestButterKnifeZeroInputs(t *testing.T) {
	var tweakey Tweakey256
	var input Block

	output := ButterKnife(&tweakey, &input)

	// Verify we get 8 output branches
	if len(*output) != 8 {
		t.Errorf("Expected 8 output branches, got %d", len(*output))
	}

	// Expected outputs (self-generated test vector after fixing round constant format)
	expectedBranches := []string{
		"9d227a10963a5cdc8f5aa76db7f42dcb",
		"8c88e63d691c634318138341d6ac37b6",
		"950077f44ed05b71b4aefc5f995c24ee",
		"286dc726a44184b677a2aa367e8a88f2",
		"e10858d4e886336aaf8a44a75615a5d5",
		"289286ed88ee124db11a68b24d4d6c14",
		"af925336714771be6514678bccfc15d7",
		"d1015b2b04000de4770c440ca064106b",
	}

	for i, branch := range output {
		got := hex.EncodeToString(branch[:])
		if got != expectedBranches[i] {
			t.Errorf("Branch %d mismatch:\ngot:  %s\nwant: %s", i, got, expectedBranches[i])
		}
	}
}

// TestButterKnifeKnownVector tests ButterKnife with a known test vector
func TestButterKnifeKnownVector(t *testing.T) {
	// Create a known tweakey (incrementing bytes)
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	// Create a known input (incrementing bytes)
	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i * 16)
	}

	output := ButterKnife(&tweakey, &input)

	// Print output for creating test vectors
	t.Logf("ButterKnife with incrementing key and patterned input:")
	t.Logf("  Tweakey: %x", tweakey[:])
	t.Logf("  Input:   %x", input[:])
	for i, branch := range output {
		t.Logf("  Branch %d: %x", i, branch[:])
	}

	// Verify all branches are different
	for i := 0; i < 8; i++ {
		for j := i + 1; j < 8; j++ {
			if output[i] == output[j] {
				t.Errorf("Branch %d and %d have identical outputs", i, j)
			}
		}
	}
}

// TestButterKnifeContext tests the context-based API
func TestButterKnifeContext(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	// Create context
	ctx := NewButterKnifeContext(&tweakey)

	// Test with two different inputs
	var input1 Block
	for i := 0; i < 16; i++ {
		input1[i] = byte(i)
	}

	var input2 Block
	for i := 0; i < 16; i++ {
		input2[i] = byte(i * 2)
	}

	output1 := ctx.Eval(&input1)
	output2 := ctx.Eval(&input2)

	// Outputs should be different for different inputs
	if *output1 == *output2 {
		t.Error("Different inputs produced identical outputs")
	}

	// Verify context produces same result as direct call
	directOutput1 := ButterKnife(&tweakey, &input1)
	if *output1 != *directOutput1 {
		t.Error("Context-based eval differs from direct ButterKnife call")
	}
}

// TestButterKnifeDeterministic verifies that ButterKnife is deterministic
func TestButterKnifeDeterministic(t *testing.T) {
	var tweakey Tweakey256
	var input Block

	// Call twice with same inputs
	output1 := ButterKnife(&tweakey, &input)
	output2 := ButterKnife(&tweakey, &input)

	// Outputs should be identical
	if *output1 != *output2 {
		t.Error("ButterKnife is not deterministic")
	}
}

// TestButterKnifeFeedForward verifies the feed-forward property
func TestButterKnifeFeedForward(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i)
	}

	// The feed-forward should ensure that the output is not invertible
	// without knowledge of the fork state
	output := ButterKnife(&tweakey, &input)

	// All branches should be non-zero
	var zeroBlock Block
	for i, branch := range output {
		if branch == zeroBlock {
			t.Errorf("Branch %d is all zeros", i)
		}
	}
}

// TestButterKnifeTweakeyScheduleReuse tests that pre-expanded tweakeys work correctly
func TestButterKnifeTweakeyScheduleReuse(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i ^ 0x55)
	}

	// Create context (pre-expands tweakey once)
	ctx := NewButterKnifeContext(&tweakey)

	// Process multiple inputs
	const numInputs = 100
	inputs := make([]Block, numInputs)
	outputs1 := make([]ButterKnifeOutput, numInputs)
	outputs2 := make([]ButterKnifeOutput, numInputs)

	for i := 0; i < numInputs; i++ {
		inputs[i][0] = byte(i)
		inputs[i][1] = byte(i >> 8)

		// Using context
		outputs1[i] = *ctx.Eval(&inputs[i])

		// Using direct call
		outputs2[i] = *ButterKnife(&tweakey, &inputs[i])
	}

	// Verify all outputs match
	for i := 0; i < numInputs; i++ {
		if outputs1[i] != outputs2[i] {
			t.Errorf("Input %d: context output differs from direct call", i)
		}
	}
}

// BenchmarkButterKnife benchmarks the full ButterKnife TPRF
func BenchmarkButterKnife(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ButterKnife(&tweakey, &input)
	}
}

// BenchmarkNewButterKnifeContext benchmarks context creation
func BenchmarkNewButterKnifeContext(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewButterKnifeContext(&tweakey)
	}
}

// BenchmarkButterKnifeContextEval benchmarks evaluation with pre-expanded tweakey
func BenchmarkButterKnifeContextEval(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	ctx := NewButterKnifeContext(&tweakey)

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Eval(&input)
	}
}

// TestButterKnifeHW tests that hardware-accelerated ButterKnife matches software
func TestButterKnifeHW(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i * 16)
	}

	// Compare HW and SW outputs
	outputSW := ButterKnife(&tweakey, &input)
	outputHW := ButterKnifeHW(&tweakey, &input)

	for i := 0; i < 8; i++ {
		if outputSW[i] != outputHW[i] {
			t.Errorf("Branch %d mismatch:\nSW: %x\nHW: %x", i, outputSW[i][:], outputHW[i][:])
		}
	}
}

// TestButterKnifeContextHW tests the hardware-accelerated context-based API
func TestButterKnifeContextHW(t *testing.T) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	// Create HW context
	ctxHW := NewButterKnifeContextHW(&tweakey)
	ctxSW := NewButterKnifeContext(&tweakey)

	// Test with multiple inputs
	for testNum := 0; testNum < 10; testNum++ {
		var input Block
		for i := 0; i < 16; i++ {
			input[i] = byte(testNum*16 + i)
		}

		outputHW := ctxHW.EvalHW(&input)
		outputSW := ctxSW.Eval(&input)

		for i := 0; i < 8; i++ {
			if outputSW[i] != outputHW[i] {
				t.Errorf("Test %d, Branch %d mismatch:\nSW: %x\nHW: %x", testNum, i, outputSW[i][:], outputHW[i][:])
			}
		}
	}
}

// TestButterKnifeHWZeroInputs tests HW with zero key and zero input
func TestButterKnifeHWZeroInputs(t *testing.T) {
	var tweakey Tweakey256
	var input Block

	outputSW := ButterKnife(&tweakey, &input)
	outputHW := ButterKnifeHW(&tweakey, &input)

	for i := 0; i < 8; i++ {
		if outputSW[i] != outputHW[i] {
			t.Errorf("Branch %d mismatch:\nSW: %x\nHW: %x", i, outputSW[i][:], outputHW[i][:])
		}
	}
}

// BenchmarkButterKnifeHW benchmarks the hardware-accelerated ButterKnife
func BenchmarkButterKnifeHW(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ButterKnifeHW(&tweakey, &input)
	}
}

// BenchmarkButterKnifeContextHWEval benchmarks HW evaluation with pre-expanded tweakey
func BenchmarkButterKnifeContextHWEval(b *testing.B) {
	var tweakey Tweakey256
	for i := 0; i < 32; i++ {
		tweakey[i] = byte(i)
	}

	ctx := NewButterKnifeContextHW(&tweakey)

	var input Block
	for i := 0; i < 16; i++ {
		input[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.EvalHW(&input)
	}
}
