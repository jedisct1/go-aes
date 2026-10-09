//go:build !amd64 || purego

package aes

func hasVAES() bool {
	return false
}
