// aesgcm provides authenticated symmetric encryption using AES-GCM. It
// generates random nonces for each message, and prepends the nonce to
// the ciphertext.
package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// aesCtr does encrypt and decrypt of aes_ctr mode
func aesCtr(in, key, iv []byte) (out []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out = make([]byte, len(in))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, in)
	return
}
