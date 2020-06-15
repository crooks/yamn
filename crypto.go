// aesgcm provides authenticated symmetric encryption using AES-GCM. It
// generates random nonces for each message, and prepends the nonce to
// the ciphertext.
package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// aesGcmEncrypt applies the necessary padding to the message and encrypts it
// with AES-GCM.
func aesGcmEncrypt(plain, key, nonce, data []byte) (ct []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ct = gcm.Seal(nil, nonce, plain, data)
	return
}

// aesGcmDecrypt decrypts the message and removes any padding.
func aesGcmDecrypt(ct, key, nonce, data []byte) (plain []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	plain, err = gcm.Open(nil, nonce, ct, data)
	if err != nil {
		panic(err)
	}
	return
}

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
