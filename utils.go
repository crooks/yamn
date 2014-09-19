// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"crypto/rand"
)

// randbytes returns n Bytes of random data
func randbytes(n int) (b []byte) {
  b = make([]byte, n)
  _, err := rand.Read(b)
  if err != nil {
    panic(err)
  }
  return
}

// lencheck verifies that a slice is of a specified length
func lencheck(b []byte, length int) error {
	if len(b) != length {
		return fmt.Errorf("Incorrect slice length.  Wanted=%d, Got=%d", length, len(b))
	} else {
		return nil
	}
}

// buflencheck verifies that a given buffer length is of a specified length
func buflencheck(buflen, length int) error {
	if buflen != length {
		return fmt.Errorf("Incorrect buffer length.  Wanted=%d, Got=%d", length, buflen)
	} else {
		return nil
	}
}
