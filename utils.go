// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"strings"
	"crypto/rand"
	"encoding/base64"
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

// b64enc takes a byte array as input and returns it as a base64 encoded
// string.  The output string is wrapped to a predefined line length.
func b64enc(data []byte) string {
	return wrap(base64.StdEncoding.EncodeToString(data))
}

// wrap takes a long string and wraps it to lines of a predefined length.
// The intention is to feed it a base64 encoded string.
func wrap(str string) (newstr string) {
	var substr string
	var end int
	strlen := len(str)
	for i := 0; i <= strlen; i += base64_line_wrap {
		end = i + base64_line_wrap
		if end > strlen {
			end = strlen
		}
		substr = str[i:end] + "\n"
		newstr += substr
	}
	// Strip the inevitable trailing LF
	newstr = strings.TrimRight(newstr, "\n")
	return
}
