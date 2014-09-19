// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"strings"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"bytes"
	"github.com/codahale/blake2"
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

// cutmarks encodes a mixmsg into a Mixmaster formatted email payload
func cutmarks(mixmsg []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)
	buf.WriteString(header)
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	buf.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	digest := blake2.New(&blake2.Config{Size: 16})
	digest.Write(mixmsg)
	buf.WriteString(b64enc(digest.Sum(nil)) + "\n")
	buf.WriteString(b64enc(mixmsg) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----")
	return buf.Bytes()
}
