// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"bufio"
	"fmt"
	"strings"
	"encoding/binary"
	"crypto/rand"
	"math/big"
	"encoding/base64"
	"strconv"
	"bytes"
	"errors"
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

//xrandomint is a pointlessly complicated random int generator
func xrandomInt(m int) (n int) {
	var err error
	bigInt, err := rand.Int(rand.Reader, big.NewInt(int64(m)))
	if err != nil {
		panic(err)
	}
	return int(bigInt.Int64())
}

// randomInt returns an integer between 0 and max
func randomInt(max int) int {
	var n uint16
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	return int(n) % max
}

// randints returns a randomly ordered slice of ints
func randInts(n int) (m []int) {
	m = make([]int, n)
	for i := 0; i < n; i++ {
		j := randomInt(i + 1)
		m[i] = m[j]
		m[j] = i
	}
	return
}

// lenCheck verifies that a slice is of a specified length
func lenCheck(got, expected int) (err error) {
	if got != expected {
		err = fmt.Errorf("Incorrect length.  Expected=%d, Got=%d", expected, got)
		Info.Println(err)
	}
	return
}

// bufLenCheck verifies that a given buffer length is of a specified length
func bufLenCheck(buflen, length int) (err error) {
	if buflen != length {
		err = fmt.Errorf("Incorrect buffer length.  Wanted=%d, Got=%d", length, buflen)
		Info.Println(err)
	}
	return
}

// sPopBytes returns n bytes from the start of a slice
func sPopBytes(sp *[]byte, n int) (pop []byte, err error) {
	s := *sp
	if len(s) < n {
		err = fmt.Errorf("Cannot pop %d bytes from slice of %d", n, len(s))
		return
	}
	pop = s[:n]
	s = s[n:]
	*sp = s
	return
}

// ePopBytes returns n bytes from the end of a slice
func ePopBytes(sp *[]byte, n int) (pop []byte, err error) {
	s := *sp
	if len(s) < n {
		err = fmt.Errorf("Cannot pop %d bytes from slice of %d", n, len(s))
		return
	}
	pop = s[len(s) - n:]
	s = s[:len(s) - n]
	*sp = s
	return
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
func cutmarks(filename, sendto string, mixmsg []byte) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString("To: " + sendto + "\n")
	f.WriteString("From: steve@mixmin.net\n\n")
	f.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)
	f.WriteString(header)
	f.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	f.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	digest := blake2.New(&blake2.Config{Size: 16})
	digest.Write(mixmsg)
	f.WriteString(b64enc(digest.Sum(nil)) + "\n")
	f.WriteString(b64enc(mixmsg) + "\n")
	f.WriteString("-----END REMAILER MESSAGE-----\n")
	f.Sync()
	return
}

