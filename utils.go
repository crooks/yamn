// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"bufio"
	"fmt"
	"strings"
	"crypto/rand"
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

// lenCheck verifies that a slice is of a specified length
func lenCheck(got, expected int) (err error) {
	if got != expected {
		err = fmt.Errorf("Incorrect length.  Expected=%d, Got=%d", expected, got)
	}
	return
}

// bufLenCheck verifies that a given buffer length is of a specified length
func bufLenCheck(buflen, length int) (err error) {
	if buflen != length {
		err = fmt.Errorf("Incorrect buffer length.  Wanted=%d, Got=%d", length, buflen)
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
func old_cutmarks(mixmsg []byte) []byte {
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

// uncut does the opposite of cutmarks and returns plain bytes
func uncut(filename string) (payload []byte, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	scanPhase := 0
	var b64 string
	var payloadLen int
	var payloadDigest []byte
	/* Scan phases are:
	0	Expecting ::
	1 Expecting Begin cutmarks
	2 Expecting size
	3	Expecting hash
	4 In payload and checking for End cutmark
	5 Got End cutmark
	*/
	for scanner.Scan() {
		line := scanner.Text()
		switch scanPhase {
		case 0:
			// Expecting ::\n
			if line == "::" {
				scanPhase = 1
			}
		case 1:
			// Expecting Begin cutmarks
			if line == "-----BEGIN REMAILER MESSAGE-----" {
				scanPhase = 2
			}
		case 2:
			// Expecting size
			payloadLen, err = strconv.Atoi(line)
			if err != nil {
				return nil, errors.New("Unable to extract payload size")
			}
			scanPhase = 3
		case 3:
			if len(line) != 24 {
				err = fmt.Errorf("Expected 24 byte Base64 Hash, got %d bytes", len(line))
				return nil, err
			} else {
				payloadDigest, err = base64.StdEncoding.DecodeString(line)
				if err != nil {
					return nil, errors.New("Unable to decode Base64 hash on payload")
				}
			}
			scanPhase = 4
		case 4:
			if line == "-----END REMAILER MESSAGE-----" {
				scanPhase = 5
				break
			}
			b64 += line
		} // End of switch
	} // End of file scan
	if scanPhase != 5 {
		err = fmt.Errorf("Payload scanning failed at phase %d", scanPhase)
		return nil, err
	}
	payload, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("Unable to decode Base64 payload")
	}
	if len(payload) != payloadLen {
		err = fmt.Errorf("Unexpected payload size. Wanted=%d, Got=%d", payloadLen, len(payload))
	}
	digest := blake2.New(&blake2.Config{Size: 16})
	digest.Write(payload)
	if ! bytes.Equal(digest.Sum(nil), payloadDigest) {
		return nil, errors.New("Incorrect payload digest")
	}
	return
}

func ivExtract(ivs []byte, n int) (iv []byte, err error) {
	if len(ivs) % 16 != 0 {
		err = fmt.Errorf("IV bytes array must be multiples of 16.  Got=%d", len(ivs))
		return
	}
	ivPos := 16 * n
	numIVs := len(ivs) / 16
	if n > numIVs {
		err = fmt.Errorf("Insufficient IVs.  Wanted=%d, Available=%d.", n, numIVs)
		return
	}
	iv = ivs[ivPos:ivPos+16]
	lenCheck(len(iv), 16)
	return
}

