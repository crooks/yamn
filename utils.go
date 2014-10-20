// vim: tabstop=2 shiftwidth=2

package main

import (
	"bytes"
	"os"
	"fmt"
	"strings"
	"path"
	"encoding/binary"
	"encoding/hex"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"encoding/base64"
	"strconv"
	//"github.com/codahale/blake2"
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
	return int(n) % (max + 1)
}

// randInts returns a randomly ordered slice of ints
func randInts(n int) (m []int) {
	m = make([]int, n)
	for i := 0; i < n; i++ {
		j := randomInt(i)
		m[i] = m[j]
		m[j] = i
	}
	return
}

// randPoolFilename returns a random filename with a given prefix
func randPoolFilename(prefix string) (fqfn string) {
	for {
		outfileName := prefix + hex.EncodeToString(randbytes(7))
		fqfn = path.Join(cfg.Files.Pooldir, outfileName)
		_, err := os.Stat(fqfn)
		if err != nil {
			// For once we want an error (indicating the file doesn't exist)
			break
		}
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

func exists(path string) (bool, error) {
	var err error
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
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

// popstr takes a pointer to a string slice and pops the last element
func popstr(s *[]string) (element string) {
	slice := *s
	element, slice = slice[len(slice) - 1], slice[:len(slice) - 1]
	*s = slice
	return
}

// wrap takes a long string and wraps it to lines of a predefined length.
// The intention is to feed it a base64 encoded string.
func wrap(str string) (newstr string) {
	var substr string
	var end int
	strlen := len(str)
	for i := 0; i <= strlen; i += base64LineWrap {
		end = i + base64LineWrap
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
func cutmarks(mixmsg []byte, sendto string) (err error) {
	/*
	With the exception of email delivery to recipients, every outbound message
	should be wrapped by this function.
	*/
	buf := new(bytes.Buffer)
	if ! cfg.Mail.Outfile {
		// Add email headers as we're not writing output to a file
		buf.WriteString(fmt.Sprintf("To: %s\n", sendto))
		buf.WriteString(fmt.Sprintf("From: %s\n", cfg.Mail.EnvelopeSender))
		buf.WriteString("\n")
	}
	buf.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)
	buf.WriteString(header)
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	// Write message length
	buf.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(mixmsg)
	// Write message digest
	buf.WriteString(base64.StdEncoding.EncodeToString(digest.Sum(nil)[:16]) + "\n")
	// Write the payload
	buf.WriteString(wrap(base64.StdEncoding.EncodeToString(mixmsg)) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----\n")
	if cfg.Mail.Outfile {
		var f *os.File
		filename := "outfile-" + hex.EncodeToString(digest.Sum(nil))
		f, err = os.Create(path.Join(cfg.Files.Pooldir, filename[:16]))
		defer f.Close()
		_, err = f.WriteString(string(buf.Bytes()))
		if err != nil {
			Warn.Printf("Outfile write failed: %s\n", err)
			return
		}
	} else if cfg.Mail.Sendmail {
		err = sendmail(buf.Bytes(), sendto)
		if err != nil {
			Warn.Println("Sendmail failed")
			return
		}
	} else {
		err = SMTPRelay(buf.Bytes(), sendto)
		if err != nil {
			Warn.Println("SMTP relay failed")
			return
		}
	}
	return
}

// armor encodes a mixmsg into a Mixmaster formatted email payload
func armor(mixmsg []byte, sendto string) []byte {
	/*
	With the exception of email delivery to recipients, every outbound message
	should be wrapped by this function.
	*/
	buf := new(bytes.Buffer)
	if ! cfg.Mail.Outfile {
		// Add email headers as we're not writing output to a file
		buf.WriteString(fmt.Sprintf("To: %s\n", sendto))
		buf.WriteString(fmt.Sprintf("From: %s\n", cfg.Mail.EnvelopeSender))
		buf.WriteString("\n")
	}
	buf.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)
	buf.WriteString(header)
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	// Write message length
	buf.WriteString(strconv.Itoa(len(mixmsg)) + "\n")
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(mixmsg)
	// Write message digest
	buf.WriteString(base64.StdEncoding.EncodeToString(digest.Sum(nil)[:16]) + "\n")
	// Write the payload
	buf.WriteString(wrap(base64.StdEncoding.EncodeToString(mixmsg)) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----\n")
	return buf.Bytes()
}

