package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
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

// daysAgo takes a timestamp and returns it as an integer of its age in days.
func daysAgo(date time.Time) (days int) {
	age := time.Since(date)
	days = int(age.Hours() / 24)
	return
}

// IsMemberStr tests for the membership of a string in a slice
func IsMemberStr(s string, slice []string) bool {
	for _, n := range slice {
		if n == s {
			return true
		}
	}
	return false
}

// randPoolFilename returns a random filename with a given prefix
func randPoolFilename(prefix string) (fqfn string) {
	for {
		outfileName := prefix + hex.EncodeToString(randbytes(7))
		fqfn = path.Join(cfg.Files.Pooldir, outfileName)
		_, err := os.Stat(fqfn)
		if err != nil {
			// For once we want an error (indicating the file
			// doesn't exist)
			break
		}
	}
	return
}

// readdir returns a list of files in a specified directory that begin with
// the specified prefix.
func readDir(path, prefix string) (files []string, err error) {
	fi, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}
	for _, f := range fi {
		if !f.IsDir() && strings.HasPrefix(f.Name(), prefix) {
			files = append(files, f.Name())
		}
	}
	return
}

// messageID returns an RFC compliant Message-ID for use in message
// construction.
func messageID() (datestr string) {
	dateComponent := time.Now().Format("20060102.150405")
	randomComponent := hex.EncodeToString(randbytes(4))
	var domainComponent string
	if strings.Contains(cfg.Remailer.Address, "@") {
		domainComponent = strings.SplitN(
			cfg.Remailer.Address, "@", 2,
		)[1]
	} else {
		domainComponent = "yamn.invalid"
	}
	datestr = fmt.Sprintf(
		"<%s.%s@%s>",
		dateComponent,
		randomComponent,
		domainComponent,
	)
	return
}

// lenCheck verifies that a slice is of a specified length
func lenCheck(got, expected int) (err error) {
	if got != expected {
		err = fmt.Errorf(
			"Incorrect length.  Expected=%d, Got=%d",
			expected,
			got,
		)
		Info.Println(err)
	}
	return
}

// bufLenCheck verifies that a given buffer length is of a specified length
func bufLenCheck(buflen, length int) (err error) {
	if buflen != length {
		err = fmt.Errorf(
			"Incorrect buffer length.  Wanted=%d, Got=%d",
			length,
			buflen,
		)
		Info.Println(err)
	}
	return
}

// Return the time when filename was last modified
func fileTime(filename string) (t time.Time, err error) {
	info, err := os.Stat(filename)
	if err != nil {
		return
	}
	t = info.ModTime()
	return
}

// httpGet retrieves url and stores it in filename
func httpGet(url, filename string) (err error) {
	res, err := http.Get(url)
	if err != nil {
		return
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		err = fmt.Errorf("%s: %s", url, res.Status)
		return err
	}
	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filename, content, 0644)
	if err != nil {
		return
	}
	return
}

// exists returns True if a given file or directory exists
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

// assertExists panics if a given file or dir doesn't exist
func assertExists(path string) {
	gotPoolDir, err := exists(cfg.Files.Pooldir)
	if err != nil {
		// Some error occurred other than the path not existing
		panic(err)
	}
	if !gotPoolDir {
		// Arghh, the path doesn't exist!
		err = fmt.Errorf(
			"Assertion failure.  Path %s does not exist.",
			path,
		)
		panic(err)
	}
}

// sPopBytes returns n bytes from the start of a slice
func sPopBytes(sp *[]byte, n int) (pop []byte, err error) {
	s := *sp
	if len(s) < n {
		err = fmt.Errorf(
			"Cannot pop %d bytes from slice of %d",
			n,
			len(s),
		)
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
		err = fmt.Errorf(
			"Cannot pop %d bytes from slice of %d",
			n,
			len(s),
		)
		return
	}
	pop = s[len(s)-n:]
	s = s[:len(s)-n]
	*sp = s
	return
}

// popstr takes a pointer to a string slice and pops the last element
func popstr(s *[]string) (element string) {
	slice := *s
	element, slice = slice[len(slice)-1], slice[:len(slice)-1]
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

// armor base64 encodes a Yamn message for emailing
func armor(yamnMsg []byte, sendto string) []byte {
	/*
		With the exception of email delivery to recipients, every
		outbound message should be wrapped by this function.
	*/
	var err error
	err = lenCheck(len(yamnMsg), messageBytes)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	if !cfg.Mail.Outfile {
		// Add email headers as we're not writing output to a file
		buf.WriteString(fmt.Sprintf("To: %s\n", sendto))
		buf.WriteString(fmt.Sprintf("From: %s\n", cfg.Remailer.Address))
		buf.WriteString(fmt.Sprintf("Subject: yamn-%s\n", version))
		buf.WriteString("\n")
	}
	buf.WriteString("::\n")
	header := fmt.Sprintf("Remailer-Type: yamn-%s\n\n", version)
	buf.WriteString(header)
	buf.WriteString("-----BEGIN REMAILER MESSAGE-----\n")
	// Write message length
	buf.WriteString(strconv.Itoa(len(yamnMsg)) + "\n")
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(yamnMsg)
	// Write message digest
	buf.WriteString(base64.StdEncoding.EncodeToString(
		digest.Sum(nil)[:16]) + "\n",
	)
	// Write the payload
	buf.WriteString(wrap(base64.StdEncoding.EncodeToString(yamnMsg)) + "\n")
	buf.WriteString("-----END REMAILER MESSAGE-----\n")
	return buf.Bytes()
}

// stripArmor takes a Mixmaster formatted message from an ioreader and
// returns its payload as a byte slice
func stripArmor(reader io.Reader) (payload []byte, err error) {
	scanner := bufio.NewScanner(reader)
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
				continue
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
				err = fmt.Errorf(
					"Unable to extract payload size from %s",
					line,
				)
				return
			}
			scanPhase = 3
		case 3:
			if len(line) != 24 {
				err = fmt.Errorf(
					"Expected 24 byte Base64 Hash, got %d bytes\n",
					len(line),
				)
				return
			} else {
				payloadDigest, err = base64.StdEncoding.DecodeString(line)
				if err != nil {
					err = errors.New(
						"Unable to decode Base64 hash on payload",
					)
					return
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
	switch scanPhase {
	case 0:
		err = errors.New("No :: found on message")
		return
	case 1:
		err = errors.New("No Begin cutmarks found on message")
		return
	case 4:
		err = errors.New("No End cutmarks found on message")
		return
	}
	payload, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return
	}
	// Validate payload length against stated length.
	if len(payload) != payloadLen {
		err = fmt.Errorf(
			"Payload size doesn't match stated size. Wanted=%d, Got=%d\n",
			payloadLen,
			len(payload),
		)
		return
	}
	// Validate payload length against packet format.
	if len(payload) != messageBytes {
		err = fmt.Errorf(
			"Payload size doesn't match stated size. Wanted=%d, Got=%d\n",
			payloadLen,
			len(payload),
		)
		return
	}
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(payload)
	if !bytes.Equal(digest.Sum(nil)[:16], payloadDigest) {
		err = errors.New("Incorrect payload digest during dearmor")
		return
	}
	return
}
