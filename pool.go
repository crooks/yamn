// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"io"
	"bytes"
	"bufio"
	"strconv"
	"errors"
	"strings"
	"path"
	"io/ioutil"
	"encoding/base64"
	"encoding/hex"
	"net/mail"
	"github.com/codahale/blake2"
	"github.com/crooks/yamn/quickmail"
	"github.com/luksen/maildir"
)

func poolRead() {
	poolFiles, err := readDir(cfg.Files.Pooldir)
	if err != nil {
		panic(err)
	}
	fmt.Println(poolFiles)
}

// poolWrite takes a Mixmaster formatted message from an io reader and
// stores it in the pool.
func poolWrite(reader io.Reader) (err error) {
	scanner := bufio.NewScanner(reader)
	scanPhase := 0
	var b64 string
	var payloadLen int
	var payloadDigest []byte
	var poolFileName string
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
				return errors.New("Unable to extract payload size")
			}
			scanPhase = 3
		case 3:
			if len(line) != 24 {
				err = fmt.Errorf("Expected 24 byte Base64 Hash, got %d bytes", len(line))
				return
			} else {
				payloadDigest, err = base64.StdEncoding.DecodeString(line)
				if err != nil {
					return errors.New("Unable to decode Base64 hash on payload")
				}
				poolFileName = "m" + hex.EncodeToString(payloadDigest)
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
		return
	}
	var payload []byte
	payload, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return errors.New("Unable to decode Base64 payload")
	}
	if len(payload) != payloadLen {
		err = fmt.Errorf("Unexpected payload size. Wanted=%d, Got=%d", payloadLen, len(payload))
	}
	digest := blake2.New(&blake2.Config{Size: 16})
	digest.Write(payload)
	if ! bytes.Equal(digest.Sum(nil), payloadDigest) {
		return errors.New("Incorrect payload digest")
	}
	outFileName := path.Join(cfg.Files.Pooldir, poolFileName[:14])
	err = ioutil.WriteFile(outFileName, payload, 0600)
	return
}


// readdir returns a list of files in a specified directory
func readDir(path string) (files []string, err error) {
	fi, err := ioutil.ReadDir(path)
	if err != nil {
		return
	}
	for _, f := range fi {
		if ! f.IsDir() {
			files = append(files, f.Name())
		}
	}
	return
}

// remailerFoo responds to requests for remailer-* info
func remailerFoo(subject, sender string) (err error) {
	m := quickmail.NewMessage()
	m.Set("From", "steve@stmellion.org")
	m.Set("To", sender)
	m.SMTP.Relay = cfg.Mail.SMTPRelay
	m.SMTP.Port = cfg.Mail.SMTPPort
	m.SMTP.User = cfg.Mail.SMTPUsername
	m.SMTP.Password = cfg.Mail.SMTPPassword
	if strings.HasPrefix(subject, "remailer-key") {
		m.Set("Subject", fmt.Sprintf("Remailer key for %s", cfg.Remailer.Name))
		m.Filename = cfg.Files.Pubkey
		m.Prefix = "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-="
	}
	err = m.Send()
	if err != nil {
		return
	}
	return
}

func mailRead() (err error) {
	dir := maildir.Dir(cfg.Files.Maildir)
	// Get a list of Maildir keys from the directory
	keys, err := dir.Keys()
	if err != nil {
		return
	}
	// Fetch headers for each Maildir key
	var head mail.Header
	for _, key := range keys {
		head, err = dir.Header(key)
		if err != nil {
			panic(err)
		}
		// The Subject determines if the message needs remailer-foo handling
		subject := strings.TrimSpace(strings.ToLower(head.Get("Subject")))
		if strings.HasPrefix(subject, "remailer-") {
			// It's a remailer-foo request
			err = remailerFoo(subject, head.Get("From"))
			if err != nil {
				panic(err)
			}
		} else {
			// It's not a remailer-foo request so assume a remailer message
			var msg *mail.Message
			msg, err := dir.Message(key)
			if err != nil {
				panic(err)
			}
			poolWrite(msg.Body)
		}
	}
	return
}
