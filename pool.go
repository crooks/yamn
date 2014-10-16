// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"io"
	"bytes"
	"bufio"
	"strconv"
	"strings"
	"path"
	"io/ioutil"
	"encoding/base64"
	"encoding/hex"
	"net/mail"
	"crypto/sha256"
	//"github.com/codahale/blake2"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/quickmail"
	"github.com/luksen/maildir"
)

func poolRead() (selectedPoolFiles []string, err error) {
	poolFiles, err := readDir(cfg.Files.Pooldir)
	if err != nil {
		Warn.Printf("Unable to access pool: %s", err)
		return
	}
	poolSize := len(poolFiles)
	Trace.Printf("Pool contains %d messages.\n", poolSize)
	if poolSize < cfg.Pool.Size {
		// Pool isn't sufficiently populated
		Trace.Println("Pool insufficiently populated to trigger sending.",
			fmt.Sprintf("Require=%d, Got=%d", cfg.Pool.Size, poolSize))
		return
	}
	keys := randInts(len(poolFiles))
	numToSend := int((float32(poolSize) / 100.0) * float32(cfg.Pool.Rate))
	Trace.Printf("Processing %d pool messages.\n", poolSize)
	for n := 0; n < numToSend; n++ {
		mykey := keys[n]
		selectedPoolFiles = append(selectedPoolFiles, poolFiles[mykey])
	}
	return
}

func poolDelete(filename string) (err error) {
	// Delete a pool file
	err = os.Remove(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		Error.Printf("Failed to remove %s from %s\n", filename, cfg.Files.Pooldir)
	}
	return
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
				err = fmt.Errorf("Unable to extract payload size from %s", line)
				return
			}
			scanPhase = 3
		case 3:
			if len(line) != 24 {
				err = fmt.Errorf("Expected 24 byte Base64 Hash, got %d bytes\n", len(line))
				return
			} else {
				payloadDigest, err = base64.StdEncoding.DecodeString(line)
				if err != nil {
					err = fmt.Errorf("Unable to decode Base64 hash on payload")
					return
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
		err = fmt.Errorf("Payload scanning failed at phase %d\n", scanPhase)
		return
	}
	var payload []byte
	payload, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		Info.Printf("Unable to decode Base64 payload")
		return
	}
	if len(payload) != payloadLen {
		Info.Printf("Unexpected payload size. Wanted=%d, Got=%d\n", payloadLen, len(payload))
		return
	}
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(payload)
	if ! bytes.Equal(digest.Sum(nil)[:16], payloadDigest) {
		Info.Println("Incorrect payload digest")
		return
	}
	outFileName := path.Join(cfg.Files.Pooldir, poolFileName[:14])
	err = ioutil.WriteFile(outFileName, payload, 0600)
	if err != nil {
		Error.Printf("Failed to write %s to %s\n", outFileName, cfg.Files.Pooldir)
		return
	}
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
		// remailer-key
		Trace.Printf("remailer-key request from %s", sender)
		m.Set("Subject", fmt.Sprintf("Remailer key for %s", cfg.Remailer.Name))
		m.Filename = cfg.Files.Pubkey
		m.Prefix = "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-="
	} else if strings.HasPrefix(subject, "remailer-conf") {
		// remailer-conf
		Trace.Printf("remailer-conf request from %s", sender)
		m.Set("Subject", fmt.Sprintf("Capabilities of the %s remailer", cfg.Remailer.Name))
		m.Text(fmt.Sprintf("Remailer-Type: Mixmaster %s\n", version))
		m.Text("Supported Formats:\n   Mixmaster\n")
		m.Text(fmt.Sprintf("Pool size: %d\n", cfg.Pool.Size))
		m.Text(fmt.Sprintf("Maximum message size: %d kB\n", cfg.Remailer.MaxSize))
		m.Text("The following header lines will be filtered:\n")
		m.Text(fmt.Sprintf("\n$remailer{\"%s\"} = \"<%s>", cfg.Remailer.Name, cfg.Remailer.Address))
		if ! cfg.Remailer.Exit {
			m.Text(" middle")
		}
		m.Text("\";\n")
		m.Text("\nSUPPORTED MIXMASTER (TYPE II) REMAILERS")
		var pubList []string
		pubList, err := keymgr.Headers(cfg.Files.Pubring)
		if err != nil {
			Info.Printf("Could not read %s", cfg.Files.Pubring)
		} else {
			m.List(pubList)
		}
	} else if strings.HasPrefix(subject, "remailer-adminkey") {
		// remailer-adminkey
		Trace.Printf("remailer-adminkey request from %s", sender)
		m.Set("Subject", fmt.Sprintf("Admin key for the %s remailer", cfg.Remailer.Name))
		m.Filename = cfg.Files.Adminkey
	} else if strings.HasPrefix(subject, "remailer-help") {
		// remailer-help
		Trace.Printf("remailer-help request from %s", sender)
		m.Set("Subject", fmt.Sprintf("Your help request for the %s Anonymous Remailer", cfg.Remailer.Name))
		m.Filename = cfg.Files.Help
	} else {
		if len(subject) > 20 {
			// Truncate long subject headers before logging them
			subject = subject[:20]
		}
		err = fmt.Errorf("Ignoring request for %s", subject)
		return
	}
	var msg []byte
	msg, err = m.Compile()
	if err != nil {
		Info.Printf("Unable to send %s", subject)
		return
	}
	if cfg.Mail.Sendmail {
    err = sendmail(msg, sender)
    if err != nil {
      Warn.Println("Sendmail failed during remailer-* request")
      return
    }
  } else {
    err = SMTPRelay(msg, sender)
    if err != nil {
      Warn.Println("SMTP relay failed during remailer-* request")
      return
    }
  }
	return
}

func mailRead() (err error) {
	dir := maildir.Dir(cfg.Files.Maildir)
	// Get a list of Maildir keys from the directory
	keys, err := dir.Unseen()
	if err != nil {
		return
	}
	if len(keys) > 0 {
		Trace.Printf("Reading %d messages from %s\n", len(keys), cfg.Files.Maildir)
	}
	// Fetch headers for each Maildir key
	var head mail.Header
	for _, key := range keys {
		head, err = dir.Header(key)
		if err != nil {
			return
		}
		// The Subject determines if the message needs remailer-foo handling
		subject := strings.TrimSpace(strings.ToLower(head.Get("Subject")))
		if strings.HasPrefix(subject, "remailer-") {
			// It's a remailer-foo request
			err = remailerFoo(subject, head.Get("From"))
			if err != nil {
				Info.Println(err)
			}
		} else {
			// It's not a remailer-foo request so assume a remailer message
			var msg *mail.Message
			msg, err := dir.Message(key)
			if err != nil {
				panic(err)
			}
			err = poolWrite(msg.Body)
			if err != nil {
				Info.Println(err)
			}
		} // End of remailer-foo or remailer message
		err = dir.Purge(key)
		if err != nil {
			Warn.Printf("Cannot delete mail: %s", err)
		}
	} // Maildir keys loop
	return
}
