// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"io"
	"bytes"
	"bufio"
	"errors"
	"strconv"
	"strings"
	"path"
	"io/ioutil"
	"encoding/base64"
	"encoding/hex"
	"net/mail"
	"crypto/sha256"
	"crypto/sha512"
	//"github.com/codahale/blake2"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/quickmail"
	"github.com/luksen/maildir"
)

// poolRead returns a dynamic Mix of filenames from the outbound pool
func poolRead() (selectedPoolFiles []string, err error) {
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
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

// Delete a given file from the pool
func poolDelete(filename string) (err error) {
	// Delete a pool file
	err = os.Remove(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		Error.Printf("Failed to remove %s from %s\n", filename, cfg.Files.Pooldir)
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
		if ! f.IsDir() && strings.HasPrefix(f.Name(), prefix) {
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

// processMail reads the Remailer's Maildir and processes the content
func processMail(public *keymgr.Pubring, secret *keymgr.Secring, id idlog.IDLog) (err error) {
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
			Warn.Printf("%s: Getting headers failed with: %s", key, err)
			continue
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
			var mailMsg *mail.Message
			mailMsg, err := dir.Message(key)
			if err != nil {
				Warn.Printf("%s: Reading message failed with: %s", key, err)
				continue
			}
			var msg []byte
			// Convert the armored Yamn message to its byte components
			msg, err = stripArmor(mailMsg.Body)
			if err != nil {
				Info.Println(err)
			}
			if msg == nil {
				Warn.Println("Dearmor returned zero bytes")
				continue
			}
			err = decodeMsg(msg, secret, id)
			if err != nil {
				Info.Println(err)
			}
			// Decide if we want to inject a dummy
			if randomInt(20) < 3 {
				err = dummy(public)
				if err != nil {
					Warn.Printf("Sending dummy failed: %s", err)
				}
			}
		} // End of remailer-foo or remailer message
		err = dir.Purge(key)
		if err != nil {
			Warn.Printf("Cannot delete mail: %s", err)
		}
	} // Maildir keys loop
	return
}

// processInpool is similar to processMail but reads the Inbound Pool
func processInpool(prefix string, secret *keymgr.Secring, id idlog.IDLog) {
	poolFiles, err := readDir(cfg.Files.Pooldir, prefix)
	if err != nil {
		Warn.Printf("Unable to access inbound pool: %s", err)
		return
	}
	poolSize := len(poolFiles)
	processed := 0
	for _, f := range poolFiles {
		filename := path.Join(cfg.Files.Pooldir, f)
		msg := make([]byte, messageBytes)
		msg, err = ioutil.ReadFile(filename)
		if err != nil {
			Warn.Printf("Failed to read %s from pool: %s", f, err)
			continue
		}
		err = decodeMsg(msg, secret, id)
		if err != nil {
			Warn.Println(err)
		}
		poolDelete(f)
		processed++
	}
	Trace.Printf("Inbound pool processing complete. Read=%d, Decoded=%d",
		poolSize, processed)
}

// stripArmor takes a Mixmaster formatted message from an ioreader and
// returns its payload as a byte slice
func stripArmor(reader io.Reader) (payload []byte, err error) {
	scanner := bufio.NewScanner(reader)
	scanPhase := 0
	var b64 string
	var payloadLen int
	var payloadDigest []byte
	var msgFrom string
	var msgSubject string
	var remailerFooRequest bool
	/* Scan phases are:
	0	Expecting ::
	1 Expecting Begin cutmarks
	2 Expecting size
	3	Expecting hash
	4 In payload and checking for End cutmark
	5 Got End cutmark
	255 Ignore and return
	*/
	for scanner.Scan() {
		line := scanner.Text()
		switch scanPhase {
		case 0:
			// Expecting ::\n (or maybe a Mail header)
			if line == "::" {
				scanPhase = 1
				continue
			}
			if flag_stdin {
				if strings.HasPrefix(line, "Subject: ") {
					// We have a Subject header.  This is probably a mail message.
					msgSubject = strings.ToLower(line[9:])
					if strings.HasPrefix(msgSubject, "remailer-") {
						remailerFooRequest = true
					}
				} else if strings.HasPrefix(line, "From: ") {
					// A From header might be useful if this is a remailer-foo request.
					msgFrom = line[6:]
				}
				if remailerFooRequest && len(msgSubject) > 0 && len(msgFrom) > 0 {
					// Do remailer-foo processing
					err = remailerFoo(msgSubject, msgFrom)
					if err != nil {
						Info.Println(err)
						err = nil
					}
					// Don't bother to read any further
					scanPhase = 255
					break
				}
			} // End of STDIN flag test
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
	case 255:
		return
	}
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
	return
}

// inPoolWrite writes a raw Byte Yamn message to the Inbound pool
func inPoolWrite(yamnMsg []byte) (err error) {
	outfileName := randPoolFilename("i")
	err = ioutil.WriteFile(outfileName, yamnMsg, 0600)
	if err != nil {
	Warn.Printf("Failed to write raw message to inbound pool: %s", err)
		return
	}
	return
}

// outPoolWrite writes a raw Byte Yamn message to the Outbound pool.
// Oubound message files are prefixed with the recipient address.
func outPoolWrite(yamnMsg []byte, sendTo string) (err error) {
	digest := sha256.New()
	digest.Write([]byte(sendTo))
	digest.Write(yamnMsg)
	poolFileName := "m" + hex.EncodeToString(digest.Sum(nil))[:14]
	var f *os.File
	f, err = os.Create(path.Join(cfg.Files.Pooldir, poolFileName))
	if err != nil {
		Error.Printf("Unable to create pool file: %s", err)
		return
	}
	defer f.Close()
	// Write recipient
	paddedSendTo := []byte(sendTo + strings.Repeat("\x00", 80 - len(sendTo)))
	var numBytes int
	numBytes, err = f.Write(paddedSendTo)
	if err != nil {
		Error.Printf("Failed to write recipient to pool file: %s", err)
		return
	}
	if numBytes != 80 {
		Error.Println("Wrong byte count writing recipient to pool.",
			fmt.Sprintf("Expected=80, Got=%d", numBytes))
		return
	}
	_, err = f.Write(yamnMsg)
	if err != nil {
		Error.Printf("Failed to write payload to pool file: %s", err)
		return
	}
	return
}
