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

func mailRead(public *keymgr.Pubring, secret *keymgr.Secring, id idlog.IDLog) (err error) {
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
			var msg *yamnMsg
			// Convert the armored Yamn message to its byte components
			msg, err = stripArmor(mailMsg.Body)
			if err != nil {
				Info.Println(err)
			}
			err = msg.decodeMsg(secret, id)
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

type yamnMsg struct {
	header []byte // First message header
	encHeaders []byte // Other header slots
	body []byte // Message body
}

func newYamnMsg() *yamnMsg {
	return &yamnMsg{
		header: make([]byte, headerBytes),
		encHeaders: make([]byte, encHeadBytes),
		body: make([]byte, bodyBytes),
	}
}

// stripArmor takes a Mixmaster formatted message from an ioreader and
// returns its payload as a byte slice
func stripArmor(reader io.Reader) (msg *yamnMsg, err error) {
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
	msg = newYamnMsg()
	msg.header = payload[:headerBytes]
	msg.encHeaders = payload[headerBytes:headersBytes]
	msg.body = payload[headersBytes:]
	if len(msg.body) != bodyBytes {
		Warn.Printf("Incorrect body size during dearmor. Expected=%d, Got=%d",
			bodyBytes, len(msg.body))
		return
	}
	return
}

func (msg *yamnMsg) decodeMsg(secret *keymgr.Secring, id idlog.IDLog) (err error) {
	var iv []byte
	/*
	decodeHead only returns the decrypted slotData bytes.  The other fields are
	only concerned with performing the decryption.
	*/
	var decodedHeader []byte
	decodedHeader, err = decodeHead(msg.header, secret)
	if err != nil {
		return
	}
	// data contains the slotData struct
	data := new(slotData)
	err = data.decodeData(decodedHeader)
	if err != nil {
		return
	}
	// Test uniqueness of packet ID
	if ! id.Unique(data.packetID, cfg.Remailer.IDexp) {
		err = errors.New("Packet ID collision")
		return
	}
	//digest := blake2.New(nil)
	digest := sha512.New()
	digest.Write(msg.encHeaders)
	digest.Write(msg.body)
	if ! bytes.Equal(digest.Sum(nil), data.tagHash) {
		err = fmt.Errorf("Digest mismatch on Anti-tag hash")
		return
	}
	if data.packetType == 0 {
		Trace.Println("This is an Intermediate type message")
		// inter contains the slotIntermediate struct
		inter := new(slotIntermediate)
		err = inter.decodeIntermediate(data.packetInfo)
		if err != nil {
			return
		}
		// Number of headers to decrypt is one less than max chain length
		for headNum := 0; headNum < maxChainLength - 1; headNum++ {
			iv, err = sPopBytes(&inter.aesIVs, 16)
			if err != nil {
				return
			}
			sbyte := headNum * headerBytes
			ebyte := (headNum + 1) * headerBytes
			copy(msg.encHeaders[sbyte:ebyte], AES_CTR(msg.encHeaders[sbyte:ebyte], data.aesKey, iv))
		}
		// The tenth IV is used to encrypt the deterministic header
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			return
		}
		//fmt.Printf("Fake: Key=%x, IV=%x\n", data.aesKey[:10], iv[:10])
		fakeHeader := make([]byte, headerBytes)
		copy(fakeHeader, AES_CTR(fakeHeader, data.aesKey, iv))
		// Body is decrypted with the final IV
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			return
		}
		copy(msg.body, AES_CTR(msg.body, data.aesKey, iv))
		// At this point there should be zero bytes left in the inter IV pool
		if len(inter.aesIVs) != 0 {
			err = fmt.Errorf("IV pool not empty.  Contains %d bytes.", len(inter.aesIVs))
			return
		}
		digest := sha256.New()
		digest.Write(inter.nextHop)
		digest.Write(msg.body)
		poolFileName := "m" + hex.EncodeToString(digest.Sum(nil))[:14]
		var f *os.File
		f, err = os.Create(path.Join(cfg.Files.Pooldir, poolFileName))
		if err != nil {
			Warn.Printf("Unable to create pool file: %s", err)
			return
		}
		defer f.Close()
		// numBytes is populated with the number of Bytes written by each Write.
		var numBytes int
		// Write nextHop
		numBytes, err = f.Write(inter.nextHop)
		if err != nil {
			Error.Printf("Failed to write Next Hop to pool: %s", err)
			return
		}
		if numBytes != 80 {
			err = fmt.Errorf("Wrong byte count writing nextHop. Expected=80, Got=%d",
				numBytes)
			return
		}
		// Write headers
		numBytes, err = f.Write(msg.encHeaders)
		if err != nil {
			Error.Printf("Failed to write headers to pool: %s", err)
			return
		}
		if numBytes != encHeadBytes {
			err = fmt.Errorf("Wrong byte count writing headers. Expected=%d, Got=%d",
				encHeadBytes, numBytes)
			return
		}
		// Write fake header
		numBytes, err = f.Write(fakeHeader)
		if err != nil {
			Error.Printf("Failed to write fake header to pool: %s", err)
			return
		}
		if numBytes != headerBytes {
			err = fmt.Errorf("Wrong byte count writing fake header. Expected=%d, Got=%d",
				headerBytes, numBytes)
			return
		}
		// Write body
		numBytes, err = f.Write(msg.body)
		if err != nil {
			Error.Printf("Failed to write body to pool: %s", err)
			return
		}
		if numBytes != bodyBytes {
			err = fmt.Errorf("Wrong byte count writing body. Expected=%d, Got=%d",
				bodyBytes, numBytes)
			return
		}
		return
	} else if data.packetType == 1 {
		Trace.Println("This is an Exit type message")
		final := new(slotFinal)
		err = final.decodeFinal(data.packetInfo)
		if err != nil {
			return
		}
		// Test for dummy message
		if final.deliveryMethod == 255 {
			Trace.Println("Discarding dummy message")
			return
		}
		msg.body = AES_CTR(msg.body[:final.bodyBytes], data.aesKey, final.aesIV)
		// If delivery methods other than SMTP are ever supported, something needs
		// to happen around here.
		if final.deliveryMethod != 0 {
			err = fmt.Errorf("Unsupported Delivery Method: %d", final.deliveryMethod)
			return
		}
		if cfg.Remailer.Exit {
			var recipients []string
			recipients, err = testMail(msg.body)
			if err != nil {
				return
			}
			for _, sendto := range recipients {
				if cfg.Mail.Sendmail {
					err = sendmail(msg.body, sendto)
					if err != nil {
						Warn.Println("Sendmail failed")
						return
					}
				} else {
					err = SMTPRelay(msg.body, sendto)
					if err != nil {
						Warn.Println("SMTP relay failed")
						return
					}
				} // End of Sendmail or Relay condition
			} // recipients loop
		} else {
			// Need to randhop as we're not an exit remailer
			//TODO Sort out randhopping
			//randhop(msg.body, public)
		} // End of Exit or Randhop
	} // Intermediate or exit
	return
}
