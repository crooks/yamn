// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"strings"
	"path"
	"io/ioutil"
	"net/mail"
	"crypto/sha256"
	"encoding/hex"
	//"github.com/codahale/blake2"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

func poolOutboundSend() {
	var err error
	var filenames []string
	if flag_send {
		// Read all the pool files
		filenames, err = readDir(cfg.Files.Pooldir, "m")
	} else {
		// Read dynamic mix of outbound files from the Pool
		filenames, err = poolRead()
	}
	if err != nil {
		Warn.Printf("Reading pool failed: %s", err)
		return
	}
	for _, file := range filenames {
		err = mailPoolFile(path.Join(cfg.Files.Pooldir, file))
		if err != nil {
			Warn.Printf("Pool mailing failed: %s", err)
		}
		poolDelete(file)
	}
}

// poolRead returns a dynamic Mix of filenames from the outbound pool.
func poolRead() (selectedPoolFiles []string, err error) {
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		Warn.Printf("Unable to access pool: %s", err)
		return
	}
	poolSize := len(poolFiles)
	var numToSend int // Number of files to return for processing
	if poolSize < cfg.Pool.Size {
		// Pool isn't sufficiently populated
		Trace.Println("Pool insufficiently populated to trigger sending.",
			fmt.Sprintf("Require=%d, Got=%d", cfg.Pool.Size, poolSize))
		return
	} else {
		// Normal pool processing condition
		numToSend = int((float32(poolSize) / 100.0) * float32(cfg.Pool.Rate))
	}
	keys := randInts(len(poolFiles))
	if poolSize > 0 {
		Trace.Printf("Processing %d pool messages.\n", poolSize)
	}
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

// processMail reads the Remailer's Maildir and processes the content
func processMail(
	public *keymgr.Pubring,
	secret *keymgr.Secring,
	id idlog.IDLog,
	chunkDB Chunk) (err error) {

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
			err = decodeMsg(msg, public, secret, id, chunkDB)
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

// processInpool is similar to processMail but reads the Inbound Pool
func processInpool(
	prefix string,
	public *keymgr.Pubring,
	secret *keymgr.Secring,
	id idlog.IDLog,
	chunkDB Chunk) {
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
		err = decodeMsg(msg, public, secret, id, chunkDB)
		if err != nil {
			Warn.Println(err)
		}
		poolDelete(f)
		processed++
	}
	if poolSize > 0 {
		Trace.Printf("Inbound pool processing complete. Read=%d, Decoded=%d",
			poolSize, processed)
	}
}

// PoolWrite writes a raw Byte Yamn message to the Outbound pool with a prefix
// string.
func poolWrite(yamnMsg []byte, prefix string) (poolFileName string) {
	/*
	Currently supported prefixs are:-
	[ m              Oubound message (final or intermediate) ]
	[ i          Inbound message (destined for this remailer ]
	[ p               Partial message chunk needing assembly ]
	*/
	digest := sha256.New()
	digest.Write(yamnMsg)
	poolFileName = prefix + hex.EncodeToString(digest.Sum(nil))[:14]
	fqfn := path.Join(cfg.Files.Pooldir, poolFileName)
	err := ioutil.WriteFile(fqfn, yamnMsg, 0600)
	if err != nil {
		panic(err)
	}
	return
}
