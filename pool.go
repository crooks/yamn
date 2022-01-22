// vim: tabstop=2 shiftwidth=2

package main

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/mail"
	"os"
	"path"
	"strings"
	"time"

	//"github.com/codahale/blake2"
	"github.com/crooks/yamn/crandom"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

// serverPoolOutboundSend is intended to be run concurrently with the server
// daemon.  It sends messages from the pool at timed intervals.
func serverPoolOutboundSend() {
	if cfg.Pool.Loop < 120 {
		Warn.Printf(
			"Pool loop of %d Seconds is too short. "+
				"Adjusting to minimum of 120 Seconds.",
			cfg.Pool.Loop,
		)
		cfg.Pool.Loop = 120
	}
	sleepFor := time.Duration(cfg.Pool.Loop) * time.Second
	for {
		// Read dynamic mix of outbound files from the Pool
		// filenames = dynamicMix()
		// Read binomialMix of outbound files from the Pool
		filenames := binomialMix()
		for _, filename := range filenames {
			emailPoolFile(filename)
		}
		time.Sleep(sleepFor)
	}
}

// poolOutboundSend flushes the outbound pool.  This should only be performed
// on clients, where all messages should be sent instantly after creation.
func poolOutboundSend() {
	var err error
	if cfg.Remailer.Daemon || flags.Daemon {
		// This should never happen.  If the server is started as a
		// daemon, the serverPoolOutboundSend process is initiated and
		// runs in an endless loop.  This function would conflict with
		// it.
		err = errors.New("cannot flush pool when running as a daemon")
		panic(err)
	}
	var filenames []string
	// Read all the pool files
	filenames, err = readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		Warn.Printf("Reading pool failed: %s", err)
		return
	}
	if flags.Remailer {
		// During normal operation, the pool shouldn't be flushed.
		Warn.Println("Flushing outbound remailer pool")
	}
	for _, filename := range filenames {
		emailPoolFile(filename)
	}
}

// emailPoolFile tries to email a given file from the Pool.  If conditions are
// met, the file is then deleted.
func emailPoolFile(filename string) {
	delFlag, err := mailPoolFile(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		Warn.Printf("Pool mailing failed: %s", err)
		if delFlag {
			// If delFlag is true, we delete the file, even though
			// mailing failed.
			poolDelete(filename)
		}
	} else {
		stats.outMail++
		poolDelete(filename)
	}
}

// dynamicMix returns a dynamic Mix of filenames from the outbound pool.
func dynamicMix() []string {
	var empty []string
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		Warn.Printf("Unable to access pool: %s", err)
		return empty
	}
	poolSize := len(poolFiles)
	if poolSize < cfg.Pool.Size || poolSize == 0 {
		// Pool isn't sufficiently populated
		Trace.Printf(
			"Pool insufficiently populated to trigger sending."+
				"Require=%d, Got=%d",
			cfg.Pool.Size,
			poolSize,
		)
		return empty
	}
	// Shuffle the slice of filenames now as we're going to return a
	// setset of the overall pool.
	crandom.Shuffle(poolFiles)
	// Normal pool processing condition
	numToSend := int((float32(poolSize) / 100.0) * float32(cfg.Pool.Rate))
	Trace.Printf("Processing %d pool messages.\n", poolSize)
	return poolFiles[:numToSend]
}

// getBatchSize takes a Pool size and returns a corresponding batch size.  This
// is intended for use with Binomial Mix Pools.
func getBatchSize(poolSize int) int {
	/*
		poolSize         -  Number of files in the pool
		cfg.Pool.Size    -  Minimum messages to keep in pool
		cfg.Pool.MinSend -  Minimum number of messages to consider sending
		cfg.Pool.Rate    -  Percentage of Pool in the batch
	*/
	if poolSize < (cfg.Pool.Size + cfg.Pool.MinSend) {
		return 0
	}
	sendable := poolSize - cfg.Pool.Size
	rate := float32(cfg.Pool.Rate) / 100
	maxSend := max(1, int(float32(poolSize)*rate))
	return min(sendable, maxSend)
}

// binomialMix returns a batched subset of Pool files to send using a
// Probability B/P method of selecting each file.
func binomialMix() (batch []string) {
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		Warn.Printf("Unable to access pool: %s", err)
		return
	}
	poolSize := len(poolFiles)
	batchSize := getBatchSize(poolSize)
	if batchSize == 0 {
		Trace.Printf("Binomial Mix Pool: Size=%d", poolSize)
		// If the batch is empty, don't bother to process it.
		return
	}
	// Shuffle the slice of filenames now as we're only going to consider a
	// subset in the following loop.
	crandom.Shuffle(poolFiles)
	// Multiply probability by 255 as dice() returns 0-255.
	prob := int((float32(batchSize) / float32(poolSize)) * 255)
	// Test each pool filename against a biased coin-toss
	for _, s := range poolFiles[:batchSize] {
		if prob >= crandom.Dice() {
			batch = append(batch, s)
		}
	}
	Trace.Printf(
		"Binomial Mix Pool: Size=%d, Batch=%d, Prob=%d/255, Sending=%d",
		poolSize,
		batchSize,
		prob,
		len(batch),
	)
	return
}

// Delete a given file from the pool
func poolDelete(filename string) {
	// Delete a pool file
	err := os.Remove(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		Error.Printf("Failed to remove %s from %s\n", filename, cfg.Files.Pooldir)
	} else {
		Trace.Printf("Deleted %s from Pool", filename)
	}
}

// processMail reads the Remailer's Maildir and processes the content
func processMail(secret *keymgr.Secring) (err error) {
	dir := maildir.Dir(cfg.Files.Maildir)
	// Get a list of Maildir keys from the directory
	keys, err := dir.Unseen()
	if err != nil {
		return
	}
	newMsgs := len(keys)
	if newMsgs == 0 {
		// Nothing to do, move along!
		return
	}
	Trace.Printf(
		"Reading %d messages from %s\n",
		newMsgs,
		cfg.Files.Maildir,
	)
	// Increment inbound Email counter
	stats.inMail += newMsgs
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
			if err == nil {
				// Increments stats counter
				stats.inRemFoo++
			} else {
				Info.Println(err)
			}
			err = dir.Purge(key)
			if err != nil {
				Warn.Printf(
					"Cannot delete remailer-foo mail: %s",
					err,
				)
			}
			// Nothing else to do, move on to the next message
			continue
		}
		// It's not a remailer-foo request so assume a remailer message
		var mailMsg *mail.Message
		mailMsg, err := dir.Message(key)
		if err != nil {
			Warn.Printf(
				"%s: Reading message failed with: %s",
				key,
				err,
			)
			continue
		}
		var msg []byte
		// Convert the armored Yamn message to its byte components
		msg, err = stripArmor(mailMsg.Body)
		if err != nil {
			Info.Println(err)
			continue
		}
		if msg == nil {
			Warn.Println("Dearmor returned zero bytes")
			continue
		}
		err = decodeMsg(msg, secret)
		if err != nil {
			Info.Println(err)
		}
		err = dir.Purge(key)
		if err != nil {
			Warn.Printf("Cannot delete mail: %s", err)
		}
	} // Maildir keys loop
	return
}

// processInpool is similar to processMail but reads the Inbound Pool
func processInpool(prefix string, secret *keymgr.Secring) {
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
		err = decodeMsg(msg, secret)
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

// randPoolFilename returns a random filename with a given prefix.  This should
// be used in all instances where a new pool file is required.
func randPoolFilename(prefix string) (fqfn string) {
	for {
		outfileName := prefix + hex.EncodeToString(crandom.Randbytes(7))
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

// newPoolFile opens a new file in Write mode and sets user-only permissions
func newPoolFile(prefix string) (f *os.File, err error) {
	/*
		Currently supported prefixs are:-
		[ m              Oubound message (final or intermediate) ]
		[ i          Inbound message (destined for this remailer ]
		[ p               Partial message chunk needing assembly ]
	*/
	fqfn := randPoolFilename(prefix)
	f, err = os.OpenFile(fqfn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	return
}

// writeMessageToPool requires a recipient address (another remailer) and a
// payload (that gets Base64 armored).
func writeMessageToPool(sendTo string, payload []byte) {
	f, err := newPoolFile("m")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// Add mail headers to the pool file
	writeInternalHeader(f)
	writeMailHeaders(f, sendTo)
	// Armor the payload
	armor(f, payload)
}

// writePlainToPool writes a plaintext file to the pool and returns the filename
func writePlainToPool(payload []byte, prefix string) (filename string) {
	f, err := newPoolFile(prefix)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	writeInternalHeader(f)
	f.Write(payload)
	_, filename = path.Split(f.Name())
	return
}
