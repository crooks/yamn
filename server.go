// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"path"
	"bytes"
	"time"
	"strings"
	"errors"
	"io/ioutil"
	"crypto/sha512"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/quickmail"
	//"github.com/codahale/blake2"
)

// Start the server process.  If run with --daemon, this will loop forever.
func loopServer() (err error) {
	var filenames []string
	// Populate public and secret keyrings
	public := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	secret := keymgr.NewSecring(cfg.Files.Secring, cfg.Files.Pubkey)
	public.ImportPubring()
	secret.ImportSecring()
	// Tell the secret keyring some basic info about this remailer
	secret.SetName(cfg.Remailer.Name)
	secret.SetAddress(cfg.Remailer.Address)
	secret.SetExit(cfg.Remailer.Exit)
	secret.SetValidity(keyValidityDays)
	secret.SetVersion(version)
	// Create some dirs if they don't already exist
	err = os.MkdirAll(cfg.Files.IDlog, 0700)
	if err != nil {
		return
	}
	err = os.MkdirAll(cfg.Files.Pooldir, 0700)
	if err != nil {
		return
	}
	// Open the IDlog
	Trace.Printf("Opening ID Log: %s", cfg.Files.IDlog)
	id, err := idlog.NewInstance(cfg.Files.IDlog)
	if err != nil {
		panic(err)
	}
	defer id.Close()
	// Expire old entries in the ID Log
	idLogExpire(id)
	// Complain about poor configs
	nagOperator()
	/*
	Ascertain the Keyid we're advertising.  This only needs to be done once at
	server startup as the act of new key publication sets the keyid to the newly
	generated key.
	*/
	err = secret.SetMyKeyid()
	if err != nil {
		Info.Printf("Error setting Keyid: %s", err)
		generateKeypair(secret)
	} else {
		Info.Printf("Advertising existing keyid: %s", secret.GetMyKeyidStr())
		// Write a tmp pub.key using current config
		tmpKey := cfg.Files.Pubkey + ".tmp"
		err = secret.WriteMyKey(tmpKey)
		if err != nil {
			Warn.Println(err)
		} else {
			// Overwrite the published key with the refreshed version
			err = os.Rename(tmpKey, cfg.Files.Pubkey)
			if err != nil {
				Warn.Println(err)
			}
		}
	}
	Info.Printf("Secret keyring contains %d keys", secret.Count())

	// Maintain time of last pool process
	poolProcessTime := time.Now()
	poolProcessDelay := time.Duration(cfg.Pool.Loop) * time.Second

	// Make a note of what day it is
	today := time.Now()
	oneDay := time.Duration(dayLength) * time.Second

	// Actually start the server loop
	if cfg.Remailer.Daemon || flag_daemon {
		Info.Printf("Starting YAMN server: %s", cfg.Remailer.Name)
	} else {
		Info.Printf("Performing routine remailer functions for: %s",
			cfg.Remailer.Name)
	}
	for {
		if flag_daemon && time.Now().Before(poolProcessTime) {
			// Process the inbound Pool
			processInpool("i", public, secret, id)
			// Process the Maildir
			processMail(public, secret, id)
			// Don't do anything beyond this point until poolProcessTime
			time.Sleep(60 * time.Second)
			continue
		} else if ! flag_daemon {
			/*
			When not running as a Daemon, always read sources first. Otherwise, the
			loop will terminate before they're ever read.
			*/
			processInpool("i", public, secret, id)
			processMail(public, secret, id)
		}

		// Test if it's time to do daily events
		if time.Since(today) > oneDay {
			Info.Println("Performing daily events")
			// Try to validate the advertised key on Secring
			valid, err := secret.Validate()
			if err != nil {
				Warn.Printf("%s: Failed to validate key in Secring",
					cfg.Files.Secring)
				generateKeypair(secret)
			} else if valid {
				Info.Printf("Advertising current keyid: %s", secret.GetMyKeyidStr())
			} else {
				Info.Printf("%s has expired, will generate a new key pair",
					secret.GetMyKeyidStr())
				generateKeypair(secret)
			}
			Info.Printf("Secret keyring contains %d keys", secret.Count())
			// Remove expired keys from memory and rewrite a secring file without
			// expired keys.
			secret.Purge("secring.new")
			// Expire entries in the ID Log
			idLogExpire(id)
			// Complain about poor configs
			nagOperator()
			// Reset today so we don't do these tasks for the next 24 hours.
			today = time.Now()
		}

		// Test if in-memory pubring is current
		if public.KeyRefresh() {
			// Time to re-read the pubring file
			Info.Printf("Reimporting keyring: %s", cfg.Files.Pubring)
			public.ImportPubring()
		}
		filenames, err = poolRead()
		if err != nil {
			Warn.Printf("Reading pool failed: %s", err)
		}
		for _, file := range filenames {
			err = mailPoolFile(path.Join(cfg.Files.Pooldir, file))
			if err != nil {
				Warn.Printf("Pool mailing failed: %s", err)
			}
			poolDelete(file)
		}
		poolProcessTime = time.Now().Add(poolProcessDelay)
		// Break out of the loop if we're not running as a daemon
		if ! flag_daemon && ! cfg.Remailer.Daemon {
			break
		}
		// Just for debugging
		//for _, k := range secret.ListKeyids() {
		//	Trace.Printf("Known secret key: %s", k)
		//}
	} // End of server loop
	return
}

// generateKeypair creates a new keypair and publishes it
func generateKeypair(secret *keymgr.Secring) {
	Info.Println("Generating and advertising a new key pair")
	pub, sec := eccGenerate()
	keyidstr := secret.Insert(pub, sec)
	secret.WritePublic(pub, keyidstr)
	secret.WriteSecret(keyidstr)
	Info.Printf("Advertising new Keyid: %s", keyidstr)
}

// idLogExpire deletes old entries in the ID Log
func idLogExpire(id idlog.IDLog) {
	count, deleted := id.Expire()
	Info.Printf("ID Log: Expired=%d, Contains=%d", deleted, count)
}

// nagOperator prompts a remailer operator about poor practices.
func nagOperator() {
	// Complain about excessively small loop values.
	if cfg.Pool.Loop < 60 {
		Warn.Println(
			fmt.Sprintf("Loop time of %d is excessively low. ", cfg.Pool.Loop),
			"Will loop every 60 seconds. A higher setting is recommended.")
	}
	// Complain about high pool rates.
	if cfg.Pool.Rate > 90 && ! flag_send {
		Warn.Println(
			fmt.Sprintf("Your pool rate of %d is excessively", cfg.Pool.Rate),
			"high. Unless testing, a lower setting is recommended.")
	}
	// Complain about running a remailer with flag_send
	if flag_send && flag_remailer {
		Warn.Println(
			"Your remailer will flush the outbound pool every",
			fmt.Sprintf("%d seconds. Unless you're testing,", cfg.Pool.Loop),
			"this is probably not what you want.")
	}
}

// decodeMsg is the actual YAMN message decoder.  It's output is always a pooled
// file, either in the Inbound or Outbound queue.
func decodeMsg(rawMsg []byte, public *keymgr.Pubring, secret *keymgr.Secring, id idlog.IDLog) (err error) {
	// Split the message into its component parts
	msgHeader := rawMsg[:headerBytes]
	msgEncHeaders := rawMsg[headerBytes:headersBytes]
	msgBody := rawMsg[headersBytes:]
	if len(msgBody) != bodyBytes {
		Warn.Printf("Incorrect body size during dearmor. Expected=%d, Got=%d",
			bodyBytes, len(msgBody))
		return
	}
	var iv []byte
	/*
	decodeHead only returns the decrypted slotData bytes.  The other fields are
	only concerned with performing the decryption.
	*/
	var decodedHeader []byte
	decodedHeader, err = decodeHead(msgHeader, secret)
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
	digest.Write(msgEncHeaders)
	digest.Write(msgBody)
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
			copy(
				msgEncHeaders[sbyte:ebyte],
				AES_CTR(msgEncHeaders[sbyte:ebyte], data.aesKey, iv))
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
		copy(msgBody, AES_CTR(msgBody, data.aesKey, iv))
		// At this point there should be zero bytes left in the inter IV pool
		if len(inter.aesIVs) != 0 {
			err = fmt.Errorf(
				"IV pool not empty.  Contains %d bytes.", len(inter.aesIVs))
			return
		}
		// Insert encrypted headers
		mixMsg := make([]byte, encHeadBytes, messageBytes)
		copy(mixMsg, msgEncHeaders)
		// Insert fake header
		mixMsg = mixMsg[0:len(mixMsg) + headerBytes]
		copy(mixMsg[encHeadBytes:], fakeHeader)
		// Insert body
		msgLen := len(mixMsg)
		mixMsg = mixMsg[0:msgLen + bodyBytes]
		copy(mixMsg[msgLen:], msgBody)
		// Create a string from the nextHop, for populating a To header
		sendTo := inter.getNextHop()
		if sendTo == cfg.Remailer.Address {
			Info.Println("Message loops back to us.",
				"Storing in pool instead of sending it.")
			outfileName := randPoolFilename("i")
			err = ioutil.WriteFile(outfileName, mixMsg, 0600)
			if err != nil {
				Warn.Printf("Failed to write to pool: %s", err)
				return
			}
		} else {
			outPoolWrite(armor(mixMsg, sendTo))
		} // End of local or remote delivery
	} else if data.packetType == 1 {
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
		msgBody = AES_CTR(msgBody[:final.bodyBytes], data.aesKey, final.aesIV)
		// If delivery methods other than SMTP are ever supported, something needs
		// to happen around here.
		if final.deliveryMethod != 0 {
			err = fmt.Errorf("Unsupported Delivery Method: %d", final.deliveryMethod)
			return
		}
		if cfg.Remailer.Exit {
			outPoolWrite(msgBody)
		} else {
			// Need to randhop as we're not an exit remailer
			randhop(msgBody, public)
		} // Randhop condition
	} // Intermediate or exit

	// Decide if we want to inject a dummy
	if ! flag_nodummy && randomInt(20) < 3 {
		dummy(public)
	}
	return
}

// randhop is a simplified client function that does single-hop encodings
func randhop(plainMsg []byte, public *keymgr.Pubring) {
	var err error
	if len(plainMsg) == 0 {
		Info.Println("Zero-byte message during randhop, ignoring it.")
		return
	}
	// Make a single hop chain with a random node
	in_chain := []string{"*"}
	final := new(slotFinal)
	final.deliveryMethod = 0
	final.messageID = randbytes(16)
	final.chunkNum = uint8(1)
	final.numChunks = uint8(1)
	var chain []string
	chain, err = makeChain(in_chain, public)
	if err != nil {
		Warn.Println(err)
		return
	}
	if len(chain) != 1 {
		err = fmt.Errorf("Randhop chain must be single hop.  Got=%d", len(chain))
		panic(err)
	}
	Trace.Printf("Performing a random hop to Exit Remailer: %s.", chain[0])
	packetid := randbytes(16)
	yamnMsg, sendTo := encodeMsg(plainMsg, packetid, chain, *final, public)
	outPoolWrite(armor(yamnMsg, sendTo))
	return
}

// dummy is a simplified client function that sends dummy messages
func dummy(public *keymgr.Pubring) {
	var err error
	plainMsg := []byte("I hope Len approves")
	// Make a single hop chain with a random node
	in_chain := []string{"*","*"}
	final := new(slotFinal)
	final.deliveryMethod = 255
	final.messageID = randbytes(16)
	final.chunkNum = uint8(1)
	final.numChunks = uint8(1)
	var chain []string
	chain, err = makeChain(in_chain, public)
	if err != nil {
		Warn.Printf("Dummy creation failed: %s", err)
		return
	}
	Trace.Printf("Sending dummy through: %s.", strings.Join(chain, ","))
	packetid := randbytes(16)
	yamnMsg, sendTo := encodeMsg(plainMsg, packetid, chain, *final, public)
	outPoolWrite(armor(yamnMsg, sendTo))
	return
}

// remailerFoo responds to requests for remailer-* info
func remailerFoo(subject, sender string) (err error) {
	m := quickmail.NewMessage()
	m.Set("From", cfg.Mail.EnvelopeSender)
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
		m.Set(
			"Subject",
			fmt.Sprintf("Capabilities of the %s remailer", cfg.Remailer.Name))
		m.Text(fmt.Sprintf("Remailer-Type: Mixmaster %s\n", version))
		m.Text("Supported Formats:\n   Mixmaster\n")
		m.Text(fmt.Sprintf("Pool size: %d\n", cfg.Pool.Size))
		m.Text(fmt.Sprintf("Maximum message size: %d kB\n", cfg.Remailer.MaxSize))
		m.Text("The following header lines will be filtered:\n")
		m.Text(
			fmt.Sprintf("\n$remailer{\"%s\"} = \"<%s>",
			cfg.Remailer.Name, cfg.Remailer.Address))
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
		m.Set(
			"Subject",
			fmt.Sprintf("Admin key for the %s remailer", cfg.Remailer.Name))
		m.Filename = cfg.Files.Adminkey
	} else if strings.HasPrefix(subject, "remailer-help") {
		// remailer-help
		Trace.Printf("remailer-help request from %s", sender)
		m.Set(
			"Subject",
			fmt.Sprintf("Your help request for the %s Anonymous Remailer",
			cfg.Remailer.Name))
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
	err = mailBytes(msg, []string{sender})
	if err != nil {
		Warn.Println("Failed to send %s to %s", subject, sender)
		return
	}
	return
}
