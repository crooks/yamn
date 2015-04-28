// vim: tabstop=2 shiftwidth=2

package main

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/quickmail"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
	//"github.com/codahale/blake2"
)

// Start the server process.  If run with --daemon, this will loop forever.
func loopServer() (err error) {
	// Populate public and secret keyrings
	public := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	secret := keymgr.NewSecring(cfg.Files.Secring, cfg.Files.Pubkey)
	public.ImportPubring()
	secret.ImportSecring()
	// Tell the secret keyring some basic info about this remailer
	secret.SetName(cfg.Remailer.Name)
	secret.SetAddress(cfg.Remailer.Address)
	secret.SetExit(cfg.Remailer.Exit)
	secret.SetValidity(cfg.Remailer.Keylife, cfg.Remailer.Keygrace)
	secret.SetVersion(version)
	// Create some dirs if they don't already exist
	createDirs()

	// Open the IDlog
	Trace.Printf("Opening ID Log: %s", cfg.Files.IDlog)
	id, err := idlog.NewInstance(cfg.Files.IDlog)
	if err != nil {
		panic(err)
	}
	defer id.Close()
	// Open the chunk DB
	Trace.Printf("Opening the Chunk DB: %s", cfg.Files.ChunkDB)
	chunkDB := OpenChunk(cfg.Files.ChunkDB)
	chunkDB.SetExpire(cfg.Remailer.ChunkExpire)

	// Expire old entries in the ID Log
	idLogExpire(id)
	// Clean the chunk DB
	chunkClean(*chunkDB)
	// Complain about poor configs
	nagOperator()
	// Run a key purge
	if purgeSecring(secret) == 0 {
		// If there are zero active keys, generate a new one.
		generateKeypair(secret)
	} else {
		/*
			If the operator changes his configuration, (such as upgrading to a new
			version or switching from exit to middleman), the published key will not
			match the configuration.  This element of code writes a new key.txt file
			with current settings.  This only needs to be done if we haven't generated
			a new key.
		*/
		refreshPubkey(secret)
	}

	Info.Printf("Secret keyring contains %d keys", secret.Count())

	// Maintain time of last pool process
	poolProcessTime := time.Now()
	poolProcessDelay := time.Duration(cfg.Pool.Loop) * time.Second

	// Define triggers for timed events
	daily := time.Now()
	hourly := time.Now()
	dayOfMonth := time.Now().Day()

	oneDay := time.Duration(dayLength) * time.Second

	// Actually start the server loop
	if cfg.Remailer.Daemon || flag_daemon {
		Info.Printf("Starting YAMN server: %s", cfg.Remailer.Name)
	} else {
		Info.Printf("Performing routine remailer functions for: %s",
			cfg.Remailer.Name)
	}
	for {
		// Panic is the pooldir doesn't exist
		assertExists(cfg.Files.Pooldir)
		if flag_daemon && time.Now().Before(poolProcessTime) {
			// Process the inbound Pool
			processInpool("i", public, secret, id, *chunkDB)
			// Process the Maildir
			processMail(public, secret, id, *chunkDB)
			// Don't do anything beyond this point until poolProcessTime
			time.Sleep(60 * time.Second)
			continue
		} else if !flag_daemon {
			/*
				When not running as a Daemon, always read sources first. Otherwise, the
				loop will terminate before they're ever read.
			*/
			processInpool("i", public, secret, id, *chunkDB)
			processMail(public, secret, id, *chunkDB)
		}

		// Midnight events
		if time.Now().Day() != dayOfMonth {
			Info.Println("Performing midnight events")
			// Remove expired keys from memory and rewrite a secring file without
			// expired keys.
			if purgeSecring(secret) == 0 {
				generateKeypair(secret)
			}
			// Expire entries in the ID Log
			idLogExpire(id)
			// Expire entries in the chunker
			chunkClean(*chunkDB)
			// Report daily throughput and reset to zeros
			stats.report()
			stats.reset()
			// Reset dayOfMonth to today
			dayOfMonth = time.Now().Day()
		}
		// Daily events
		if time.Since(daily) > oneDay {
			Info.Println("Performing daily events")
			// Complain about poor configs
			nagOperator()
			// Reset today so we don't do these tasks for the next 24 hours.
			daily = time.Now()
		}
		// Hourly events
		if time.Since(hourly) > time.Hour {
			/*
				The following two conditions try to import new pubring and mlist2 URLs.
				If they fail, a warning is logged but no further action is taken.  It's
				better to have old keys/stats than none.
			*/
			// Retrieve Mlist2 and Pubring URLs
			if cfg.Urls.Fetch {
				timedURLFetch(cfg.Urls.Pubring, cfg.Files.Pubring)
				timedURLFetch(cfg.Urls.Mlist2, cfg.Files.Mlist2)
			}
			// Report throughput
			stats.report()
			hourly = time.Now()
		}

		// Select outbound pool files and mail them
		poolOutboundSend()

		// Reset the process time for the next pool read
		poolProcessTime = time.Now().Add(poolProcessDelay)
		// Break out of the loop if we're not running as a daemon
		if !flag_daemon && !cfg.Remailer.Daemon {
			break
		}
	} // End of server loop
	return
}

// refreshPubkey updates an existing Public key file
func refreshPubkey(secret *keymgr.Secring) {
	tmpKey := cfg.Files.Pubkey + ".tmp"
	keyidstr := secret.WriteMyKey(tmpKey)
	Info.Printf("Advertising keyid: %s", keyidstr)
	Trace.Printf("Writing current public key to %s", tmpKey)
	// Overwrite the published key with the refreshed version
	Trace.Printf("Renaming %s to %s", tmpKey, cfg.Files.Pubkey)
	err := os.Rename(tmpKey, cfg.Files.Pubkey)
	if err != nil {
		Warn.Println(err)
	}
}

// purgeSecring deletes old keys and counts active ones.  If no active keys
// are found, it triggers a generation.
func purgeSecring(secret *keymgr.Secring) (active int) {
	active, expired, purged := secret.Purge()
	Info.Printf(
		"Key purge complete. Active=%d, Expired=%d, Purged=%d",
		active, expired, purged)
	return
}

// generateKeypair creates a new keypair and publishes it
func generateKeypair(secret *keymgr.Secring) {
	Info.Println("Generating and advertising a new key pair")
	pub, sec := eccGenerate()
	keyidstr := secret.Insert(pub, sec)
	Info.Printf("Generated new keypair with keyid: %s", keyidstr)
	Info.Println("Writing new Public Key to disc")
	secret.WritePublic(pub, keyidstr)
	Info.Println("Inserting Secret Key into Secring")
	secret.WriteSecret(keyidstr)
}

// idLogExpire deletes old entries in the ID Log
func idLogExpire(id idlog.IDLog) {
	count, deleted := id.Expire()
	Info.Printf("ID Log: Expired=%d, Contains=%d", deleted, count)
}

// chunkClean expires entries from the chunk DB and deletes any stranded files
func chunkClean(chunkDB Chunk) {
	cret, cexp := chunkDB.Expire()
	if cexp > 0 {
		Info.Printf("Chunk expiry complete. Retained=%d, Expired=%d\n", cret, cexp)
	}
	fret, fdel := chunkDB.Housekeep()
	if fdel > 0 {
		Info.Printf("Stranded chunk deletion: Retained=%d, Deleted=%d", fret, fdel)
	}
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
	if cfg.Pool.Rate > 90 && !flag_send {
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

func createDirs() {
	var err error
	err = os.MkdirAll(cfg.Files.IDlog, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", cfg.Files.IDlog, err)
		os.Exit(1)
	}
	err = os.MkdirAll(cfg.Files.Pooldir, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", cfg.Files.Pooldir, err)
		os.Exit(1)
	}
	err = os.MkdirAll(cfg.Files.ChunkDB, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", cfg.Files.ChunkDB, err)
		os.Exit(1)
	}
	err = os.MkdirAll(cfg.Files.Maildir, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", cfg.Files.Maildir, err)
		os.Exit(1)
	}
	mdirnew := path.Join(cfg.Files.Maildir, "new")
	err = os.MkdirAll(mdirnew, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", mdirnew, err)
		os.Exit(1)
	}
	mdircur := path.Join(cfg.Files.Maildir, "cur")
	err = os.MkdirAll(mdircur, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", mdircur, err)
		os.Exit(1)
	}
	mdirtmp := path.Join(cfg.Files.Maildir, "tmp")
	err = os.MkdirAll(mdirtmp, 0700)
	if err != nil {
		Error.Println("Failed to create %s. %s", mdirtmp, err)
		os.Exit(1)
	}
}

// decodeMsg is the actual YAMN message decoder.  It's output is always a
// pooled file, either in the Inbound or Outbound queue.
func decodeMsg(
	rawMsg []byte,
	public *keymgr.Pubring,
	secret *keymgr.Secring,
	id idlog.IDLog,
	chunkDB Chunk) (err error) {
	if len(rawMsg) != messageBytes {
		Error.Printf(
			"Incorrect byte count in binary payload. Expected=%d, Got=%d",
			messageBytes,
			len(rawMsg),
		)
		return
	}
	// Split the message into its component parts
	msgHeader := rawMsg[:headerBytes]
	msgEncHeaders := rawMsg[headerBytes:headersBytes]
	msgBody := rawMsg[headersBytes:]
	/*
		decodeHead returns the raw Bytes of the Inner Header after it has been
		decrypted using the Secret Key that corresponds with the provided KeyID.
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
	if !id.Unique(data.packetID, cfg.Remailer.IDexp) {
		err = errors.New("Packet ID collision")
		return
	}
	//digest := blake2.New(nil)
	digest := sha512.New()
	digest.Write(msgEncHeaders)
	digest.Write(msgBody)
	if !bytes.Equal(digest.Sum(nil), data.tagHash) {
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
		var iv []byte
		// Number of headers to decrypt is one less than max chain length
		for headNum := 0; headNum < maxChainLength-1; headNum++ {
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
		mixMsg = mixMsg[0 : len(mixMsg)+headerBytes]
		copy(mixMsg[encHeadBytes:], fakeHeader)
		// Insert body
		msgLen := len(mixMsg)
		mixMsg = mixMsg[0 : msgLen+bodyBytes]
		copy(mixMsg[msgLen:], msgBody)
		// Create a string from the nextHop, for populating a To header
		sendTo := inter.getNextHop()
		/*
			The following conditional tests if we are the next hop in addition to being
			the current hop.  If we are, then it's better to store the message in the
			inbound pool.  This prevents it being emailed back to us.
		*/
		if sendTo == cfg.Remailer.Address {
			Info.Println(
				"Message loops back to us.",
				"Storing in pool instead of sending it.")
			outfileName := randPoolFilename("i")
			err = ioutil.WriteFile(outfileName, mixMsg, 0600)
			if err != nil {
				Warn.Printf("Failed to write to pool: %s", err)
				return
			}
			stats.outLoop += 1
		} else {
			poolWrite(armor(mixMsg, sendTo), "m")
			stats.outEnc += 1
		} // End of local or remote delivery

		// Decide if we want to inject a dummy
		if !flag_nodummy && randomInt(100) < 21 {
			dummy(public)
			stats.outDummy += 1
		}
		// End of Intermediate type packet handling

	} else if data.packetType == 1 {
		/*
			This section is concerned with final hop messages. i.e. Delivery to final
			recipients.  Currently two methods of delivery are defined:-
			[   0                           SMTP ]
			[ 255         Dummy (Don't deliver) ]
		*/
		final := new(slotFinal)
		err = final.decodeFinal(data.packetInfo)
		if err != nil {
			return
		}
		// Test for dummy message
		if final.deliveryMethod == 255 {
			Trace.Println("Discarding dummy message")
			stats.inDummy += 1
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
			if final.numChunks == 1 {
				poolWrite(msgBody, "m")
			} else {
				chunkFilename := poolWrite(msgBody, "p")
				Trace.Printf(
					"Pooled partial chunk. MsgID=%x, Num=%d, Parts=%d, Filename=%s",
					final.messageID,
					final.chunkNum,
					final.numChunks,
					chunkFilename)
				// Fetch the chunks info from the DB for the given message ID
				chunks := chunkDB.Get(final.messageID, int(final.numChunks))
				// This saves losts of -1's as slices start at 0 and chunks at 1
				cslot := final.chunkNum - 1
				// Test that the slot for this chunk is empty
				if chunks[cslot] != "" {
					Warn.Printf(
						"Duplicate chunk %d in MsgID: %x",
						final.chunkNum, final.messageID)
				}
				// Insert the new chunk into the slice
				chunks[cslot] = chunkFilename
				Trace.Printf("Chunk state: %s", strings.Join(chunks, ","))
				// Test if all chunk slots are populated
				if IsPopulated(chunks) {
					newPoolFile := randPoolFilename("m")
					Trace.Printf("Assembling chunked message into %s", newPoolFile)
					err = chunkDB.Assemble(newPoolFile, chunks)
					if err != nil {
						Warn.Printf("Chunk assembly failed: %s", err)
					}
					// Now the message is assembled into the Pool, the DB record can be deleted
					chunkDB.Delete(final.messageID)
				} else {
					// Write the updated chunk status to the DB
					chunkDB.Insert(final.messageID, chunks)
				}
				return
			}
		} else {
			if final.numChunks == 1 {
				// Need to randhop as we're not an exit remailer
				randhop(msgBody, public)
			} else {
				Warn.Println(
					"Randhopping doesn't support multi-chunk messages. ",
					"As per Mixmaster, this message will be dropped.")
				return
			}
		} // Randhop condition
	} // Intermediate or exit
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
	poolWrite(armor(yamnMsg, sendTo), "m")
	return
}

// dummy is a simplified client function that sends dummy messages
func dummy(public *keymgr.Pubring) {
	var err error
	plainMsg := []byte("I hope Len approves")
	// Make a single hop chain with a random node
	in_chain := []string{"*", "*"}
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
	poolWrite(armor(yamnMsg, sendTo), "m")
	return
}

// remailerFoo responds to requests for remailer-* info
func remailerFoo(subject, sender string) (err error) {
	m := quickmail.NewMessage()
	m.Set("From", cfg.Remailer.Address)
	m.Set("To", sender)
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
		if !cfg.Remailer.Exit {
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
