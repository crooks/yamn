// vim: tabstop=2 shiftwidth=2

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/crooks/yamn/crandom"
	"github.com/crooks/yamn/keymgr"
	//"github.com/codahale/blake2"
)

// readMessage tries to read a file containing the plaintext to be sent
func readMessage(filename string) []byte {
	var err error
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Unable to open file\n", filename)
		os.Exit(1)
	}
	msg, err := mail.ReadMessage(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Malformed mail message\n", filename)
		os.Exit(1)
	}
	if flagTo != "" {
		msg.Header["To"] = []string{flagTo}
		if !strings.Contains(flagTo, "@") {
			fmt.Fprintf(
				os.Stderr,
				"%s: Recipient doesn't appear to be an "+
					"email address\n",
				flagTo,
			)
		}
	}
	if flagSubject != "" {
		msg.Header["Subject"] = []string{flagSubject}
	}
	return assemble(*msg)
}

// mixprep fetches the plaintext and prepares it for mix encoding
func mixprep() {
	var err error
	err = os.MkdirAll(cfg.Files.Pooldir, 0700)
	if err != nil {
		panic(err)
	}
	// plain will contain the byte version of the plain text message
	var plain []byte
	// final is consistent across multiple copies so we define it early
	final := newSlotFinal()
	if len(flagArgs) == 0 {
		//fmt.Println("Enter message, complete with headers.  Ctrl-D to finish")
		plain, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else if len(flagArgs) == 1 {
		// A single arg should be the filename
		plain = readMessage(flagArgs[0])
	} else if len(flagArgs) >= 2 {
		// Two args should be recipient and filename
		flagTo = flagArgs[0]
		plain = readMessage(flagArgs[1])
	}
	// plainLen is the length of the plain byte message and can exceed
	// the total body size of the payload.
	plainLen := len(plain)
	if plainLen == 0 {
		fmt.Fprintln(os.Stderr, "No bytes in message")
		os.Exit(1)
	}

	// Download stats URLs if the time is right
	if cfg.Urls.Fetch {
		// Retrieve Mlist2 and Pubring URLs
		timedURLFetch(cfg.Urls.Pubring, cfg.Files.Pubring)
		timedURLFetch(cfg.Urls.Mlist2, cfg.Files.Mlist2)
	}

	// Create the Public Keyring
	Pubring = keymgr.NewPubring(
		cfg.Files.Pubring,
		cfg.Files.Mlist2,
	)
	// Set the Use Expired flag to include remailers with expired keys as
	// candidates.
	if cfg.Stats.UseExpired {
		Pubring.UseExpired()
	}
	err = Pubring.ImportPubring()
	if err != nil {
		log.WithField("pubring", cfg.Files.Pubring).Warn("Pubring import failed")
		return
	}
	// Read the chain from flag or config
	var inChain []string
	if flagChain == "" {
		inChain = strings.Split(cfg.Stats.Chain, ",")
	} else {
		inChain = strings.Split(flagChain, ",")
	}
	if len(inChain) == 0 {
		err = errors.New("Empty input chain")
		return
	}
	var cnum int // Chunk number
	var numc int // Number of chunks
	numc = int(math.Ceil(float64(plainLen) / float64(maxFragLength)))
	final.setNumChunks(numc)
	var exitnode string // Address of exit node (for multiple copy chains)
	var gotExit bool    // Flag to indicate an exit node has been selected
	var firstByte int   // First byte of message slice
	var lastByte int    // Last byte of message slice
	// Fragments loop begins here
	for cnum = 1; cnum <= numc; cnum++ {
		final.setChunkNum(cnum)
		// First byte of message fragment
		firstByte = (cnum - 1) * maxFragLength
		lastByte = firstByte + maxFragLength
		// Don't slice beyond the end of the message
		if lastByte > plainLen {
			lastByte = plainLen
		}
		gotExit = false
		// If no copies flag is specified, use the config file NUMCOPIES
		if flagCopies == 0 {
			flagCopies = cfg.Stats.Numcopies
		}
		if flagCopies > maxCopies {
			// Limit copies to a maximum of 10
			flagCopies = maxCopies
		}
		// Copies loop begins here
		for n := 0; n < flagCopies; n++ {
			if gotExit {
				// Set the last node in the chain to the
				// previously select exitnode
				inChain[len(inChain)-1] = exitnode
			}
			var chain []string
			chain, err = makeChain(inChain)
			if err != nil {
				log.WithError(err).Fatal("Failed to make chain")
			}
			if len(chain) != len(inChain) {
				log.WithError(err).WithFields(log.Fields{
					"expected": len(inChain),
					"got":      len(chain),
				}).Fatal("Chain length mismatch")
			}
			//fmt.Println(chain)
			if !gotExit {
				exitnode = chain[len(chain)-1]
				gotExit = true
			}
			// Retain the entry hop.  We need to mail the message to it.
			sendTo := chain[0]
			// Report the chain if we're running as a client.
			if flagClient {
				log.WithField("chain", strings.Join(chain, ",")).Info("Remailer chain")
			}
			yamnMsg := encodeMsg(
				plain[firstByte:lastByte],
				chain,
				*final,
			)
			writeMessageToPool(sendTo, yamnMsg)
		} // End of copies loop
	} // End of fragments loop

	// Decide if we want to inject a dummy
	if !flagNoDummy && Pubring.HaveStats() && crandom.Dice() < 80 {
		dummy()
	}
}

// encodeMsg encodes a plaintext fragment into mixmaster format.
func encodeMsg(
	plain []byte,
	chain []string,
	final slotFinal) []byte {

	var err error
	var hop string
	m := newEncMessage()
	m.setChainLength(len(chain))
	length := m.setPlainText(plain)
	// Pop the exit remailer address from the chain
	hop = popstr(&chain)
	// Insert the plain message length into the Final Hop header.

	final.setBodyBytes(length)
	slotData := newSlotData()
	// Identify this hop as Packet-Type 1 (Exit).
	slotData.setExit()
	// For exit hops, the AES key can be entirely random.
	slotData.setAesKey(crandom.Randbytes(32))
	// Override the random PacketID so that multi-copy messages all share a
	// common Exit PacketID.
	slotData.setPacketID(final.getPacketID())
	// Encode the (final) Packet Info and store it in the Slot Data.
	slotData.setPacketInfo(final.encode())
	// Get KeyID and NaCl PK for the remailer we're enrypting to.
	remailer, err := Pubring.Get(hop)
	if err != nil {
		log.WithField("remailer", hop).Fatal("Remailer unknown in public keyring")
	}
	// Create a new Header.
	header := newEncodeHeader()
	// Tell the header function what KeyID and PK to NaCl encrypt with.
	header.setRecipient(remailer.Keyid, remailer.PK)
	log.WithFields(log.Fields{
		"remailer": hop,
		"keyid":    remailer.Keyid,
	}).Debug("Encrypting final hop")
	// Only the body needs to be encrypted during Exit encoding.  At all other
	// hops, the entire header stack will also need encrypting.
	m.encryptBody(slotData.aesKey, final.aesIV)
	// Shift all the header down by headerBytes
	m.shiftHeaders()
	// We've already popped an entry from the Chain so were testing for
	// length greater than zero rather than 1.
	if len(chain) > 0 {
		// Single hop chains don't require deterministic headers.  All
		// longer chains do.
		m.deterministic(0)
	}
	// Set the Anti-tag hash in the slotData.
	slotData.setTagHash(m.getAntiTag())
	// Encode the slot data into Byte form.
	slotDataBytes := slotData.encode()
	// Encode the header and insert it into the payload.
	m.insertHeader(header.encode(slotDataBytes))

	// That concludes Exit hop compilation.  Now for intermediates.

	interHops := m.getIntermediateHops()
	for interHop := 0; interHop < interHops; interHop++ {
		inter := newSlotIntermediate()
		inter.setPartialIV(m.getPartialIV(interHop))
		// hop still contains the previous iteration (or exit) address.
		inter.setNextHop(hop)
		// Pop another remailer from the left side of the Chain
		hop = popstr(&chain)
		// Create new Slot Data
		slotData = newSlotData()
		slotData.setAesKey(m.getKey(interHop))
		slotData.setPacketInfo(inter.encode())
		m.encryptAll(interHop)
		m.shiftHeaders()
		m.deterministic(interHop + 1)
		slotData.setTagHash(m.getAntiTag())
		slotDataBytes = slotData.encode()
		header = newEncodeHeader()
		remailer, err := Pubring.Get(hop)
		if err != nil {
			log.WithField("remailer", hop).Fatal("Remailer unknown in public keyring")
		}
		header.setRecipient(remailer.Keyid, remailer.PK)
		log.WithFields(log.Fields{
			"remailer": hop,
			"keyid":    remailer.Keyid,
		}).Debug("Encrypting header")
		m.insertHeader(header.encode(slotDataBytes))
	}
	if len(chain) != 0 {
		panic("After encoding, chain was not empty.")
	}
	return m.getPayload()
}

func injectDummy() {
	// Populate public keyring
	Pubring = keymgr.NewPubring(
		cfg.Files.Pubring,
		cfg.Files.Mlist2,
	)
	Pubring.ImportPubring()
	dummy()
}

// TimedURLFetch attempts to read a url into a file if the file is more
// than an hour old or doesn't exist.
func timedURLFetch(url, filename string) {
	var err error
	var stamp time.Time
	var doFetch bool
	if cfg.Urls.Fetch {
		stamp, err = fileTime(filename)
		if err != nil {
			doFetch = true
		} else if time.Since(stamp) > time.Hour {
			doFetch = true
		} else {
			doFetch = false
		}
		if doFetch {
			log.WithFields(log.Fields{
				"url":      url,
				"filename": filename,
			}).Info("Fetching and storing url")
			err = httpGet(url, filename)
			if err != nil {
				log.WithError(err).WithField("url", url).Warn("Failed to fetch url")
			}
		}
	}
}

// dummy is a simplified client function that sends dummy messages
func dummy() {
	var err error
	plainMsg := []byte("I hope Len approves")
	// Make a single hop chain with a random node
	var inChain []string
	if flagChain == "" {
		inChain = []string{"*", "*"}
	} else {
		inChain = strings.Split(flagChain, ",")
	}
	final := newSlotFinal()
	// Override the default delivery method (255 = Dummy)
	final.setDeliveryMethod(255)
	var chain []string
	chain, err = makeChain(inChain)
	sendTo := chain[0]
	if err != nil {
		log.WithError(err).Warn("Dummy creation failed")
		return
	}
	log.WithField("chain", strings.Join(chain, ",")).Debug("Sending dummy")
	yamnMsg := encodeMsg(plainMsg, chain, *final)
	writeMessageToPool(sendTo, yamnMsg)
	return
}
