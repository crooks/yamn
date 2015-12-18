// vim: tabstop=2 shiftwidth=2

package main

import (
	"errors"
	"fmt"
	"github.com/crooks/yamn/keymgr"
	"github.com/dchest/blake2s"
	"io/ioutil"
	"math"
	"net/mail"
	"os"
	"strings"
	"time"
	//"github.com/codahale/blake2"
)

func headDiag(headers []byte) {
	fmt.Printf("Length: %d\n", len(headers))
	for h := 0; h < maxChainLength; h++ {
		sbyte := h * headerBytes
		ebyte := sbyte + 20
		fmt.Printf("sbyte=%d, Header: %d, Starts: %x\n", sbyte, h, headers[sbyte:ebyte])
	}
}

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
	if flag_to != "" {
		msg.Header["To"] = []string{flag_to}
		if !strings.Contains(flag_to, "@") {
			fmt.Fprintf(os.Stderr, "%s: Recipient doesn't appear to be an email address\n", flag_to)
		}
	}
	if flag_subject != "" {
		msg.Header["Subject"] = []string{flag_subject}
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
	var message []byte
	final := newSlotFinal()
	if len(flag_args) == 0 {
		//fmt.Println("Enter message, complete with headers.  Ctrl-D to finish")
		message, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else if len(flag_args) == 1 {
		// A single arg should be the filename
		message = readMessage(flag_args[0])
	} else if len(flag_args) >= 2 {
		// Two args should be recipient and filename
		flag_to = flag_args[0]
		message = readMessage(flag_args[1])
	}
	msglen := len(message)
	if msglen == 0 {
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
	pubring := keymgr.NewPubring(
		cfg.Files.Pubring,
		cfg.Files.Mlist2,
		cfg.Stats.UseExpired,
	)
	err = pubring.ImportPubring()
	if err != nil {
		Warn.Printf("Pubring import failed: %s", cfg.Files.Pubring)
		return
	}
	// Read the chain from flag or config
	var in_chain []string
	if flag_chain == "" {
		in_chain = strings.Split(cfg.Stats.Chain, ",")
	} else {
		in_chain = strings.Split(flag_chain, ",")
	}
	if len(in_chain) == 0 {
		err = errors.New("Empty input chain")
		return
	}
	var cnum int // Chunk number
	var numc int // Number of chunks
	numc = int(math.Ceil(float64(msglen) / float64(maxFragLength)))
	final.numChunks = uint8(numc)
	cnum = 1
	var exitnode string // Address of exit node (for multiple copy chains)
	var got_exit bool   // Flag to indicate an exit node has been selected
	var packetid []byte // Final hop Packet ID
	var first_byte int  // First byte of message slice
	var last_byte int   // Last byte of message slice
	// Fragments loop begins here
	for cnum = 1; cnum <= numc; cnum++ {
		final.chunkNum = uint8(cnum)
		// First byte of message fragment
		first_byte = (cnum - 1) * maxFragLength
		last_byte = first_byte + maxFragLength
		// Don't slice beyond the end of the message
		if last_byte > msglen {
			last_byte = msglen
		}
		got_exit = false
		packetid = randbytes(16)
		// If no copies flag is specified, use the config file NUMCOPIES
		if flag_copies == 0 {
			flag_copies = cfg.Stats.Numcopies
		}
		if flag_copies > maxCopies {
			// Limit copies to a maximum of 10
			flag_copies = maxCopies
		}
		// Copies loop begins here
		for n := 0; n < flag_copies; n++ {
			if got_exit {
				// Set the last node in the chain to the previously select exitnode
				in_chain[len(in_chain)-1] = exitnode
			}
			var chain []string
			chain, err = makeChain(in_chain, pubring)
			if err != nil {
				Error.Println(err)
				os.Exit(0)
			}
			if len(chain) != len(in_chain) {
				err = fmt.Errorf(
					"Chain length mismatch.  In=%d, Out=%d",
					len(in_chain), len(chain))
				panic(err)
			}
			//fmt.Println(chain)
			if !got_exit {
				exitnode = chain[len(chain)-1]
				got_exit = true
			}
			// Report the chain if we're running as a client.  UseExpired is an
			// Echolot workaround to allow pinging of expired keys.  It's used here
			// to prevent stdout messages in the pingd.log.
			if flag_client && !cfg.Stats.UseExpired {
				fmt.Printf("Chain: %s\n", strings.Join(chain, ","))
			}
			yamnMsg, sendTo := encodeMsg(
				message[first_byte:last_byte],
				packetid,
				chain,
				*final,
				pubring)
			poolWrite(armor(yamnMsg, sendTo), "m")
		} // End of copies loop
	} // End of fragments loop

	// Decide if we want to inject a dummy
	if !flag_nodummy && pubring.Stats && randomInt(7) < 3 {
		dummy(pubring)
	}
}

// encodeMsg encodes a plaintext fragment into mixmaster format.
func encodeMsg(
	msg, packetid []byte,
	chain []string,
	final slotFinal,
	pubring *keymgr.Pubring) (payload []byte, sendto string) {

	var err error
	chainLength := len(chain)
	// Retain the address of the entry remailer, the message must be sent to it.
	sendto = chain[0]
	final.bodyBytes = len(msg)
	body := make([]byte, bodyBytes)
	headers := make([]byte, headersBytes)
	numRandHeads := maxChainLength - chainLength
	copy(headers, randbytes(numRandHeads*headerBytes))
	// One key and partial IV required per intermediate hop.
	aes := newEncMessage()
	/*
		16 Byte IVs are constructed from 12 random bytes plus a 4 byte
		counter (defined in AES_IVS()).  The counter doesn't disclose
		any information as headers are in an identical sequence during
		encrypt and decrypt operations.  E.g. Slot1 will be encrypted
		and decrypted with the Slot1 counter regardless of its real
		sequence in the chain.
	*/
	// body doesn't require padding as it was initialised at length bodyBytes
	copy(body, msg)
	var hop string
	for hopNum := 0; hopNum < chainLength; hopNum++ {
		//detPos := (numRandHeads + hopNum) * headerBytes
		//copy(headers[:detPos], deterministic(interAESKeys, interAESIVs, chainLength, hopNum))
		// Here we begin assembly of the slot data
		data := newSlotData()
		if hopNum == 0 {
			// Exit hop
			data.packetType = 1
			// This key and IV are not used in deterministic headers
			data.aesKey = randbytes(32)
			final.aesIV = randbytes(16)
			if err != nil {
				panic(err)
			}
			data.setPacketInfo(final.encode())
			// Override the random packetID created by newSlotData.
			data.packetID = packetid
			// Encrypt the message body
			copy(body, AES_CTR(body, data.aesKey, final.aesIV))
		} else {
			inter := newSlotIntermediate()
			// Grab a Key and IV from the array.
			data.aesKey = aes.getKey(hopNum - 1)
			inter.setPartialIV(aes.getPartialIV(hopNum - 1))
			// The chain hasn't been popped yet so hop still contains the last node name.
			inter.setNextHop(hop)
			data.setPacketInfo(inter.encode())
			data.packetID = randbytes(16)
			// Encrypt the current header slots
			for slot := 0; slot < maxChainLength-1; slot++ {
				sbyte := slot * headerBytes
				ebyte := (slot + 1) * headerBytes
				iv := inter.seqIV(slot)
				//fmt.Printf("Real: Hop=%d, Slot=%d, Key=%x, IV=%x\n", hopNum, slot, data.aesKey[:10], iv[:10])
				copy(headers[sbyte:ebyte], AES_CTR(headers[sbyte:ebyte], data.aesKey, iv))
			}
			aes.deterministic(hopNum)
			// The final IV is used to Encrypt the message body
			iv := inter.seqIV(maxChainLength)
			copy(body, AES_CTR(body, data.aesKey, iv))
		} // End of Intermediate processing
		// Move all the headers down one slot and chop the last header
		copy(headers[headerBytes:], headers[:headersBytes-headerBytes])

		digest, err := blake2s.New(nil)
		if err != nil {
			panic(err)
		}
		digest.Write(headers[headerBytes:])
		digest.Write(body)
		data.tagHash = digest.Sum(nil)
		head := newEncodeHeader()
		hop = popstr(&chain)
		rem, err := pubring.Get(hop)
		if err != nil {
			Error.Printf("%s: Remailer unknown in public keyring\n")
		}
		head.setRecipient(rem.Keyid, rem.PK)
		copy(headers[:headerBytes], head.encode(data.encode()))
	}
	if len(chain) != 0 {
		panic("After encoding, chain was not empty.")
	}
	payload = make([]byte, headersBytes+bodyBytes)
	copy(payload, headers)
	copy(payload[headersBytes:], body)
	return
}

func injectDummy() {
	// Populate public keyring
	public := keymgr.NewPubring(
		cfg.Files.Pubring,
		cfg.Files.Mlist2,
		cfg.Stats.UseExpired,
	)
	public.ImportPubring()
	dummy(public)
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
			Info.Printf("Fetching %s and storing in %s", url, filename)
			err = httpGet(url, filename)
			if err != nil {
				Warn.Println(err)
			}
		}
	}
}
