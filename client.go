// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"net/mail"
	"strings"
	"path"
	"math"
	"errors"
	"crypto/sha512"
	"github.com/crooks/yamn/keymgr"
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
		if ! strings.Contains(flag_to, "@") {
			fmt.Fprintf(os.Stderr, "%s: Recipient doesn't appear to be an email address\n", flag_to)
		}
	}
	if flag_subject != "" {
		msg.Header["Subject"] = []string{flag_subject}
	}
	return assemble(*msg)
}

// deterministic precalculates the header content for fake headers inserted at
// each remailer hop.
func deterministic(keys, ivs [maxChainLength - 1][]byte, chainLength, hopNum int) (pos int, content []byte) {
	bottomSlotNum := maxChainLength - 1  // (9 for 10 hops)
	numDslots := chainLength - 1 - hopNum // (2 for exit of 10 hops)
	topDslotNum := bottomSlotNum - numDslots + 1 // (8 for exit of 10 hops)
	content = make([]byte, 0, numDslots * headerBytes)
	//fmt.Printf("Chain=%d, Hop=%d\n", chainLength, hopNum)
	for slot := topDslotNum; slot <= bottomSlotNum; slot++ {
		fakehead := make([]byte, headerBytes)
		//fmt.Printf("Location: H%dS%d\n", hopNum, slot)
		startHop := maxChainLength + hopNum - slot
		startSlot := bottomSlotNum
		for iterLeft := startHop; iterLeft > hopNum; iterLeft-- {
			// Minus one because we don't use these keys/iv on the exit hop
			hopkey := keys[iterLeft - 1]
			hopivs := ivs[iterLeft - 1]
			hopiv := hopivs[startSlot * 16:(startSlot + 1) * 16]
			//fmt.Printf("Fake: Hop=%d, Slot=%d, Key=%x, IV=%x\n", iterLeft, startSlot, hopkey[:10], hopiv[:10])
			fakehead = AES_CTR(fakehead, hopkey, hopiv)
			startSlot--
		}
		clen := len(content)
		content = content[0:clen + headerBytes]
		copy(content[clen:], fakehead)
	}
	pos = topDslotNum * headerBytes
	return
}

// mixprep fetches the plaintext and prepares it for mix encoding
func mixprep() {
	var err error
	var message []byte
	final := new(slotFinal)
	if len(flag_args) == 0  {
		fmt.Println("Enter message, complete with headers.  Ctrl-D to finish")
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
	// Create the Public Keyring
	pubring := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	err = pubring.ImportPubring()
	if err != nil {
		Warn.Printf("Pubring import failed: %s", cfg.Files.Pubring)
		return
	}
	in_chain := strings.Split(flag_chain, ",")
	if len(in_chain) == 0 {
		err = errors.New("Empty input chain")
		return
	}
	// Delivery type 0 indicates SMTP.  No other methods (other than dummies)
	// are currently supported.
	final.deliveryMethod = 0
	final.messageID = randbytes(16)
	var cnum int // Chunk number
	var numc int // Number of chunks
	numc = int(math.Ceil(float64(msglen) / float64(maxFragLength)))
	final.numChunks = uint8(numc)
	cnum = 1
	var exitnode string // Address of exit node (for multiple copy chains)
	var got_exit bool // Flag to indicate an exit node has been selected
	var packetid []byte // Final hop Packet ID
	var first_byte int // First byte of message slice
	var last_byte int // Last byte of message slice
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
				in_chain[len(in_chain) - 1] = exitnode
			}
			var chain []string
			chain, err = chain_build(in_chain, pubring)
			if err != nil {
				panic(err)
			}
			if len(chain) != len(in_chain) {
				err = fmt.Errorf("Chain length mismatch.  In=%d, Out=%d", len(in_chain), len(chain))
				panic(err)
			}
			//fmt.Println(chain)
			if ! got_exit {
				exitnode = chain[len(chain) - 1]
				got_exit = true
			}
			encmsg, sendTo := mixmsg(message[first_byte:last_byte], packetid, chain, *final, pubring)
			err = outPoolWrite(armor(encmsg, sendTo), sendTo)
			if err != nil {
				Warn.Println(err)
			}
		} // End of copies loop
	} // End of fragments loop
	var filenames []string
	filenames, err = poolRead()
	if err != nil {
		Warn.Printf("Reading pool failed: %s", err)
	}
	for _, file := range filenames {
		err = mailFile(path.Join(cfg.Files.Pooldir, file))
		if err != nil {
			Warn.Printf("Pool mailing failed: %s", err)
		} else {
			poolDelete(file)
		}
	}
}

// mixmsg encodes a plaintext fragment into mixmaster format.
func mixmsg(
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
	copy(headers, randbytes(numRandHeads * headerBytes))
	// Generate all the intermediate hop Keys and IVs
	var keys [maxChainLength - 1][]byte
  var ivs [maxChainLength - 1][]byte
	// One key required per intermediate hop
	for n := 0; n < chainLength - 1; n++ {
		keys[n] = randbytes(32)
		ivs[n] = randbytes((maxChainLength + 1) * 16)
	}
	// body doesn't require padding as it was initialised at length bodyBytes
	copy(body, msg)
	var hop string
	for hopNum := 0; hopNum < chainLength; hopNum++ {
		//detPos := (numRandHeads + hopNum) * headerBytes
		//copy(headers[:detPos], deterministic(interAESKeys, interAESIVs, chainLength, hopNum))
		// Here we begin assembly of the slot data
		data := new(slotData)
		if err != nil {
			panic(err)
		}
		data.timestamp = timestamp()
		if hop == "" {
			// Exit hop
			data.packetType = 1
			// This key and IV are not used in deterministic headers
			data.aesKey = randbytes(32)
			final.aesIV = randbytes(16)
			if err != nil {
				panic(err)
			}
			data.packetInfo = final.encodeFinal()
			data.packetID = packetid
			// Encrypt the message body
			copy(body, AES_CTR(body, data.aesKey, final.aesIV))
		} else {
			inter := new(slotIntermediate)
			data.packetType = 0
			// Grab a Key and block of IVs from the pool for this header
			data.aesKey = keys[hopNum - 1]
			inter.aesIVs = ivs[hopNum - 1]
			// The chain hasn't been popped yet so hop still contains the last node name.
			inter.setNextHop(hop)
			data.packetInfo = inter.encodeIntermediate()
			data.packetID = randbytes(16)
			// Encrypt the current header slots
			for slot := 0; slot < maxChainLength - 1; slot++ {
				sbyte := slot * headerBytes
				ebyte := (slot + 1) * headerBytes
				iv := inter.aesIVs[slot * 16:(slot + 1) * 16]
				//fmt.Printf("Real: Hop=%d, Slot=%d, Key=%x, IV=%x\n", hopNum, slot, data.aesKey[:10], iv[:10])
				copy(headers[sbyte:ebyte], AES_CTR(headers[sbyte:ebyte], data.aesKey, iv))
			}
			// The final IV is used to Encrypt the message body
			iv := inter.aesIVs[maxChainLength * 16:]
			copy(body, AES_CTR(body, data.aesKey, iv))
		} // End of Intermediate processing
		// Move all the headers down one slot and chop the last header
		copy(headers[headerBytes:], headers[:headersBytes - headerBytes])
		if hopNum < chainLength - 1 {
			pos, fakes := deterministic(keys, ivs, chainLength, hopNum)
			if err != nil {
				panic(err)
			}
			copy(headers[pos:], fakes)
		}
		//digest := blake2.New(nil)
		digest := sha512.New()
		digest.Write(headers[headerBytes:])
		digest.Write(body)
		data.tagHash = digest.Sum(nil)
		head := new(slotHead)
		hop = popstr(&chain)
		head.data, err = data.encodeData()
		if err != nil {
			panic(err)
		}
		rem, err := pubring.Get(hop)
		if err != nil {
			Error.Printf("%s: Remailer unknown in public keyring\n")
		}
	  head.recipientKeyid = rem.Keyid
	  head.recipientPK = rem.PK
		copy(headers[:headerBytes], head.encodeHead())
	}
	if len(chain) != 0 {
		panic("After encoding, chain was not empty.")
	}
	payload = make([]byte, headersBytes + bodyBytes)
	copy(payload, headers)
	copy(payload[headersBytes:], body)
	return
}

func injectDummy() {
	// Populate public keyring
	public := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	public.ImportPubring()
	err := dummy(public)
	if err != nil {
		Info.Println("Dummy injection failed")
	}
}
