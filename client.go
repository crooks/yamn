// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"
	"math"
	"encoding/binary"
)

// mixprep fetches the plaintext and prepares it for mix encoding
func mixprep() {
	var err error
	var message []byte
	var final slotFinal
	if len(flag_args) == 0 && ! flag_stdin {
		os.Stderr.Write([]byte("No input filename provided\n"))
		os.Exit(1)
	} else if flag_stdin {
		// Flag instructs message should be read from stdin
		message, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(flag_args) == 1 {
			// A single arg on an stdin msg implies a recipient address
			flag_to = flag_args[0]
		}
	} else if len(flag_args) == 1 {
		// A single arg should be the filename
		message = import_msg(flag_args[0])
	} else if len(flag_args) >= 2 {
		// Two args should be recipient and filename
		flag_to = flag_args[0]
		message = import_msg(flag_args[1])
	}
	msglen := len(message)
	if msglen == 0 {
		fmt.Fprintln(os.Stderr, "No bytes in message")
		os.Exit(1)
	}
	// Create the Public Keyring
	pubring, xref := import_pubring()
	// Populate keyring's uptime and latency fields
	_ = import_mlist2(cfg.Files.Mlist2, pubring, xref)
	in_chain := strings.Split(flag_chain, ",")
	final.messageID = randbytes(16)
	var cnum int // Chunk number
	var numc int // Number of chunks
	numc = int(math.Ceil(float64(msglen) / float64(max_frag_length)))
	final.numChunks = uint8(numc)
	cnum = 1
	var exitnode string // Address of exit node (for multiple copy chains)
	var got_exit bool // Flag to indicate an exit node has been selected
	var packetid []byte // Final hop Packet ID
	var first_byte int // First byte of message slice
	var last_byte int // Last byte of message slice
	for cnum = 1; cnum <= numc; cnum++ {
		final.chunkNum = uint8(cnum)
		// First byte of message fragment
		first_byte = (cnum - 1) * max_frag_length
		last_byte = first_byte + max_frag_length
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
		if flag_copies > 10 {
			// Limit copies to a maximum of 10
			flag_copies = 10
		}
		for n := 0; n < flag_copies; n++ {
			if got_exit {
				// Set the last node in the chain to the previously select exitnode
				in_chain[len(in_chain) - 1] = exitnode
			}
			chain := chain_build(in_chain, pubring, xref)
			//fmt.Println(chain)
			if ! got_exit {
				exitnode = chain[len(chain) - 1]
				got_exit = true
			}
			final.aesIV = randbytes(16)
			encmsg, sendto := mixmsg(message[first_byte:last_byte], packetid, chain, final, pubring, xref)
			encmsg = cutmarks(encmsg)
			/* Temporarily stop emailing
			if cfg.Mail.Sendmail {
				sendmail(encmsg, sendto)
			} else {
				smtprelay(encmsg, sendto)
			}
			*/
			fmt.Println(string(encmsg))
			fmt.Fprintln(os.Stderr, sendto)
		} // End of copies loop
	} // End of fragments loop
}

// mixmsg encodes a plaintext fragment into mixmaster format.
func mixmsg(msg, packetid []byte, chain []string, final slotFinal,
						pubring map[string]pubinfo, xref map[string]string) (payload []byte, sendto string) {
	// Retain the address of the entry remailer, the message must be sent to it.
	sendto = chain[0]
	msgLen := len(msg)
	final.bodyBytes = make([]byte, 4)
	binary.LittleEndian.PutUint32(final.bodyBytes, uint32(msgLen))
	body := make([]byte, bodyBytes)
	copy(body, msg)
	// body doesn't require padding as it was initialised at length bodyBytes
	// Identify the last hop in the chain (The exit remailer)
	hop := popstr(&chain)
	// Here we begin assembly of the slot data
	var data slotData
	data.packetInfo = encodeFinal(final)
	data.packetID = packetid
	data.aesKey = randbytes(32)
	data.packetType = 1
	data.timestamp = timestamp()
	data.tagHash = make([]byte, 32)
	var head slotHead
	head.slotData = encode_data(data)
  head.recipientKeyid = pubring[hop].keyid
  head.recipientPK = pubring[hop].pk
	headers := make([]byte, headerBytes, headersBytes)
	// Populate the top header slot and the body
	copy(headers, encode_head(head))
	copy(body, AES_CTR(body, data.aesKey, final.aesIV))
	// That's it for final hop preparation.
	// What follows is intermediate hop interation.
	for {
		if len(chain) == 0 {
			// Abort iterating when the chain is fully processed.
			break
		}
		var inter slotIntermediate
		// The chain hasn't been popped yet so hop still contains the last node name.
		inter.nextHop = hop + strings.Repeat("\x00", 80 - len(hop))
		// TODO These IVs can't be generated here if we want deterministic headers
		inter.aesIVs = randbytes(16 * maxChainLength)
		hop = popstr(&chain)
		var data slotData
		data.packetInfo = encodeIntermediate(inter)
		data.packetID = randbytes(16)
		// TODO The AES key can't be generated here if we want deterministic headers
		data.aesKey = randbytes(32)
		data.packetType = 0
		data.timestamp = timestamp()
		data.tagHash = make([]byte, 32)
		var head slotHead
		head.slotData = encode_data(data)
	  head.recipientKeyid = pubring[hop].keyid
	  head.recipientPK = pubring[hop].pk
		// Extend headers by one slot
		headLen := len(headers)
		headers = headers[0:headLen + headerBytes]
		// Move all the existing headers down a slot
		copy(headers[headLen:], headers)
		// Now populate the vacated top slot and re-encrypt the body
		copy(headers, encode_head(head))
		copy(body, AES_CTR(body, data.aesKey, final.aesIV))
	}

	headers = headers[0:headersBytes]
	payload = make([]byte, headersBytes + bodyBytes)
	copy(payload, headers)
	copy(payload[headersBytes:], body)
	return
}
