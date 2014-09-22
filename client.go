// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"
	"math"
	"github.com/codahale/blake2"
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
	// Fragments loop begins here
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
			chain := chain_build(in_chain, pubring, xref)
			//fmt.Println(chain)
			if ! got_exit {
				exitnode = chain[len(chain) - 1]
				got_exit = true
			}
			encmsg, sendto := mixmsg(message[first_byte:last_byte], packetid, chain, final, pubring, xref)
			err = cutmarks("test.txt", sendto, encmsg)
			if err != nil {
				panic(err)
			}
		} // End of copies loop
	} // End of fragments loop
}

// mixmsg encodes a plaintext fragment into mixmaster format.
func mixmsg(msg, packetid []byte, chain []string, final slotFinal, pubring map[string]pubinfo, xref map[string]string) (payload []byte, sendto string) {
	var err error
	chainLength := len(chain)
	// Retain the address of the entry remailer, the message must be sent to it.
	sendto = chain[0]
	final.bodyBytes = len(msg)
	body := make([]byte, bodyBytes)
	headers := make([]byte, headersBytes)
	// One key required per hop
	allAESKeys := randbytes(chainLength * 32)
	// One IV for Final and Eleven for every Inter
	numIVs := ((chainLength - 1) * (maxChainLength + 1)) + 1
	// Eleven IVs required per Inter
	allAESIVs := randbytes(numIVs * 16)
	// body doesn't require padding as it was initialised at length bodyBytes
	copy(body, msg)
	var hop string
	for {
		// Here we begin assembly of the slot data
		var data slotData
		data.aesKey, err = sPopBytes(&allAESKeys, 32)
		if err != nil {
			panic(err)
		}
		data.timestamp = timestamp()
		if hop == "" {
			// Exit hop
			data.packetType = 1
			final.aesIV, err = sPopBytes(&allAESIVs, 16)
			if err != nil {
				panic(err)
			}
			data.packetInfo = encodeFinal(final)
			data.packetID = packetid
			// Encrypt the message body
			copy(body, AES_CTR(body, data.aesKey, final.aesIV))
			digest := blake2.New(nil)
			digest.Write(headers)
			digest.Write(body)
			data.tagHash = digest.Sum(nil)
		} else {
			var inter slotIntermediate
			data.packetType = 0
			// Grab enough IVs from the pool for this header
			inter.aesIVs, err = sPopBytes(&allAESIVs, (maxChainLength + 1) * 16)
			if err != nil {
				panic(err)
			}
			// The chain hasn't been popped yet so hop still contains the last node name.
			inter.nextHop = hop + strings.Repeat("\x00", 80 - len(hop))
			data.packetInfo = encodeIntermediate(inter)
			data.packetID = randbytes(16)
			// Encrypt the current header slots
			for slot := 0; slot < maxChainLength - 1; slot++ {
				sbyte := slot * headerBytes
				ebyte := (slot + 1) * headerBytes
				iv, err := sPopBytes(&inter.aesIVs, 16)
				if err != nil {
					panic(err)
				}
				copy(headers[sbyte:ebyte], AES_CTR(headers[sbyte:ebyte], data.aesKey, iv))
				//fmt.Printf("sbyte=%d, ebyte=%d, iv=%x\n", sbyte, ebyte, iv)
			}
			// Encrypt the message body
			iv, err := sPopBytes(&inter.aesIVs, 16)
			if err != nil {
				panic(err)
			}
			copy(body, AES_CTR(body, data.aesKey, iv))
			// Pop the eleventh IV, used for the deterministic header
			iv, err = sPopBytes(&inter.aesIVs, 16)
			if err != nil {
				panic(err)
			}
			if len(inter.aesIVs) != 0 {
				err = fmt.Errorf("IV pool not empty.  Contains %d bytes.", len(inter.aesIVs))
				panic(err)
			}
			digest := blake2.New(nil)
			digest.Write(headers)
			digest.Write(body)
			data.tagHash = digest.Sum(nil)
			// Move all the headers down one slot
			copy(headers[headerBytes:], headers[:headersBytes - headerBytes])
		} // End of Intermediate processing
		var head slotHead
		hop = popstr(&chain)
		head.data, err = encodeData(data)
		if err != nil {
			panic(err)
		}
	  head.recipientKeyid = pubring[hop].keyid
	  head.recipientPK = pubring[hop].pk
		copy(headers[:headerBytes], encodeHead(head))
		if len(chain) == 0 {
			// Abort iterating when the chain is fully processed.
			break
		}
	}
	payload = make([]byte, headersBytes + bodyBytes)
	copy(payload, headers)
	copy(payload[headersBytes:], body)
	return
}
