// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
)

const (
	version string = "0.1b"
	date_format string = "2006-01-02"
	key_validity_days int = 60
)

func client(pub map[string]keyinfo) []byte {
	var final slotfinal
	var data slotdata
	var head slothead
	recipient_remailer := "mix@nowhere.invalid"
	final.chunknum = uint8(1)
	final.numchunks = uint8(1)
	final.messageid = make([]byte, 16)
	final.aesiv = make([]byte, 16)
	data.packetinfo = encode_final(final)
	data.packetid = make([]byte, 16)
	data.aeskey = make([]byte, 32)
	data.packettype = uint8(1)
	data.timestamp = timestamp()
	data.taghash = make([]byte, 32)
	head.slotdata = encode_data(data)
	head.recipient_keyid = pub[recipient_remailer].keyid
	head.recipient_pk = pub[recipient_remailer].pk
	return encode_head(head)  // This is the encoded header
}

func server(header []byte, sec map[string][]byte) (final slotfinal) {
	slotdata, auth, err := decode_head(header, sec)
	if err != nil {
		panic(err)
	}
	if ! auth {
		fmt.Fprintln(os.Stderr, "Auth failed ECC decoding slot data")
	}
	data, err := decode_data(slotdata)
	if err != nil {
		panic(err)
	}
	if data.packettype == 1 {
		final, err = decode_final(data.packetinfo)
		if err != nil {
			panic(err)
		}
	}
	return
}


func main() {
	// Import keyrings
	pub, _ := import_pubring()
	sec := import_secring()

	// Encode a header
	header := client(pub)

	// Now try to decrypt it
	out := server(header, sec)
	fmt.Println(out.messageid)
}
