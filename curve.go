// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"crypto/rand"
)

const (
	version string = "0.1b"
	date_format string = "2006-01-02"
	key_validity_days int = 60
)

// randbytes returns n Bytes of random data
func randbytes(n int) (b []byte) {
  b = make([]byte, n)
  _, err := rand.Read(b)
  if err != nil {
    panic(err)
  }
  return
}

// lencheck verifies that slice b is of a given length
func lencheck(b []byte, length int) error {
	if len(b) != length {
		return fmt.Errorf("Incorrect slice length.  Wanted=%d, Got=%d", length, len(b))
	} else {
		return nil
	}
}

// buflencheck verifies that a given buffer length is of a specified length
func buflencheck(buflen, length int) error {
	if buflen != length {
		return fmt.Errorf("Incorrect buffer length.  Wanted=%d, Got=%d", length, buflen)
	} else {
		return nil
	}
}


func main() {
	// Import keyrings
	pub, _ := import_pubring()
	sec := import_secring()

	// Encode a header
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
	header := encode_head(head)  // This is the encoded header

	// Now try to decrypt it
	slotdata, auth, err := decode_head(header, sec)
	if err != nil {
		panic(err)
	}
	if ! auth {
		fmt.Fprintln(os.Stderr, "Auth failed ECC decoding slot data")
	}
	newdata, err := decode_data(slotdata)
	if err != nil {
		panic(err)
	}
	var newfinal slotfinal
	if newdata.packettype == 1 {
		newfinal, err = decode_final(newdata.packetinfo)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(newfinal.chunknum)
}
