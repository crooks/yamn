// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"bytes"
	"strings"
	"encoding/binary"
	"encoding/hex"
	"time"
	"crypto/rand"
	"code.google.com/p/go.crypto/nacl/box"
)

// timestamp creates a Mixmaster formatted timestamp, consisting of an intro
// string concatented to the number of days since Epoch (little Endian).
func timestamp() (stamp []byte) {
	d := uint16(time.Now().UTC().Unix() / 86400)
	days := make([]byte, 2)
	binary.LittleEndian.PutUint16(days, d)
	stamp = append([]byte("0000\x00"), days...)
	return
}

/*
Slot Header Format
[ Recipient key ID		 16 Bytes ]
[ Sender Public key		 32 Bytes ]
[ Xsalsa20 Nonce		 24 Bytes ]
[ Encrypted data		408 Bytes ] (392 + Overhead)
[ Random padding		 32 Bytes ]
*/

type slothead struct {
	recipient_keyid []byte
	recipient_pk []byte
	//sender_pubkey []byte
	//nonce []byte
	slotdata []byte
}

func encode_head(h slothead) []byte {
	// Generate an ECC key pair
	sendpub, sendpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var nonce [24]byte
	copy(nonce[:], randbytes(24))
	buf := new(bytes.Buffer)
	buf.Write(h.recipient_keyid)
	buf.Write(sendpub[:])
	buf.Write(nonce[:])
	var pk [32]byte
	copy(pk[:], h.recipient_pk)
	buf.Write(box.Seal(nil, h.slotdata, &nonce, &pk, sendpriv))
	err = buflencheck(buf.Len(), 480)
	if err != nil {
		panic(err)
	}
	buf.Write(randbytes(512 - buf.Len()))
	return buf.Bytes()
}

func decode_head(b []byte, sec map[string][]byte) (slotdata []byte, auth bool, err error) {
	var keyid string
	keyid = hex.EncodeToString(b[0:16])
	sk, present := sec[keyid]
	if ! present {
		err = fmt.Errorf("%s: Keyid not found in secring", keyid)
		return
	}
	err = lencheck(sk, 32)
	if err != nil {
		return
	}
	var sender_pk [32]byte
	copy(sender_pk[:], b[16:48])
	var recipient_sk [32]byte
	copy(recipient_sk[:], sk)
	var nonce [24]byte
	copy(nonce[:], b[48:72])
	slotdata, auth = box.Open(nil, b[72:72+408], &nonce, &sender_pk, &recipient_sk)
	err = lencheck(slotdata, 392)
	return
}

/*
Encrypted Data
[ Packet ID			 16 Bytes ]
[ AES-CTR key			 32 Bytes ]
[ Packet type ID		  1 Byte  ]
[ Padded packet info		240 Bytes ]
[ Timestamp			  7 Bytes ]
[ Anti-tag digest		 32 Bytes ]
[ Padding			 64 Bytes ]
Total	392 Bytes
*/

type slotdata struct {
	packetid []byte
	aeskey []byte
	packettype uint8
	packetinfo []byte
	timestamp []byte
	taghash []byte
}

func encode_data(d slotdata) []byte {
	buf := new(bytes.Buffer)
	buf.Write(d.packetid)
	buf.Write(d.aeskey)
	buf.WriteByte(d.packettype)
	buf.Write(d.packetinfo)
	buf.Write(d.timestamp)
	buf.Write(d.taghash)
	err := buflencheck(buf.Len(), 328)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", 392 - buf.Len()))
	return buf.Bytes()
}

func decode_data(b []byte) (data slotdata, err error) {
	err = lencheck(b, 392)
	if err != nil {
		return
	}
	data.packetid = b[0:16]
	data.aeskey = b[16:48]
	data.packettype = uint8(b[48])
	data.packetinfo = b[49:289]
	//TODO Test timestamp
	data.taghash = b[296:328]
	//Padding[328:392]
	return
}

/*
Final Hop
[ Chunk num			  1 Byte  ]
[ Num chunks			  1 Byte ]
[ Message ID			 16 Bytes ]
[ AES-CTR IV			 16 Bytes ]
*/

type slotfinal struct {
	chunknum uint8
	numchunks uint8
	messageid []byte
	aesiv []byte
}

func encode_final(f slotfinal) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(f.chunknum)
	buf.WriteByte(f.numchunks)
	buf.Write(f.messageid)
	buf.Write(f.aesiv)
	err := buflencheck(buf.Len(), 34)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", 240 - buf.Len()))
	return buf.Bytes()
}

func decode_final(b []byte) (final slotfinal, err error) {
	err = lencheck(b, 240)
	if err != nil {
		return
	}
	final.chunknum = b[0]
	final.numchunks = b[1]
	final.messageid = b[2:18]
	final.aesiv = b[18:34]
	return
}

/*
Intermediate Hop
[ 10 * AES-CTR IVs		160 Bytes ]
[ Next hop address		 80 Bytes ]
*/

type slotintermediate struct {
	aesivs []byte
	nexthop string
}

func encode_intermediate(inter slotintermediate) []byte {
	buf := new(bytes.Buffer)
	buf.Write(inter.aesivs)
	buf.WriteString(inter.nexthop)
	err := buflencheck(buf.Len(), 240)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decode_intermediate(b []byte) (inter slotintermediate, err error) {
	err = lencheck(b, 240)
	if err != nil {
		return
	}
	inter.aesivs = b[0:160]
	inter.nexthop = string(b[160:240])
	return
}
