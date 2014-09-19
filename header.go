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

type slotHead struct {
	recipientKeyid []byte
	recipientPK []byte
	//sender_pubkey []byte
	//nonce []byte
	slotData []byte
}

func encode_head(h slotHead) []byte {
	// Generate an ECC key pair
	sendpub, sendpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var nonce [24]byte
	copy(nonce[:], randbytes(24))
	buf := new(bytes.Buffer)
	buf.Write(h.recipientKeyid)
	buf.Write(sendpub[:])
	buf.Write(nonce[:])
	var pk [32]byte
	copy(pk[:], h.recipientPK)
	buf.Write(box.Seal(nil, h.slotData, &nonce, &pk, sendpriv))
	err = buflencheck(buf.Len(), 480)
	if err != nil {
		panic(err)
	}
	buf.Write(randbytes(headerBytes - buf.Len()))
	return buf.Bytes()
}

func decode_head(b []byte, sec map[string][]byte) (slotData []byte, auth bool, err error) {
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
	slotData, auth = box.Open(nil, b[72:72+408], &nonce, &sender_pk, &recipient_sk)
	err = lencheck(slotData, 392)
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

type slotData struct {
	packetID []byte
	aesKey []byte
	packetType uint8
	packetInfo []byte
	timestamp []byte
	tagHash []byte
}

func encode_data(d slotData) []byte {
	buf := new(bytes.Buffer)
	buf.Write(d.packetID)
	buf.Write(d.aesKey)
	buf.WriteByte(d.packetType)
	buf.Write(d.packetInfo)
	buf.Write(d.timestamp)
	buf.Write(d.tagHash)
	err := buflencheck(buf.Len(), 328)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", 392 - buf.Len()))
	return buf.Bytes()
}

func decode_data(b []byte) (data slotData, err error) {
	err = lencheck(b, 392)
	if err != nil {
		return
	}
	data.packetID = b[0:16]
	data.aesKey = b[16:48]
	data.packetType = uint8(b[48])
	data.packetInfo = b[49:289]
	//TODO Test timestamp
	data.tagHash = b[296:328]
	//Padding[328:392]
	return
}

/*
Final Hop
[ Chunk num			  1 Byte  ]
[ Num chunks			  1 Byte ]
[ Message ID			 16 Bytes ]
[ AES-CTR IV			 16 Bytes ]
[ Body length			  4 Bytes ]
*/

type slotFinal struct {
	chunkNum uint8
	numChunks uint8
	messageID []byte
	aesIV []byte
	bodyBytes []byte
}

func encodeFinal(f slotFinal) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(f.chunkNum)
	buf.WriteByte(f.numChunks)
	buf.Write(f.messageID)
	buf.Write(f.aesIV)
	buf.Write(f.bodyBytes)
	err := buflencheck(buf.Len(), 38)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", 240 - buf.Len()))
	return buf.Bytes()
}

func decodeFinal(b []byte) (final slotFinal, err error) {
	err = lencheck(b, 240)
	if err != nil {
		return
	}
	final.chunkNum = b[0]
	final.numChunks = b[1]
	final.messageID = b[2:18]
	final.aesIV = b[18:34]
	return
}

/*
Intermediate Hop
[ 10 * AES-CTR IVs		160 Bytes ]
[ Next hop address		 80 Bytes ]
*/

type slotIntermediate struct {
	aesIVs []byte
	nextHop string
}

func encodeIntermediate(inter slotIntermediate) []byte {
	buf := new(bytes.Buffer)
	buf.Write(inter.aesIVs)
	buf.WriteString(inter.nextHop)
	err := buflencheck(buf.Len(), 240)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decodeIntermediate(b []byte) (inter slotIntermediate, err error) {
	err = lencheck(b, 240)
	if err != nil {
		return
	}
	inter.aesIVs = b[0:160]
	inter.nextHop = string(b[160:240])
	return
}
