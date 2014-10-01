// vm: tabstop=2 shiftwidth=2

package main

import (
	"bytes"
	"strings"
	"errors"
	"encoding/binary"
	"encoding/hex"
	"time"
	"crypto/rand"
	"github.com/crooks/yamn/keymgr"
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

// Generate a public/private ECC key pair
func eccGenerate() (public, private []byte) {
	puba, priva, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	public = make([]byte, 32)
	private = make([]byte, 32)
	copy(public[:], puba[:])
	copy(private[:], priva[:])
	if len(public) != 32 {
		panic("Invalid pubkey length generated")
	}
	if len(private) != 32 {
		panic("Invalid seckey length generated")
	}
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
	data []byte
}

func (h slotHead) encodeHead() []byte {
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
	buf.Write(box.Seal(nil, h.data, &nonce, &pk, sendpriv))
	err = bufLenCheck(buf.Len(), 480)
	if err != nil {
		panic(err)
	}
	buf.Write(randbytes(headerBytes - buf.Len()))
	return buf.Bytes()
}

// decodeHead decodes a slot header
func decodeHead(b []byte, secret *keymgr.Secring) (data []byte, err error) {
	/*
	Decode functions should return their associated structs but, in this
	instance, the only field of value is the decrypted data.
	*/
	err = lenCheck(len(b), headerBytes)
	if err != nil {
		return
	}
	var keyid string
	keyid = hex.EncodeToString(b[0:16])
	var sk []byte
	sk, err = secret.GetSK(keyid)
	if err != nil {
		return
	}
	var sender_pk [32]byte
	copy(sender_pk[:], b[16:48])
	var recipient_sk [32]byte
	copy(recipient_sk[:], sk)
	var nonce [24]byte
	copy(nonce[:], b[48:72])
	var auth bool
	data, auth = box.Open(nil, b[72:72+408], &nonce, &sender_pk, &recipient_sk)
	if ! auth {
		err = errors.New("Authentication failed decrypting slot data")
		return
	}
	err = lenCheck(len(data), 392)
	return
}

/*
Encrypted Data
[ Packet ID		 16 Bytes ]
[ AES-CTR key		 32 Bytes ]
[ Packet type ID	  1 Byte  ]
[ Padded packet info	256 Bytes ]
[ Timestamp		  7 Bytes ]
[ Anti-tag digest	 64 Bytes ]
[ Padding		 16 Bytes ]
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

func (d slotData) encodeData() (b []byte, err error) {
	err = lenCheck(len(d.packetID), 16)
	if err != nil {
		return
	}
	err = lenCheck(len(d.aesKey), 32)
	if err != nil {
		return
	}
	err = lenCheck(len(d.packetInfo), 256)
	if err != nil {
		return
	}
	err = lenCheck(len(d.tagHash), 64)
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	buf.Write(d.packetID)
	buf.Write(d.aesKey)
	buf.WriteByte(d.packetType)
	buf.Write(d.packetInfo)
	buf.Write(d.timestamp)
	buf.Write(d.tagHash)
	err = bufLenCheck(buf.Len(), 376)
	if err != nil {
		return
	}
	buf.WriteString(strings.Repeat("\x00", 392 - buf.Len()))
	b = buf.Bytes()
	return
}

func (data slotData) decodeData(b []byte) (err error) {
	err = lenCheck(len(b), 392)
	if err != nil {
		return
	}
	data.packetID = b[0:16]
	data.aesKey = b[16:48]
	data.packetType = uint8(b[48])
	data.packetInfo = b[49:305]
	data.timestamp = b[305:312]
	//TODO Test timestamp
	data.tagHash = b[312:376]
	//Padding[376:392]
	return
}

/*
Final Hop
[ Chunk num		  1 Byte  ]
[ Num chunks		  1 Byte  ]
[ Message ID		 16 Bytes ]
[ AES-CTR IV		 16 Bytes ]
[ Body length		  4 Bytes ]
*/

type slotFinal struct {
	chunkNum uint8
	numChunks uint8
	messageID []byte
	aesIV []byte
	bodyBytes int
}

func (f slotFinal) encodeFinal() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(f.chunkNum)
	buf.WriteByte(f.numChunks)
	buf.Write(f.messageID)
	buf.Write(f.aesIV)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(f.bodyBytes))
	buf.Write(tmp)
	err := bufLenCheck(buf.Len(), 38)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", 256 - buf.Len()))
	return buf.Bytes()
}

func (f slotFinal) decodeFinal(b []byte) (err error) {
	err = lenCheck(len(b), 256)
	if err != nil {
		return
	}
	f.chunkNum = b[0]
	f.numChunks = b[1]
	f.messageID = b[2:18]
	f.aesIV = b[18:34]
	f.bodyBytes = int(binary.LittleEndian.Uint32(b[34:]))
	return
}

/*
Intermediate Hop
[ 11 * AES-CTR IVs		176 Bytes ]
[ Next hop address		 80 Bytes ]

IVs are 9 * header slots, payload and deterministic
*/

type slotIntermediate struct {
	aesIVs []byte
	nextHop string
}

func (i slotIntermediate) encodeIntermediate() []byte {
	var err error
	err = lenCheck(len(i.aesIVs), (maxChainLength + 1) * 16)
	if err != nil {
		panic(err)
	}
	buf := new(bytes.Buffer)
	buf.Write(i.aesIVs)
	buf.WriteString(i.nextHop)
	err = bufLenCheck(buf.Len(), 256)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func (i slotIntermediate) decodeIntermediate(b []byte) (err error) {
	err = lenCheck(len(b), 256)
	if err != nil {
		return
	}
	i.aesIVs = b[:176]
	i.nextHop = strings.TrimRight(string(b[176:]), "\x00")
	return
}
