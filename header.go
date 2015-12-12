package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"strings"
	"time"
	//"code.google.com/p/go.crypto/nacl/box"
)

// Generate a public/private ECC key pair
func eccGenerate() (pk, sk []byte) {
	pka, ska, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pk = make([]byte, 32)
	sk = make([]byte, 32)
	copy(pk[:], pka[:])
	copy(sk[:], ska[:])
	return
}

/*
Slot Header Format
[ Recipient key ID	 16 Bytes ]
[ Sender Public key	 32 Bytes ]
[ Xsalsa20 Nonce	 24 Bytes ]
[ Encrypted header	176 Bytes ] (160 + Overhead)
[ Random padding	  8 Bytes ]
Total	256 Bytes
*/
type encodeHeader struct {
	gotRecipient   bool
	recipientKeyID []byte
	recipientPK    [32]byte
}

func newEncodeHeader() *encodeHeader {
	return &encodeHeader{
		gotRecipient:   false,
		recipientKeyID: make([]byte, 16),
	}
}

func (h *encodeHeader) setRecipient(recipientKeyID, recipientPK []byte) {
	err := lenCheck(len(recipientKeyID), 16)
	if err != nil {
		panic(err)
	}
	err = lenCheck(len(recipientPK), 32)
	if err != nil {
		panic(err)
	}
	// Copying from a slice to an array requires trickery ([:])
	copy(h.recipientPK[:], recipientPK)
	copy(h.recipientKeyID, recipientKeyID)
	h.gotRecipient = true
}

func (h *encodeHeader) encode(encHead []byte) []byte {
	var err error
	// Test a recipient has been defined
	if !h.gotRecipient {
		err = errors.New("Header encode without defining recipient")
		panic(err)
	}
	// Test passed encHead is the correct length
	err = lenCheck(len(encHead), encHeadBytes)
	if err != nil {
		panic(err)
	}

	// Every header has a randomly generate sender PK & SK
	senderPK, senderSK, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var nonce [24]byte
	copy(nonce[:], randbytes(24))
	buf := new(bytes.Buffer)
	buf.Write(h.recipientKeyID)
	buf.Write(senderPK[:])
	buf.Write(nonce[:])
	buf.Write(box.Seal(nil, encHead, &nonce, &h.recipientPK, senderSK))
	err = lenCheck(buf.Len(), 248)
	if err != nil {
		panic(err)
	}
	buf.Write(randbytes(headerBytes - buf.Len()))
	return buf.Bytes()
}

type decodeHeader struct {
	header       []byte
	gotRecipient bool
	recipientSK  [32]byte
}

func newDecodeHeader(b []byte) *decodeHeader {
	err := lenCheck(len(b), headerBytes)
	if err != nil {
		panic(err)
	}
	h := new(decodeHeader)
	h.header = make([]byte, 256)
	copy(h.header, b)
	h.gotRecipient = false
	return h
}

// getRecipientKeyID returns the encoded keyid as a string.  This is required
// to ascertain the Recipient Secret Key that will be passed to
// "setRecipientSK".
func (h *decodeHeader) getRecipientKeyID() (keyid string) {
	return hex.EncodeToString(h.header[0:16])
}

// setRecipientSK defines the Secret Key that will be used to decrypt the
// Encrypted Header component.
func (h *decodeHeader) setRecipientSK(recipientSK []byte) {
	err := lenCheck(len(recipientSK), 32)
	if err != nil {
		panic(err)
	}
	copy(h.recipientSK[:], recipientSK)
	h.gotRecipient = true
}

func (h *decodeHeader) decode() (data []byte, err error) {
	if !h.gotRecipient {
		err = errors.New("Cannot decode header until recipient defined")
		panic(err)
	}
	// Length to decode should be lenEndBytes plus the NaCl Box overhead
	var senderPK [32]byte
	copy(senderPK[:], h.header[16:48])
	var nonce [24]byte
	copy(nonce[:], h.header[48:72])
	data, auth := box.Open(
		nil,
		h.header[72:248],
		&nonce,
		&senderPK,
		&h.recipientSK,
	)
	if !auth {
		err = errors.New("Authentication failed decrypting slot data")
		return
	}
	return
}

/*
Encrypted data
[ Packet type ID	  1 Byte  ]
[ Delivery protocol	  1 Byte  ]
[ Packet ID		 16 Bytes ]
[ AES-CTR key		 32 Bytes ]
[ Timestamp		  2 Bytes ]
[ Packet info		 64 Bytes ]
[ Anti-tag digest	 32 Bytes ]
[ Padding		 12 Bytes ]
Total	160 Bytes

Packet Type: 0=Intermediate 1=Exit
Delivery protocol: 0=SMTP
*/
type slotData struct {
	packetType    uint8
	protocol      uint8
	packetID      []byte
	aesKey        []byte // Used for encrypting slots and body
	timestamp     []byte
	gotPacketInfo bool // Test if packetInfo has been defined
	packetInfo    []byte
	tagHash       []byte
}

func newSlotData() *slotData {
	return &slotData{
		packetType: 0,
		protocol:   0,
		// packetID is random for intermediate hops but needs to be
		// identical on multi-copy Exits.
		packetID:  randbytes(16),
		aesKey:    randbytes(32),
		timestamp: make([]byte, 2),
		tagHash:   make([]byte, 32),
	}
}

func (head *slotData) setPacketInfo(ei []byte) {
	err := lenCheck(len(ei), encDataBytes)
	if err != nil {
		panic(err)
	}
	head.gotPacketInfo = true
	head.packetInfo = ei
}

// setTimestamp creates a two-Byte timestamp (in little Endian format) based on
// the number of days since Epoch.
func (head *slotData) setTimestamp() {
	d := uint16(time.Now().UTC().Unix() / 86400)
	binary.LittleEndian.PutUint16(head.timestamp, d)
	return
}

func (head *slotData) ageTimestamp() uint16 {
	err := lenCheck(len(head.timestamp), 2)
	if err != nil {
		panic(err)
	}
	now := uint16(time.Now().UTC().Unix() / 86400)
	then := binary.LittleEndian.Uint16(head.timestamp)
	return then - now
}

func (head *slotData) encode() []byte {
	if !head.gotPacketInfo {
		err := errors.New(
			"Exit/Intermediate not defined before attempt to " +
				"encode Encrypted Header.",
		)
		panic(err)
	}
	head.setTimestamp()
	buf := new(bytes.Buffer)
	buf.WriteByte(head.packetType)
	buf.WriteByte(head.protocol)
	buf.Write(head.packetID)
	buf.Write(head.aesKey)
	buf.Write(head.timestamp)
	buf.Write(head.packetInfo)
	buf.Write(head.tagHash)
	err := lenCheck(buf.Len(), 148)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", encHeadBytes-buf.Len()))
	return buf.Bytes()
}

func decodeSlotData(b []byte) *slotData {
	err := lenCheck(len(b), encHeadBytes)
	if err != nil {
		panic(err)
	}
	return &slotData{
		packetType: b[0],
		protocol:   b[1],
		packetID:   b[2:18],
		aesKey:     b[18:50],
		timestamp:  b[50:52],
		packetInfo: b[52:116],
		tagHash:    b[116:148],
	}
}

/*
Enyrypted Final
[ AES-CTR IV		 16 Bytes ]
[ Chunk num		  1 Byte  ]
[ Num chunks		  1 Byte  ]
[ Message ID		 16 Bytes ]
[ Body length		  4 Bytes ]
[ Delivery method	  1 Byte ]
[ Padding		 25 Bytes ]
Total	64 Bytes

Delivery methods: 0=SMTP, 255=Dummy
*/
type slotFinal struct {
	aesIV          []byte
	chunkNum       uint8
	numChunks      uint8
	messageID      []byte
	gotBodyBytes   bool
	bodyBytes      int
	deliveryMethod uint8
}

func newSlotFinal() *slotFinal {
	return &slotFinal{
		aesIV:          randbytes(16),
		chunkNum:       1,
		numChunks:      1,
		messageID:      randbytes(16),
		gotBodyBytes:   false,
		deliveryMethod: 0,
	}
}

func (f *slotFinal) setBodyBytes(length int) {
	if length > bodyBytes {
		err := fmt.Errorf(
			"Body (%d Bytes) exceeds maximum (%d Bytes)",
			length,
			bodyBytes,
		)
		panic(err)
	}
	f.bodyBytes = length
	f.gotBodyBytes = true
}

func (f *slotFinal) encode() []byte {
	if !f.gotBodyBytes {
		err := errors.New(
			"Cannot encode Slot Final before Body Length is " +
				"defined",
		)
		panic(err)
	}
	buf := new(bytes.Buffer)
	buf.Write(f.aesIV)
	buf.WriteByte(f.chunkNum)
	buf.WriteByte(f.numChunks)
	buf.Write(f.messageID)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(f.bodyBytes))
	buf.Write(tmp)
	buf.WriteByte(f.deliveryMethod)
	err := lenCheck(buf.Len(), 39)
	if err != nil {
		panic(err)
	}
	buf.WriteString(strings.Repeat("\x00", encDataBytes-buf.Len()))
	return buf.Bytes()
}

func decodeFinal(b []byte) *slotFinal {
	err := lenCheck(len(b), encDataBytes)
	if err != nil {
		panic(err)
	}
	return &slotFinal{
		aesIV:     b[:16],
		chunkNum:  b[16],
		numChunks: b[17],
		messageID: b[18:34],
		bodyBytes: int(binary.LittleEndian.Uint32(b[34:38])),
	}
}

/* Encrypted Intermediate
[ AES-CTR IV (Partial)	 12 Bytes ]
[ Next hop address	 52 Bytes ]
[ Padding		  0 Bytes ]
Total	64 Bytes

IVs are:
[ 9 * Header slots		 ]
[ 1 * Deterministic header	 ]
[ 1 * Payload header		 ]
*/

type slotIntermediate struct {
	gotAesIV12 bool
	aesIV12    []byte
	nextHop    []byte
}

//seqIV constructs a complete 16 Byte IV from a partial 12 Byte IV + a 4 Byte
//counter.
func seqIV(partialIV []byte, slot int) (iv []byte) {
	err := lenCheck(len(partialIV), 12)
	if err != nil {
		panic(err)
	}
	iv = make([]byte, 16)
	copy(iv[0:4], partialIV[0:4])
	copy(iv[8:16], partialIV[4:12])
	ctr := make([]byte, 4)
	binary.LittleEndian.PutUint32(ctr, uint32(slot))
	copy(iv[4:8], ctr)
	return
}

func (i *slotIntermediate) setNextHop(nh string) {
	if len(nh) > 52 {
		err := fmt.Errorf("Next hop address exceeds 52 chars")
		panic(err)
	}
	i.nextHop = []byte(nh + strings.Repeat("\x00", 52-len(nh)))
}

func (i *slotIntermediate) getNextHop() string {
	return strings.TrimRight(string(i.nextHop), "\x00")
}

func newSlotIntermediate() *slotIntermediate {
	return &slotIntermediate{
		gotAesIV12: false,
		aesIV12:    make([]byte, 12),
		nextHop:    make([]byte, 52),
	}
}

func (s *slotIntermediate) setIV(partialIV []byte) {
	if len(partialIV) != 12 {
		err := fmt.Errorf(
			"Invalid IV input. Expected 12 Bytes, got %d bytes",
			len(partialIV),
		)
		panic(err)
	}
	s.gotAesIV12 = true
	copy(s.aesIV12, partialIV)
}

// AES_IV constructs a 16 Byte IV from an input of 12 random Bytes and a uint32
// counter.  The format is arbitrary but needs to be predictable and consistent
// between encrypt and decrypt operations.
func (s *slotIntermediate) seqIV(counter int) (iv []byte) {
	if !s.gotAesIV12 {
		err := errors.New(
			"Cannot sequence IV until partial IV is defined",
		)
		panic(err)
	}
	// IV format is: RRRRCCCCRRRRRRRR. Where R=Random and C=Counter
	iv = make([]byte, 16)
	copy(iv, seqIV(s.aesIV12, counter))
	return
}

func (s *slotIntermediate) encode() []byte {
	if !s.gotAesIV12 {
		err := errors.New(
			"Cannot encode until partial IV is defined",
		)
		panic(err)
	}
	var err error
	buf := new(bytes.Buffer)
	buf.Write(s.aesIV12)
	buf.Write(s.nextHop)
	err = lenCheck(buf.Len(), 64)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func decodeIntermediate(b []byte) *slotIntermediate {
	err := lenCheck(len(b), encDataBytes)
	if err != nil {
		panic(err)
	}
	return &slotIntermediate{
		gotAesIV12: true,
		aesIV12:    b[:12],
		nextHop:    b[12:],
	}
}

// ----- Deterministic Headers -----
type aesKeys struct {
	keys             [maxChainLength - 1][]byte
	ivs              [maxChainLength - 1][]byte
	chainLen         int
	intermediateHops int
}

func newAesKeys(intermediateHops int) *aesKeys {
	aes := new(aesKeys)
	// Loop is to 1 less than chainLen as it starts from 0
	for n := 0; n < intermediateHops; n++ {
		aes.keys[n] = randbytes(32)
		aes.ivs[n] = randbytes(12)
	}
	aes.chainLen = intermediateHops + 1
	aes.intermediateHops = intermediateHops
	return aes
}

// seqIV constructs a 16 Byte IV from an input of 12 random Bytes and a uint32
// counter.  The format is arbitrary but needs to be predictable and consistent
// between encrypt and decrypt operations.
func (aes *aesKeys) seqIV(intermediateHop, slot int) (iv []byte) {
	// IV format is: RRRRCCCCRRRRRRRR. Where R=Random and C=Counter
	iv = make([]byte, 16)
	copy(iv, seqIV(aes.ivs[intermediateHop], slot))
	return
}

func (aes *aesKeys) getKey(intermediateHop int) (key []byte) {
	if intermediateHop >= aes.intermediateHops {
		err := fmt.Errorf(
			"Requested key for hop (%d) exceeds array length"+
				" (%d)",
			intermediateHop,
			aes.intermediateHops,
		)
		panic(err)
	}
	key = aes.keys[intermediateHop]
	return
}

func (aes *aesKeys) getIV(intermediateHop, slot int) (iv []byte) {
	iv = make([]byte, 16)
	copy(iv, seqIV(aes.ivs[intermediateHop], slot))
	return
}

func (aes *aesKeys) getPartialIV(intermediateHop int) (ivPartial []byte) {
	if intermediateHop >= aes.intermediateHops {
		err := fmt.Errorf(
			"Requested IV for hop (%d) exceeds array length"+
				" (%d)",
			intermediateHop,
			aes.intermediateHops,
		)
		panic(err)
	}
	ivPartial = aes.ivs[intermediateHop]
	return
}

func (aes *aesKeys) deterministic(hop int) (detBytes []byte) {
	// bottomSlot is total headers - 2.
	// Top slot doesn't count, it's already decrypted.
	// Next slot is numbered Slot 0.
	// For 10 headers, bottom slotnum will be 8.
	bottomSlot := maxChainLength - 2
	topSlot := bottomSlot + hop - (aes.chainLen - 2)
	fakeSlots := bottomSlot - topSlot + 1
	fakeBytes := fakeSlots * headerBytes
	detBytes = make([]byte, fakeBytes)
	fmt.Printf("Fakes=%d, Bytes=%d\n", fakeSlots, fakeBytes)
	fakeSlot := 0
	for slot := topSlot; slot <= bottomSlot; slot++ {
		// Within the slot loop, we're creating a single slot for a
		// single hop but encrypting it multiple times.  fakeHead will
		// contain the actual encrypted Bytes.
		fakeHead := make([]byte, headerBytes)
		// right is the right-most hop from which to encrypt from.  The
		// highest fake slot at hop 0 should encrypt from the first
		// intermediate hop (bottom slot) in the chain. Remember,
		// chains are constructed in reverse.  Hop 0 is always the exit
		// hop.
		right := bottomSlot - slot
		useHop := aes.chainLen - 2 - fakeSlot
		for useSlot := bottomSlot + 1; useSlot > slot; useSlot-- {
			fmt.Printf(
				"PutHop=%d, Top=%d, bottom=%d, PutSlot=%d, Right=%d, useSlot=%d, useHop=%d\n",
				hop,
				topSlot,
				bottomSlot,
				slot,
				right,
				useSlot,
				useHop,
			)
			key := aes.getKey(0)
			iv := aes.getIV(0, useSlot)
			copy(fakeHead, AES_CTR(fakeHead, key, iv))
			useHop--
		}
		copy(detBytes[fakeSlot*headerBytes:(fakeSlot+1)*headerBytes], fakeHead)
		fakeSlot++
	}
	fmt.Printf("Position=%d\n", encHeadersBytes-fakeBytes-headerBytes)
	return
}
