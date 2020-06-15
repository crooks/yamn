package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dchest/blake2s"
	"golang.org/x/crypto/nacl/box"
	"strings"
	"time"
	//"code.google.com/p/go.crypto/nacl/box"
)

const (
	maxChainLength  = 10
	headerBytes     = 256 // An entire header slot
	encHeadBytes    = 160 // The encrypted component of a header
	encDataBytes    = 64  // Exit / Intermediate header component
	headersBytes    = headerBytes * maxChainLength
	encHeadersBytes = headersBytes - headerBytes
	bodyBytes       = 17920
	messageBytes    = headersBytes + bodyBytes
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

	// Every header has a randomly generated sender PK & SK
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

func (h *decodeHeader) decode() (data []byte, version int, err error) {
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
	// Version number is the first byte of decrypted data
	version = int(data[0])
	return
}

/*
Encrypted data
[ Packet version	  1 Byte  ]
[ Packet type ID	  1 Byte  ]
[ Delivery protocol	  1 Byte  ]
[ Packet ID		 16 Bytes ]
[ AES-CTR key		 32 Bytes ]
[ Timestamp		  2 Bytes ]
[ Packet info		 64 Bytes ]
[ Anti-tag digest	 32 Bytes ]
[ Padding		 11 Bytes ]
Total	160 Bytes

Packet Type: 0=Intermediate 1=Exit
Delivery protocol: 0=SMTP
*/
type slotData struct {
	version       uint8
	packetType    uint8
	protocol      uint8
	packetID      []byte
	gotAesKey     bool   // Test if the AES Key has been defined
	aesKey        []byte // Used for encrypting slots and body
	timestamp     []byte
	gotPacketInfo bool // Test if packetInfo has been defined
	packetInfo    []byte
	gotTagHash    bool // Test if Anti-tag hash has been defined
	tagHash       []byte
}

func newSlotData() *slotData {
	// timestamp will contain the current days since Epoch
	timestamp := make([]byte, 2)
	ts := time.Now().UTC().Unix() / 86400
	// Add some randomness to the timestamp by subtracting 0-3 days
	ts -= int64(dice() % 4)
	binary.LittleEndian.PutUint16(timestamp, uint16(ts))
	return &slotData{
		version:    2, // This packet format is v2
		packetType: 0,
		protocol:   0,
		// packetID is random for intermediate hops but needs to be
		// identical on multi-copy Exits.
		packetID:      randbytes(16),
		gotAesKey:     false,
		aesKey:        make([]byte, 32),
		timestamp:     timestamp,
		gotPacketInfo: false,
		gotTagHash:    false,
		tagHash:       make([]byte, 32),
	}
}

// getPacketID returns the Packet-ID from the Slot Data.
func (head *slotData) getPacketID() []byte {
	return head.packetID
}

func (head *slotData) getPacketType() int {
	return int(head.packetType)
}

// setExit overrides the default Packet Type (0 = Intermediate) with an Exit
// Packet Type (Exit = 1)
func (head *slotData) setExit() {
	head.packetType = 1
}

func (head *slotData) getAesKey() []byte {
	return head.aesKey
}

// setAesKey defines the AES key required to decode the header stack and body.
// For Exit headers, this can be completely random, but for Intermediates, it
// needs to be predetermined in order to calculate Anti-Tag hashes.
func (head *slotData) setAesKey(key []byte) {
	err := lenCheck(len(key), 32)
	if err != nil {
		panic(err)
	}
	copy(head.aesKey, key)
	head.gotAesKey = true
}

// setPacketID overrides the random ID defined in newSlotData.  This ensures
// that on multi-copy messages, the exit hops all have the same Packet ID.
func (head *slotData) setPacketID(id []byte) {
	err := lenCheck(len(id), 16)
	if err != nil {
		panic(err)
	}
	copy(head.packetID, id)
}

func (head *slotData) setTagHash(hash []byte) {
	err := lenCheck(len(hash), 32)
	if err != nil {
		panic(err)
	}
	copy(head.tagHash, hash)
	head.gotTagHash = true
}

func (head *slotData) getTagHash() []byte {
	return head.tagHash
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

// ageTimestamp returns an integer of the timestamp's age in days.
func (head *slotData) ageTimestamp() int {
	err := lenCheck(len(head.timestamp), 2)
	if err != nil {
		panic(err)
	}
	now := int(time.Now().UTC().Unix() / 86400)
	then := int(binary.LittleEndian.Uint16(head.timestamp))
	return now - then
}

func (head *slotData) encode() []byte {
	if !head.gotAesKey {
		err := errors.New(
			"AES key not specified before attempt to encode " +
				"Encrypted Header",
		)
		panic(err)
	}
	if !head.gotPacketInfo {
		err := errors.New(
			"Exit/Intermediate not defined before attempt to " +
				"encode Encrypted Header.",
		)
		panic(err)
	}
	if !head.gotTagHash {
		err := errors.New(
			"Anti-Tag Hash not defined before attempt to " +
				"encode Encrypted Header.",
		)
		panic(err)
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(head.version)
	buf.WriteByte(head.packetType)
	buf.WriteByte(head.protocol)
	buf.Write(head.packetID)
	buf.Write(head.aesKey)
	buf.Write(head.timestamp)
	buf.Write(head.packetInfo)
	buf.Write(head.tagHash)
	err := lenCheck(buf.Len(), 149)
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
	// Test the correct libary is being employed for the packet version
	version := int(b[0])
	if version != 2 {
		err := fmt.Errorf(
			"Attempt to decode packet v%d with v2 library",
			version,
		)
		panic(err)
	}
	return &slotData{
		version:    b[0],
		packetType: b[1],
		protocol:   b[2],
		packetID:   b[3:19],
		aesKey:     b[19:51],
		timestamp:  b[51:53],
		packetInfo: b[53:117],
		tagHash:    b[117:149],
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
	packetID       []byte // Not encoded but used in Slot Header on Exits
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
		packetID:       randbytes(16),
		gotBodyBytes:   false,
		deliveryMethod: 0,
	}
}

func (f *slotFinal) getBodyBytes() int {
	return f.bodyBytes
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

func (f *slotFinal) getAesIV() []byte {
	return f.aesIV
}

// getPacketID returns the packet ID that should be copied into the Slot Data
// for Exit Hop messages.  When creating mutliple copies, the PacketID needs to
// be common across all exit packets to prevent duplicate deliveries.
func (f *slotFinal) getPacketID() []byte {
	return f.packetID
}

func (f *slotFinal) getNumChunks() int {
	return int(f.numChunks)
}

func (f *slotFinal) setNumChunks(n int) {
	f.numChunks = uint8(n)
}

func (f *slotFinal) getMessageID() []byte {
	return f.messageID
}

func (f *slotFinal) setDeliveryMethod(n int) {
	f.deliveryMethod = uint8(n)
}

func (f *slotFinal) getDeliveryMethod() int {
	return int(f.deliveryMethod)
}

func (f *slotFinal) getChunkNum() int {
	return int(f.chunkNum)
}

func (f *slotFinal) setChunkNum(n int) {
	if uint8(n) > f.numChunks {
		err := fmt.Errorf(
			"Attempt to set Chunk Num (%d) greater than defined"+
				"number of chunks (%d)",
			n,
			int(f.numChunks),
		)
		panic(err)
	}
	f.chunkNum = uint8(n)
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
		aesIV:          b[:16],
		chunkNum:       b[16],
		numChunks:      b[17],
		messageID:      b[18:34],
		bodyBytes:      int(binary.LittleEndian.Uint32(b[34:38])),
		deliveryMethod: b[38],
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

func newSlotIntermediate() *slotIntermediate {
	return &slotIntermediate{
		gotAesIV12: false,
		aesIV12:    make([]byte, 12),
		nextHop:    make([]byte, 52),
	}
}

func (s *slotIntermediate) setPartialIV(partialIV []byte) {
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

// setNextHop inserts the name of the next hop remailer and pads it.
func (i *slotIntermediate) setNextHop(nh string) {
	if len(nh) > 52 {
		err := fmt.Errorf("Next hop address exceeds 52 chars")
		panic(err)
	}
	i.nextHop = []byte(nh + strings.Repeat("\x00", 52-len(nh)))
}

//getNextHop returns the next hop remailer name after stripping any padding.
func (i *slotIntermediate) getNextHop() string {
	return strings.TrimRight(string(i.nextHop), "\x00")
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
type encMessage struct {
	gotPayload       bool   // Test if a Payload has been submitted
	payload          []byte // The actual Yamn message
	plainLength      int    // Length of the plain-text bytes
	keys             [maxChainLength - 1][]byte
	ivs              [maxChainLength - 1][]byte
	chainLength      int // Number of hops in chain
	intermediateHops int // Number of Intermediate hops
	padHeaders       int // Number of padding headers
	padBytes         int // Total bytes of padding
}

// newEncMessage creates a new encMessage object.  This provides client-side
// functionality for creating a new Yamn message.
func newEncMessage() *encMessage {
	return &encMessage{
		gotPayload:  false,
		payload:     make([]byte, messageBytes),
		chainLength: 0,
	}
}

// getPayload returns the raw payload bytes.  Currently no checks are performed
// as to what state the payload is in when its requested.
func (m *encMessage) getPayload() []byte {
	return m.payload
}

// setChainLength takes an integer containing the length of the chain being
// encoded.  From this we can derive various settings, such as the number of
// fake (padding) headers required.  It also initializes and populates an array
// of AES keys and IVs used to encrypt the intermediate hops.  These have to be
// predefined as they're required to create deterministic headers.
func (m *encMessage) setChainLength(chainLength int) {
	if chainLength > maxChainLength {
		err := fmt.Errorf(
			"Specified chain length (%d) exceeds "+
				"maximum chain length (%d)",
			chainLength,
			maxChainLength,
		)
		panic(err)
	}
	if chainLength <= 0 {
		err := errors.New("Chain length cannot be negative or zero")
		panic(err)
	}
	m.chainLength = chainLength
	m.intermediateHops = chainLength - 1
	m.padHeaders = maxChainLength - m.chainLength
	m.padBytes = m.padHeaders * headerBytes
	// The padding bytes need to be randomized, otherwise the final
	// intermediate remailer in the chain can know its position due to the
	// zero bytes below the decrypted exit header.  After this, the payload
	// will contain nothing but padding.
	copy(m.payload, randbytes(m.padBytes))
	// Generate keys and (partial) IVs for each hop
	for n := 0; n < m.intermediateHops; n++ {
		m.keys[n] = randbytes(32)
		m.ivs[n] = randbytes(12)
	}
}

// setPlainText inserts the plain message content into the payload and returns
// its length in Bytes
func (m *encMessage) setPlainText(plain []byte) (plainLength int) {
	plainLength = len(plain)
	if m.plainLength > bodyBytes {
		err := fmt.Errorf(
			"Payload (%d) exceeds max length (%d)",
			plainLength,
			bodyBytes,
		)
		panic(err)
	}
	// Insert the plain bytes after the headers
	copy(m.payload[headersBytes:], plain)
	m.gotPayload = true
	return
}

// getIntermediateHops returns the number of intermediate hops in the chain.
func (m *encMessage) getIntermediateHops() int {
	if m.chainLength == 0 {
		err := errors.New(
			"Cannot get hop count. Chain length is not defined",
		)
		panic(err)
	}
	return m.intermediateHops
}

// seqIV constructs a 16 Byte IV from an input of 12 random Bytes and a uint32
// counter.  The format is arbitrary but needs to be predictable and consistent
// between encrypt and decrypt operations.
func (m *encMessage) getIV(intermediateHop, slot int) (iv []byte) {
	if m.chainLength == 0 {
		err := errors.New(
			"Cannot get an IV until the chain length is defined",
		)
		panic(err)
	}
	// IV format is: RRRRCCCCRRRRRRRR. Where R=Random and C=Counter
	iv = make([]byte, 16)
	copy(iv, seqIV(m.ivs[intermediateHop], slot))
	return
}

// getKey returns the predetermined AES key for a specific Hop in the Chain.
func (m *encMessage) getKey(intermediateHop int) (key []byte) {
	if m.chainLength == 0 {
		err := errors.New(
			"Cannot get a Key until the chain length is defined",
		)
		panic(err)
	}
	if intermediateHop >= m.intermediateHops {
		err := fmt.Errorf(
			"Requested key for hop (%d) exceeds array length"+
				" (%d)",
			intermediateHop,
			m.intermediateHops,
		)
		panic(err)
	}
	key = m.keys[intermediateHop]
	return
}

// getPartialIV returns the predetermined partial IV for a specific Hop.
func (m *encMessage) getPartialIV(intermediateHop int) (ivPartial []byte) {
	/*
		It should be noted that the 12 byte partial IV returned by this
		function cannot be used directly to encrypt anything.  It needs
		a 4 byte sequence number added to it in order to be usable.
	*/
	if intermediateHop > m.intermediateHops {
		err := fmt.Errorf(
			"Requested IV for hop (%d) exceeds array length"+
				" (%d)",
			intermediateHop,
			m.intermediateHops,
		)
		panic(err)
	}
	ivPartial = m.ivs[intermediateHop]
	return
}

// getAntiTag returns a digest for the entire header stack.  It needs to be run
// before a new header is inserted but after deterministic headers are appended
// to the bottom of the header stack.
func (m *encMessage) getAntiTag() []byte {
	digest, err := blake2s.New(nil)
	if err != nil {
		panic(err)
	}
	digest.Write(m.payload[headerBytes:])
	return digest.Sum(nil)
}

// Encrypt the body with the provided key and IV.  This should only be used for
// encryption of the Body during Exit-Hop encoding.  At other times, encryptAll
// should be used.
func (m *encMessage) encryptBody(key, iv []byte) {
	var err error
	if !m.gotPayload {
		err = errors.New("Cannot encrypt payload until it's defined")
		panic(err)
	}
	err = lenCheck(len(key), 32)
	if err != nil {
		panic(err)
	}
	err = lenCheck(len(iv), 16)
	if err != nil {
		panic(err)
	}

	copy(
		m.payload[headersBytes:],
		aesCtr(
			m.payload[headersBytes:],
			key,
			iv,
		),
	)
}

// encryptAll encrypts each Header Slot in the message using a predetermined
// AES Key and partial (12 byte) IV, plus a 4 byte sequence number base on the
// Slot number.  Finally, the body is encrypted using the same key and partial
// IV (with the next sequenced number).
func (m *encMessage) encryptAll(hop int) {
	// The same key is used for all these encrypt operations
	key := m.getKey(hop)
	var iv []byte
	/*
		* This should run before headers are shifted down *
		For maxChainLength = 10:-
		IVs 0-8 are used to encrypt headers
		IV 9 is used to encrypt the payload
	*/
	for slot := 0; slot < maxChainLength; slot++ {
		sbyte := slot * headerBytes
		ebyte := (slot + 1) * headerBytes
		iv = m.getIV(hop, slot)
		copy(
			m.payload[sbyte:ebyte],
			aesCtr(m.payload[sbyte:ebyte], key, iv),
		)
	}
	iv = m.getIV(hop, maxChainLength)
	copy(
		m.payload[headersBytes:],
		aesCtr(m.payload[headersBytes:], key, iv),
	)
}

// shiftHeaders moves the entire header stack down by headerBytes.
func (m *encMessage) shiftHeaders() {
	// Find a point one header size up from the bottom of the header stack
	bottomHeader := headersBytes - headerBytes
	// Move the header stack down by headerBytes
	copy(m.payload[headerBytes:], m.payload[:bottomHeader])
}

// insertHeader copies provided header bytes into the payload
func (m *encMessage) insertHeader(header []byte) {
	err := lenCheck(len(header), headerBytes)
	if err != nil {
		panic(err)
	}
	copy(m.payload[:headerBytes], header)
}

// deterministic inserts predetermined headers at the bottom of the stack.  As
// the stack scrolls up during decryption, a blank header is inserted at the
// bottom.  This is then decrypted along with all the real headers.  This
// hellish function works out what those headers will contain at each phase of
// the remailer decryption chain.
func (m *encMessage) deterministic(hop int) {
	if m.chainLength == 0 {
		err := errors.New(
			"Cannot generate deterministic headers until chain " +
				"length has been specified.",
		)
		panic(err)
	}
	// The top and bottom slots are the slots we're populating during this
	// cycle.
	bottomSlot := maxChainLength - 1
	topSlot := bottomSlot - (m.intermediateHops - hop - 1)
	// Slot in this context is the slot the header will be placed in, on
	// the current hop.  Not, the slot to encrypt from.
	for slot := topSlot; slot <= bottomSlot; slot++ {
		// right is the rightmost hop, from which to encrypt.
		right := bottomSlot - slot + hop
		useSlot := bottomSlot
		fakeHead := make([]byte, headerBytes)
		// Work back from the rightmost slot to the first intermediate
		// header.
		for interHop := right; interHop-hop >= 0; interHop-- {
			key := m.getKey(interHop)
			iv := m.getIV(interHop, useSlot)
			copy(fakeHead, aesCtr(fakeHead, key, iv))
			useSlot--
		}
		// Actually insert the fiendish header into the message
		sByte := slot * headerBytes
		eByte := sByte + headerBytes
		copy(m.payload[sByte:eByte], fakeHead)
	}
}

// debugPacket is only used for debugging purposes.  It outputs the first 20
// bytes of each message component.  The last line output will be the first 20
// bytes of the payload body.
func (m *encMessage) debugPacket() {
	fmt.Println("Encrypt diagnostic")
	for slot := 0; slot <= maxChainLength; slot++ {
		sbyte := slot * headerBytes
		ebyte := sbyte + 20
		fmt.Printf(
			"%05d-%05d: %x %02d\n",
			sbyte,
			ebyte,
			m.payload[sbyte:ebyte],
			slot,
		)
	}
}

type decMessage struct {
	payload []byte // The actual Yamn message
}

// newDecMessage creates a new decMessage object and populates it with the
// provided message bytes (assumed to be an encrypted message).
func newDecMessage(encPayload []byte) (dec *decMessage) {
	err := lenCheck(len(encPayload), messageBytes)
	if err != nil {
		panic(err)
	}
	dec = new(decMessage)
	dec.payload = make([]byte, messageBytes)
	copy(dec.payload, encPayload)
	return
}

// getHeader returns the top-most header
func (m *decMessage) getHeader() []byte {
	return m.payload[:headerBytes]
}

// getPayload returns the entire payload as a byte slice
func (m *decMessage) getPayload() []byte {
	return m.payload
}

// shiftHeaders moves the entire header stack up by headerBytes and chops off
// the top header.  The created slot of headerBytes at the bottom is
// initialized.
func (m *decMessage) shiftHeaders() {
	// Find a point one header size up from the bottom of the header stack
	bottomHeader := headersBytes - headerBytes
	// Move the header stack  up by one headerBytes
	copy(m.payload, m.payload[headerBytes:headersBytes])
	// Insert a new empty header at the bottom of the stack
	copy(m.payload[bottomHeader:], make([]byte, headerBytes))
}

// testAntiTag creates a Blake2 hash of the entire payload (less the top
// headerBytes) and compares it with the provided hash.  If the two collide, it
// returns True.
func (m *decMessage) testAntiTag(tag []byte) bool {
	digest, err := blake2s.New(nil)
	if err != nil {
		panic(err)
	}
	digest.Write(m.payload[headerBytes:])
	if bytes.Compare(tag, digest.Sum(nil)) == 0 {
		return true
	}
	return false
}

// Decrypt the body with the provided key and IV.  This function should only be
// called during exit decryption.  At other times, decryptAll should be used.
func (m *decMessage) decryptBody(key, iv []byte, length int) []byte {
	var err error
	err = lenCheck(len(key), 32)
	if err != nil {
		panic(err)
	}
	err = lenCheck(len(iv), 16)
	if err != nil {
		panic(err)
	}

	copy(
		m.payload[headersBytes:],
		aesCtr(
			m.payload[headersBytes:],
			key,
			iv,
		),
	)
	return m.payload[headersBytes : headersBytes+length]
}

// Decrypt each header in turn using a supplied key and partial IV.  Also
// decrypt the body using the same key and last IV in the sequence.
func (m *decMessage) decryptAll(key, partialIV []byte) {
	var err error
	err = lenCheck(len(key), 32)
	if err != nil {
		panic(err)
	}
	err = lenCheck(len(partialIV), 12)
	if err != nil {
		panic(err)
	}
	var iv []byte
	for slot := 0; slot < maxChainLength; slot++ {
		sbyte := slot * headerBytes
		ebyte := (slot + 1) * headerBytes
		iv = seqIV(partialIV, slot)
		copy(
			m.payload[sbyte:ebyte],
			aesCtr(m.payload[sbyte:ebyte], key, iv),
		)
	}
	// IVs from 0 to maxChainLength-1 have been used for the headers.  The
	// next IV in sequence (maxChainLength) is used to decrypt the body.
	iv = seqIV(partialIV, maxChainLength)
	copy(
		m.payload[headersBytes:],
		aesCtr(m.payload[headersBytes:], key, iv),
	)
}

// debugPacket is only used for debugging purposes.  It outputs the first 20
// bytes of each message component.  The last line output will be the first 20
// bytes of the payload body.
func (m *decMessage) debugPacket() {
	fmt.Println("Decrypt diagnostic")
	for slot := 0; slot <= maxChainLength; slot++ {
		sbyte := slot * headerBytes
		ebyte := sbyte + 20
		fmt.Printf(
			"%05d-%05d: %x %02d\n",
			sbyte,
			ebyte,
			m.payload[sbyte:ebyte],
			slot,
		)
	}
}
