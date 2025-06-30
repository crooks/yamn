package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/crooks/yamn/crandom"
)

func errTest(err error) {
	if err != nil {
		panic(err)
	}
}

func TestEpochTimestamp(t *testing.T) {
	data := newSlotData()
	age := data.ageTimestamp()
	if age < 0 || age > 3 {
		t.Fatalf("Epoch age should be in the range 0-3. Got: %d", age)
	}
}

func TestIntermediate(t *testing.T) {
	inputAesIV12 := []byte("abcdefghijkl")
	inputNextHop := "mrfoobar@anonymous.invalid"
	inInter := newSlotIntermediate()
	inInter.setPartialIV(inputAesIV12)
	inInter.setNextHop(inputNextHop)
	outInter := decodeIntermediate(inInter.encode())
	if !bytes.Equal(outInter.aesIV12, inputAesIV12) {
		t.Fatalf("Intermediate AES IV mismatch: %x", outInter.aesIV12)
	}
	if outInter.getNextHop() != inputNextHop {
		t.Fatalf(
			"Intermediate nextHop mismatch: %s",
			outInter.getNextHop(),
		)
	}
}

func TestSlotData(t *testing.T) {
	inSlotData := newSlotData()
	inSlotData.setTimestamp()
	inSlotData.setPacketInfo(make([]byte, 64))
	inSlotData.setAesKey(crandom.Randbytes(32))
	inSlotData.setTagHash(make([]byte, 32))
	outSlotData := decodeSlotData(inSlotData.encode())
	if !bytes.Equal(inSlotData.packetID, outSlotData.packetID) {
		t.Fatal("PacketID Mismatch")
	}
}

func TestNaClEncryptDecrypt(t *testing.T) {
	inHead := newEncodeHeader()
	inPlain := crandom.Randbytes(160)
	recipientPK, _ := eccGenerate()
	fakeKeyid := crandom.Randbytes(16)
	inHead.setRecipient(fakeKeyid, recipientPK)
	inHead.encode(inPlain)
}

func TestPacket(t *testing.T) {
	plainText := "Hello world!"

	outExitHead := newSlotFinal()
	outExitHead.setBodyBytes(len([]byte(plainText)))
	payload := make([]byte, bodyBytes)
	copy(payload, []byte(plainText))

	outHead := newSlotData()
	outHead.setAesKey(crandom.Randbytes(32))
	outHead.setTagHash(make([]byte, 32))
	outHead.setPacketInfo(outExitHead.encode())
	copy(payload, aesCtr(payload, outHead.aesKey, outExitHead.aesIV))

	inHead := decodeSlotData(outHead.encode())

	inExitHead := decodeFinal(inHead.packetInfo)
	if !bytes.Equal(outHead.aesKey, inHead.aesKey) {
		t.Fatal("AES Key mismatch")
	}
	if !bytes.Equal(outExitHead.aesIV, inExitHead.aesIV) {
		t.Fatal("AES IV mismatch")
	}
	copy(payload, aesCtr(payload, inHead.aesKey, inExitHead.aesIV))
	outText := string(payload[0:inExitHead.bodyBytes])
	if outText != plainText {
		t.Fatal("Body encrypt/decrypt mismatch")
	}
	if !bytes.Equal(outExitHead.messageID, inExitHead.messageID) {
		t.Fatal("MessageID mismatch")
	}
}

/*
func TestKeys(t *testing.T) {
	chainLength := 3
	k := newAesKeys(chainLength - 1)
	fmt.Printf("%x\n", k.deterministic(0))
}
*/

func TestOneHop(t *testing.T) {
	encPlain := []byte("Hello World!")
	exitPK, exitSK := eccGenerate()
	//interPK, interSK := eccGenerate()

	//Create Exit Header Data
	encSlotFinal := newSlotFinal()
	encSlotFinal.setBodyBytes(len(encPlain))
	// Create and populate the Slot Data
	encSlotData := newSlotData()
	// Tell the Slot Data that this is the exit hop, otherwise it will
	// default to intermediate.
	encSlotData.setExit()
	encSlotData.setAesKey(crandom.Randbytes(32))
	encSlotData.setPacketInfo(encSlotFinal.encode())
	encSlotData.setTagHash(make([]byte, 32))
	encSlotDataBytes := encSlotData.encode()

	fakeRecipientKeyID := make([]byte, 16)
	encHeader := newEncodeHeader()
	encHeader.setRecipient(fakeRecipientKeyID, exitPK)

	exitHeader := encHeader.encode(encSlotDataBytes)
	encBody := make([]byte, bodyBytes)
	copy(encBody, aesCtr(encPlain, encSlotData.aesKey, encSlotFinal.aesIV))

	// Create a decode struct called exitHead and fill it with the encoded
	// bytes from encHead
	decHeader := newDecodeHeader(exitHeader)
	// We're faking the KeyID but this at least proves the function
	_ = decHeader.getRecipientKeyID()
	decHeader.setRecipientSK(exitSK)
	decSlotDataBytes, version, err := decHeader.decode()
	if err != nil {
		t.Fatalf("Header docode failed: %s", err)
	}
	if version != 2 {
		t.Fatalf(
			"Not a version 2 type packet. Got version: %d",
			version,
		)
	}
	// Test if the decoded raw Slot Data bytes match the input Slot Data
	if !bytes.Equal(encSlotDataBytes, decSlotDataBytes) {
		t.Fatal("Encoded/Decoded Slot Data mismatch")
	}
	// Convert the raw Slot Data Bytes to meaningful slotData.
	decSlotData := decodeSlotData(decSlotDataBytes)
	if decSlotData.packetType != 1 {
		t.Fatalf(
			"Expected Packet Type 1 (Exit Hop) but got %d",
			decSlotData.packetType,
		)
	}
	decSlotFinal := decodeFinal(decSlotData.packetInfo)

	decBody := make([]byte, bodyBytes)
	copy(decBody, aesCtr(encBody, decSlotData.aesKey, decSlotFinal.aesIV))
	decPlain := decBody[:decSlotFinal.bodyBytes]
	if !bytes.Equal(encPlain, decPlain) {
		t.Fatalf(
			"Body decode mismatch. In=%s, Out=%s",
			encPlain,
			decPlain,
		)
	}
}
func TestMultiHop(t *testing.T) {
	chainLength := maxChainLength
	m := newEncMessage()
	encPlain := []byte("Hello World!")
	plainLength := m.setPlainText(encPlain)
	testPK, testSK := eccGenerate()

	//Create Exit Header Data
	encFinal := newSlotFinal()
	encFinal.setBodyBytes(plainLength)
	// Create and populate the Slot Data
	encData := newSlotData()
	// Tell the Slot Data that this is the exit hop, otherwise it will
	// default to intermediate.
	encData.setExit()
	encData.setAesKey(crandom.Randbytes(32))
	// Encode the Packet Info and store it in the Slot Data
	encData.setPacketInfo(encFinal.encode())

	fakeRecipientKeyID := make([]byte, 16)
	encHeader := newEncodeHeader()
	encHeader.setRecipient(fakeRecipientKeyID, testPK)

	// Define the chain length
	m.setChainLength(chainLength)
	// Populate the message with the encrypted body
	m.encryptBody(encData.aesKey, encFinal.aesIV)
	m.shiftHeaders()
	if chainLength > 1 {
		m.deterministic(0)
	}
	//m.debugPacket()
	encData.setTagHash(m.getAntiTag())
	// Encode the Slot Data
	encDataBytes := encData.encode()
	// Insert an byte encoded version of the newly created header
	m.insertHeader(encHeader.encode(encDataBytes))
	//m.debugPacket()

	// That concludes the exit hop compilation

	//m.debugPacket()
	interHops := m.getIntermediateHops()
	for interHop := 0; interHop < interHops; interHop++ {
		encInter := newSlotIntermediate()
		encInter.setPartialIV(m.getPartialIV(interHop))
		encInter.setNextHop("fake@remailer.org")
		encData = newSlotData()
		encData.setAesKey(m.getKey(interHop))
		encData.setPacketInfo(encInter.encode())
		m.encryptAll(interHop)
		m.shiftHeaders()
		m.deterministic(interHop + 1)
		encData.setTagHash(m.getAntiTag())
		encDataBytes = encData.encode()
		encHeader = newEncodeHeader()
		encHeader.setRecipient(fakeRecipientKeyID, testPK)
		m.insertHeader(encHeader.encode(encDataBytes))
	}

	// End of Intermediate hop encoding

	// Kludge to put the previously encrypted payload into a decMessage
	// struct.
	d := newDecMessage(m.payload)

	var gotExit bool
	for remailer := 0; remailer < maxChainLength; remailer++ {
		// Create a decode struct called exitHead and fill it with the
		// encoded bytes from encHead
		decHeader := newDecodeHeader(d.getHeader())
		// We're faking the KeyID but this at least proves the function
		_ = decHeader.getRecipientKeyID()
		decHeader.setRecipientSK(testSK)
		decDataBytes, version, err := decHeader.decode()
		if err != nil {
			t.Fatalf("Header decode failed: %s", err)
		}
		if version != 2 {
			t.Fatalf(
				"Not a version 2 type packet. Got version: %d",
				version,
			)
		}
		// Convert the raw Slot Data Bytes to meaningful slotData.
		decData := decodeSlotData(decDataBytes)
		if !d.testAntiTag(decData.getTagHash()) {
			d.debugPacket()
			fmt.Printf("Packet Type: %d\n", decData.packetType)
			t.Fatalf("Anti-tag fail at remailer: %d\n", remailer)
		}
		if decData.packetType == 0 {
			d.shiftHeaders()
			// Decode Intermediate
			decInter := decodeIntermediate(decData.packetInfo)
			d.decryptAll(decData.aesKey, decInter.aesIV12)
		} else if decData.packetType == 1 {
			//d.debugPacket()
			// Decode Exit
			gotExit = true
			decFinal := decodeFinal(decData.packetInfo)

			decPlain := d.decryptBody(
				decData.aesKey,
				decFinal.aesIV,
				decFinal.bodyBytes,
			)
			if !bytes.Equal(encPlain, decPlain) {
				t.Fatalf(
					"Body decode mismatch. In=%s, Out=%s",
					encPlain,
					decPlain,
				)
			}
		} else {
			t.Fatalf("Unknown Packet Type: %d", decData.packetInfo)
		}

		if gotExit {
			break
		}
	}
	if !gotExit {
		t.Fatal("Decode loop ended without finding an exit header")
	}
}
