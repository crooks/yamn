package main

import (
	"bytes"
	"fmt"
	"testing"
)

func errTest(err error) {
	if err != nil {
		panic(err)
	}
}

func TestEpochTimestamp(t *testing.T) {
	data := newSlotData()
	data.setTimestamp()
	age := data.ageTimestamp()
	if age != 0 {
		t.Fatalf("Epoch age should be zero. Got: %d", age)
	}
}

func TestIntermediate(t *testing.T) {
	inputAesIV12 := []byte("abcdefghijkl")
	inputNextHop := "mrfoobar@anonymous.invalid"
	inInter := newSlotIntermediate()
	inInter.setPartialIV(inputAesIV12)
	inInter.setNextHop(inputNextHop)
	outInter := decodeIntermediate(inInter.encode())
	if bytes.Compare(outInter.aesIV12, inputAesIV12) != 0 {
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
	inSlotData.setAesKey(randbytes(32))
	outSlotData := decodeSlotData(inSlotData.encode())
	if bytes.Compare(inSlotData.packetID, outSlotData.packetID) != 0 {
		t.Fatal("PacketID Mismatch")
	}
}

func TestNaClEncryptDecrypt(t *testing.T) {
	inHead := newEncodeHeader()
	inPlain := randbytes(160)
	recipientPK, _ := eccGenerate()
	fakeKeyid := randbytes(16)
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
	outHead.setAesKey(randbytes(32))
	outHead.setPacketInfo(outExitHead.encode())
	copy(payload, AES_CTR(payload, outHead.aesKey, outExitHead.aesIV))

	inHead := decodeSlotData(outHead.encode())

	inExitHead := decodeFinal(inHead.packetInfo)
	if bytes.Compare(outHead.aesKey, inHead.aesKey) != 0 {
		t.Fatal("AES Key mismatch")
	}
	if bytes.Compare(outExitHead.aesIV, inExitHead.aesIV) != 0 {
		t.Fatal("AES IV mismatch")
	}
	copy(payload, AES_CTR(payload, inHead.aesKey, inExitHead.aesIV))
	outText := string(payload[0:inExitHead.bodyBytes])
	if outText != plainText {
		t.Fatal("Body encrypt/decrypt mismatch")
	}
	if bytes.Compare(outExitHead.messageID, inExitHead.messageID) != 0 {
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

func DontTestOneHop(t *testing.T) {
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
	encSlotData.setPacketInfo(encSlotFinal.encode())
	encSlotDataBytes := encSlotData.encode()

	fakeRecipientKeyID := make([]byte, 16)
	encHeader := newEncodeHeader()
	encHeader.setRecipient(fakeRecipientKeyID, exitPK)

	exitHeader := encHeader.encode(encSlotDataBytes)
	encBody := make([]byte, bodyBytes)
	copy(encBody, AES_CTR(encPlain, encSlotData.aesKey, encSlotFinal.aesIV))

	// Create a decode struct called exitHead and fill it with the encoded
	// bytes from encHead
	decHeader := newDecodeHeader(exitHeader)
	// We're faking the KeyID but this at least proves the function
	_ = decHeader.getRecipientKeyID()
	decHeader.setRecipientSK(exitSK)
	decSlotDataBytes, err := decHeader.decode()
	if err != nil {
		t.Fatalf("Header docode failed: %s", err)
	}
	// Test if the decoded raw Slot Data bytes match the input Slot Data
	if bytes.Compare(encSlotDataBytes, decSlotDataBytes) != 0 {
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
	copy(decBody, AES_CTR(encBody, decSlotData.aesKey, decSlotFinal.aesIV))
	decPlain := decBody[:decSlotFinal.bodyBytes]
	if bytes.Compare(encPlain, decPlain) != 0 {
		t.Fatalf(
			"Body decode mismatch. In=%s, Out=%s",
			encPlain,
			decPlain,
		)
	}
}
func TestMultiHop(t *testing.T) {
	chainLength := 5
	m := newEncMessage(chainLength)
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
	encData.setAesKey(randbytes(32))
	// Encode the Packet Info and store it in the Slot Data
	encData.setPacketInfo(encFinal.encode())

	fakeRecipientKeyID := make([]byte, 16)
	encHeader := newEncodeHeader()
	encHeader.setRecipient(fakeRecipientKeyID, testPK)

	// Populate the message with the encrypted body
	m.encryptBody(encData.aesKey, encFinal.aesIV)
	// Insert the anti-Tag hash into the Slot Data.  This needs to be done
	// before the new header is inserted, thus pushing down the header
	// stack.
	encData.setTagHash(m.getAntiTag())
	// Encode the Slot Data
	encDataBytes := encData.encode()
	// Insert an byte encoded version of the newly created header
	m.insertHeader(encHeader.encode(encDataBytes))

	// That concludes the exit hop compilation

	//m.debugPacket()
	for interHop := 0; interHop < m.intermediateHops; interHop++ {
		encInter := newSlotIntermediate()
		encInter.setPartialIV(m.getPartialIV(interHop))
		encInter.setNextHop("fake@remailer.org")
		encData = newSlotData()
		encData.setAesKey(m.getKey(interHop))
		encData.setPacketInfo(encInter.encode())
		m.encryptAll(interHop)
		m.debugPacket()
		encData.setTagHash(m.getAntiTag())
		encDataBytes = encData.encode()
		encHeader = newEncodeHeader()
		encHeader.setRecipient(fakeRecipientKeyID, testPK)
		m.insertHeader(encHeader.encode(encDataBytes))
	}
	//m.debugPacket()

	// End of Intermediate hop encoding

	// Kludge to put the previously encrypted payload into a decMessage
	// struct.
	d := newDecMessage(m.payload)

	var gotExit bool
	for remailer := 0; remailer < maxChainLength; remailer++ {
		// Create a decode struct called exitHead and fill it with the
		// encoded bytes from encHead
		decHeader := newDecodeHeader(d.payload[:headerBytes])
		d.shiftHeaders()
		// We're faking the KeyID but this at least proves the function
		_ = decHeader.getRecipientKeyID()
		decHeader.setRecipientSK(testSK)
		decDataBytes, err := decHeader.decode()
		if err != nil {
			t.Fatalf("Header decode failed: %s", err)
		}
		// Convert the raw Slot Data Bytes to meaningful slotData.
		decData := decodeSlotData(decDataBytes)
		if !d.testAntiTag(decData.getTagHash()) {
			d.debugPacket()
			//t.Fatal("Anti-Tagging Digest mismatch")
		}
		if decData.packetType == 0 {
			// Decode Intermediate
			decInter := decodeIntermediate(decData.packetInfo)
			d.decryptAll(decData.aesKey, decInter.aesIV12)
			fmt.Println("Completed intermediate decode")
		} else if decData.packetType == 1 {
			// Decode Exit
			gotExit = true
			decFinal := decodeFinal(decData.packetInfo)

			decPlain := d.decryptBody(
				decData.aesKey,
				decFinal.aesIV,
				decFinal.bodyBytes,
			)
			if bytes.Compare(encPlain, decPlain) != 0 {
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
