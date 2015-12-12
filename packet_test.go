package main

import (
	"bytes"
	//"fmt"
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
	inInter.setIV(inputAesIV12)
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

func TestCompile(t *testing.T) {
	encPlain := []byte("Hello World!")
	exitPK, exitSK := eccGenerate()
	//interPK, interSK := eccGenerate()

	//Create Exit Header Data
	encSlotFinal := newSlotFinal()
	encSlotFinal.setBodyBytes(len(encPlain))
	// Create and populate the Slot Data
	encSlotData := newSlotData()
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
	if bytes.Compare(encSlotDataBytes, decSlotDataBytes) != 0 {
		t.Fatal("Encoded/Decoded Slot Data mismatch")
	}
	decSlotData := decodeSlotData(decSlotDataBytes)
	decSlotFinal := decodeFinal(decSlotData.packetInfo)

	decBody := make([]byte, bodyBytes)
	copy(decBody, AES_CTR(encBody, decSlotData.aesKey, decSlotFinal.aesIV))
	decPlain := decBody[:decSlotFinal.bodyBytes]
	if bytes.Compare(encPlain, decPlain) != 0 {
		t.Fatalf("Body decode mismatch. In=%s, Out=%s", encPlain, decPlain)
	}
}
