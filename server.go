// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"path"
	"bytes"
	"io/ioutil"
	"encoding/hex"
	"github.com/codahale/blake2"
)

func exportMessage(headers, fake, body []byte, sendto string) (err error) {
	hlen := len(headers) + len(fake)
	err = lenCheck(hlen, headersBytes)
	if err != nil {
		return
	}
	err = lenCheck(len(body), bodyBytes)
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	buf.Write(headers)
	buf.Write(fake)
	buf.Write(body)
	err = bufLenCheck(buf.Len(), messageBytes)
	if err != nil {
		Error.Println("Incorrect outbound message size. Not sending.")
		return
	}
	if sendto == cfg.Remailer.Address {
		Info.Println("Message loops back to us. Storing in pool.")
		digest := blake2.New(&blake2.Config{Size: 16})
		digest.Write(buf.Bytes())
		filename := "m" + hex.EncodeToString(digest.Sum(nil))
		filename = path.Join(cfg.Files.Pooldir, filename[:14])
		err = ioutil.WriteFile(filename, buf.Bytes(), 0600)
		if err != nil {
			Warn.Println(err)
			return
		}
	} else {
		Trace.Printf("Forwarding message to: %s", sendto)
		err = cutmarks(buf.Bytes(), sendto)
	}
	return
}

func server(filename string) (err error) {
	f, err := os.Open(path.Join(cfg.Files.Pooldir, filename))
	defer f.Close()
	if err != nil {
		return
	}
	Trace.Printf("Processing pool file: %s\n", filename)
	// Initialize some slices for the message components
	header := make([]byte, headerBytes)
	headers := make([]byte, encHeadBytes)
	body := make([]byte, bodyBytes)
	var bytesRead int
	// Read each message component and validate its size
	bytesRead, err = f.Read(header)
	if err != nil {
		return
	}
	if bytesRead != headerBytes {
		Warn.Printf("Incorrect header bytes. Wanted=%d, Got=%d", headerBytes, bytesRead)
		return
	}
	bytesRead, err = f.Read(headers)
	if err != nil {
		return
	}
	if bytesRead != encHeadBytes {
		Warn.Printf("Incorrect headers bytes. Wanted=%d, Got=%d", encHeadBytes, bytesRead)
		return
	}
	bytesRead, err = f.Read(body)
	if err != nil {
		return
	}
	if bytesRead != bodyBytes {
		Warn.Printf("Incorrect body bytes. Wanted=%d, Got=%d", bodyBytes, bytesRead)
		return
	}

	var iv []byte
	secring := import_secring()
	/*
	decodeHead only returns the decrypted slotData bytes.  The other fields are
	only concerned with performing the decryption.
	*/
	decodedHeader, err := decodeHead(header, secring)
	if err != nil {
		panic(err)
	}
	// data contains the slotData struct
	data, err := decodeData(decodedHeader)
	if err != nil {
		panic(err)
	}
	digest := blake2.New(nil)
	digest.Write(headers)
	digest.Write(body)
	if ! bytes.Equal(digest.Sum(nil), data.tagHash) {
		panic("Hash tag mismatch")
	}
	if data.packetType == 0 {
		Trace.Println("This is an Intermediate type message")
		// inter contains the slotIntermediate struct
		inter, err := decodeIntermediate(data.packetInfo)
		if err != nil {
			panic(err)
		}
		// Number of headers to decrypt is one less than max chain length
		for headNum := 0; headNum < maxChainLength - 1; headNum++ {
			iv, err = sPopBytes(&inter.aesIVs, 16)
			if err != nil {
				panic(err)
			}
			sbyte := headNum * headerBytes
			ebyte := (headNum + 1) * headerBytes
			copy(headers[sbyte:ebyte], AES_CTR(headers[sbyte:ebyte], data.aesKey, iv))
		}
		// The tenth IV is used to encrypt the deterministic header
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			panic(err)
		}
		//fmt.Printf("Fake: Key=%x, IV=%x\n", data.aesKey[:10], iv[:10])
		fakeHeader := make([]byte, headerBytes)
		copy(fakeHeader, AES_CTR(fakeHeader, data.aesKey, iv))
		// Body is decrypted with the final IV
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			panic(err)
		}
		copy(body, AES_CTR(body, data.aesKey, iv))
		// At this point there should be zero bytes left in the inter IV pool
		if len(inter.aesIVs) != 0 {
			err = fmt.Errorf("IV pool not empty.  Contains %d bytes.", len(inter.aesIVs))
			panic(err)
		}
		err = exportMessage(headers, fakeHeader, body, inter.nextHop)
		if err != nil {
			panic(err)
		}
	} else if data.packetType == 1 {
		Trace.Println("This is an Exit type message")
		final, err := decodeFinal(data.packetInfo)
		if err != nil {
			panic(err)
		}
		body = AES_CTR(body, data.aesKey, final.aesIV)
		fmt.Println(string(body[:final.bodyBytes]))
	}
	return
}
