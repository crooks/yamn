// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"bytes"
)

const (
	version string = "0.1a"
	date_format string = "2006-01-02"
	key_validity_days int = 60
	max_frag_length = 10230
	maxChainLength = 10
	maxCopies = 5
	base64_line_wrap = 40
	headerBytes = 512
	headersBytes = headerBytes * maxChainLength
	bodyBytes = 10240
	messageBytes = headersBytes + bodyBytes
)

func importMessage(filename string) (header, headers, body []byte, err error) {
	msg, err := uncut(filename)
	if err != nil {
		return
	}
	header = msg[:headerBytes]
	headers = msg[headerBytes:headersBytes]
	body = msg[headersBytes:]
	err = lenCheck(len(body), bodyBytes)
	return
}

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
		return
	}
	err = cutmarks("test.txt", sendto, buf.Bytes())
	return
}

func server() {
	var err error
	var iv []byte
	header, headers, body, err := importMessage("test.txt")
	if err != nil {
		panic(err)
	}
	secring := import_secring()
	/*
	decodeHead only returns the decrypted slotData bytes.  The other headers are
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
	//TODO Deterministic Hashtag check needs to happen here
	if data.packetType == 0 {
		// inter contains the slotIntermediate struct
		inter, err := decodeIntermediate(data.packetInfo)
		if err != nil {
			panic(err)
		}
		// Number of headers to decrypt is one less than max chain length
		for headNum := 0; headNum <= maxChainLength - 1; headNum++ {
			iv, err = ivExtract(inter.aesIVs, headNum)
			if err != nil {
				panic(err)
			}
			headersPos := headerBytes * headNum
			header := make([]byte, headerBytes)
			copy(header, headers[headersPos:headersPos+headerBytes])
			copy(headers[headersPos:], AES_CTR(header, data.aesKey, iv))
		}
		// Body is decrypted with the next IV
		iv, err = ivExtract(inter.aesIVs, maxChainLength)
		if err != nil {
			panic(err)
		}
		copy(body, AES_CTR(body, data.aesKey, iv))
		// The final IV is used to encrypt the deterministic header
		iv, err = ivExtract(inter.aesIVs, maxChainLength + 1)
		if err != nil {
			panic(err)
		}
		fakeHeader := make([]byte, headerBytes)
		copy(fakeHeader, AES_CTR(fakeHeader, data.aesKey, iv))
		err = exportMessage(headers, fakeHeader, body, inter.nextHop)
		if err != nil {
			panic(err)
		}
	} else if data.packetType == 1 {
		final, err := decodeFinal(data.packetInfo)
		if err != nil {
			panic(err)
		}
		body = AES_CTR(body, data.aesKey, final.aesIV)
		fmt.Println(string(body[:final.bodyBytes]))
	}
}

func main() {
	flags()
	if flag_client {
		mixprep()
	} else {
		server()
	}
}
