// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"path"
	"bytes"
	"time"
	"errors"
	"io/ioutil"
	"encoding/hex"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/idlog"
	//"github.com/codahale/blake2"
)

func loopServer() (err error) {
	var filenames []string
	// Populate public and secret keyrings
	public := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	secret := keymgr.NewSecring()
	public.ImportPubring()
	secret.ImportSecring(cfg.Files.Secring)
	// Create some dirs if it doesn't already exist
	err = os.MkdirAll(cfg.Files.IDlog, 0700)
	if err != nil {
		return
	}
	err = os.MkdirAll(cfg.Files.Pooldir, 0700)
	if err != nil {
		return
	}
	// Open the IDlog
	Trace.Printf("Opening ID Log: %s", cfg.Files.IDlog)
	idlog, err := idlog.NewInstance(cfg.Files.IDlog)
	if err != nil {
		panic(err)
	}
	defer idlog.Close()
	// Is a new ECC Keypair required?
	generate := false
	// Find out the Keyid we're advertising
	advertisedKeyid, err := public.Advertising(cfg.Files.Pubkey)
	if err != nil {
		Info.Println("No valid Public key, will generate a new pair")
		generate = true
	}
	// Try to validate the advertised key on Secring
	if ! generate {
		valid, err := secret.Validate(advertisedKeyid)
		if err != nil {
			Warn.Printf("%s: Failed to validate key in Secring", advertisedKeyid)
			generate = true
		} else if valid {
			Info.Printf("Advertising keyid=%s", advertisedKeyid)
		} else {
			Info.Printf("%s has expired, will generate a new key pair", advertisedKeyid)
			generate = true
		}
	}
	// Create a new key pair
	if generate {
		Info.Println("Generating and advertising a new key pair")
		pub, sec := eccGenerate()
		err = secret.Publish(
			cfg.Files.Pubkey,	cfg.Files.Secring,
			pub, sec,
			keyValidityDays,
			cfg.Remailer.Exit,
			cfg.Remailer.Name, cfg.Remailer.Address, version)
		if err != nil {
			Error.Printf("Aborting! Key generation failure: %s", err)
			return
		}
	}

	//TODO Make this a flag function
	secret.Purge("test.txt")

	// Complain about excessively small loop values.
	if cfg.Remailer.Loop < 60 {
		Warn.Println(
			fmt.Sprintf("Loop time of %d is excessively low. ", cfg.Remailer.Loop),
			"Will loop every 60 seconds. A higher setting is recommended.")
	}
	// Complain about high pool rates.
	if cfg.Pool.Rate > 90 {
		Warn.Println(
			fmt.Sprintf("Your pool rate of %d is excessively", cfg.Pool.Rate),
			"high. Unless testing, a lower setting is recommended.")
	}

	// Maintain time of last pool process
	poolProcessTime := time.Now()
	poolProcessDelay := time.Duration(cfg.Remailer.Loop) * time.Second

	// Actually start the server loop
	Info.Printf("Starting YAMN server: %s", cfg.Remailer.Name)
	for {
		if time.Now().Before(poolProcessTime) {
			mailRead()
			// Don't do anything beyond this point until poolProcessTime
			time.Sleep(60 * time.Second)
			continue
		}
		// Test if in-memory pubring is current
		if public.KeyRefresh() {
			// Time to re-read the pubring file
			Info.Printf("Reimporting keyring: %s", cfg.Files.Pubring)
			public.ImportPubring()
		}
		filenames, err = poolRead()
		for _, file := range filenames {
			err = processPoolFile(file, secret, idlog)
			if err != nil {
				Info.Printf("Discarding message: %s", err)
			}
			poolDelete(file)
		}
		poolProcessTime = time.Now().Add(poolProcessDelay)
	}
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
		Error.Println("Incorrect outbound message size. Not sending.")
		return
	}
	if sendto == cfg.Remailer.Address {
		Info.Println("Message loops back to us. Storing in pool.")
		//digest := blake2.New(&blake2.Config{Size: 16})
		digest := sha256.New()
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

func processPoolFile(filename string, secret *keymgr.Secring, idlog idlog.IDLog) (err error) {
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
	/*
	decodeHead only returns the decrypted slotData bytes.  The other fields are
	only concerned with performing the decryption.
	*/
	var decodedHeader []byte
	decodedHeader, err = decodeHead(header, secret)
	if err != nil {
		return
	}
	// data contains the slotData struct
	data := new(slotData)
	err = data.decodeData(decodedHeader)
	if err != nil {
		return
	}
	// Test uniqueness of packet ID
	if ! idlog.Unique(data.packetID, cfg.Remailer.IDexp) {
		err = errors.New("Packet ID collision")
		return
	}
	//digest := blake2.New(nil)
	digest := sha512.New()
	digest.Write(headers)
	digest.Write(body)
	if ! bytes.Equal(digest.Sum(nil), data.tagHash) {
		err = fmt.Errorf("Digest mismatch on Anti-tag hash")
		return
	}
	if data.packetType == 0 {
		Trace.Println("This is an Intermediate type message")
		// inter contains the slotIntermediate struct
		inter := new(slotIntermediate)
		err = inter.decodeIntermediate(data.packetInfo)
		if err != nil {
			return
		}
		// Number of headers to decrypt is one less than max chain length
		for headNum := 0; headNum < maxChainLength - 1; headNum++ {
			iv, err = sPopBytes(&inter.aesIVs, 16)
			if err != nil {
				return
			}
			sbyte := headNum * headerBytes
			ebyte := (headNum + 1) * headerBytes
			copy(headers[sbyte:ebyte], AES_CTR(headers[sbyte:ebyte], data.aesKey, iv))
		}
		// The tenth IV is used to encrypt the deterministic header
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			return
		}
		//fmt.Printf("Fake: Key=%x, IV=%x\n", data.aesKey[:10], iv[:10])
		fakeHeader := make([]byte, headerBytes)
		copy(fakeHeader, AES_CTR(fakeHeader, data.aesKey, iv))
		// Body is decrypted with the final IV
		iv, err = sPopBytes(&inter.aesIVs, 16)
		if err != nil {
			return
		}
		copy(body, AES_CTR(body, data.aesKey, iv))
		// At this point there should be zero bytes left in the inter IV pool
		if len(inter.aesIVs) != 0 {
			err = fmt.Errorf("IV pool not empty.  Contains %d bytes.", len(inter.aesIVs))
			return
		}
		err = exportMessage(headers, fakeHeader, body, inter.nextHop)
		if err != nil {
			return
		}
	} else if data.packetType == 1 {
		Trace.Println("This is an Exit type message")
		final := new(slotFinal)
		err = final.decodeFinal(data.packetInfo)
		if err != nil {
			return
		}
		body = AES_CTR(body[:final.bodyBytes], data.aesKey, final.aesIV)
		var recipients []string
		recipients, err = testMail(body)
		if err != nil {
			return
		}
		for _, sendto := range recipients {
			if cfg.Mail.Sendmail {
				err = sendmail(body, sendto)
				if err != nil {
					Warn.Println("Sendmail failed")
					return
				}
			} else {
				err = SMTPRelay(body, sendto)
				if err != nil {
					Warn.Println("SMTP relay failed")
					return
				}
			}
		}
	}
	return
}
