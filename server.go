// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
	"path"
	"bytes"
	"time"
	"strings"
	"io/ioutil"
	"encoding/hex"
	"crypto/sha256"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/idlog"
	//"github.com/codahale/blake2"
)

func loopServer() (err error) {
	var filenames []string
	// Populate public and secret keyrings
	public := keymgr.NewPubring(cfg.Files.Pubring, cfg.Files.Mlist2)
	secret := keymgr.NewSecring(cfg.Files.Secring, cfg.Files.Pubkey)
	public.ImportPubring()
	secret.ImportSecring()
	// Tell the secret keyring some basic info about this remailer
	err = secret.SetName(cfg.Remailer.Name)
	if err != nil {
		return
	}
	err = secret.SetAddress(cfg.Remailer.Address)
	if err != nil {
		return
	}
	secret.SetExit(cfg.Remailer.Exit)
	secret.SetVersion(version)
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
	id, err := idlog.NewInstance(cfg.Files.IDlog)
	if err != nil {
		panic(err)
	}
	defer id.Close()
	// Is a new ECC Keypair required?
	generate := false
	/*
	Ascertain the Keyid we're advertising.  This only needs to be done once at
	server startup as the act of new key publication sets the keyid to the newly
	generated key.
	*/
	err = secret.SetMyKeyid()
	if err != nil {
		Info.Println("No valid Public key, will generate a new pair")
		generate = true
	} else {
		Info.Printf("Advertising existing keyid: %s", secret.GetMyKeyidStr())
		// Write a tmp pub.key using current config
		tmpKey := cfg.Files.Pubkey + ".tmp"
		err = secret.WriteMyKey(tmpKey)
		if err != nil {
			Warn.Println(err)
		} else {
			// Overwrite the published key with the refreshed version
			err = os.Rename(tmpKey, cfg.Files.Pubkey)
			if err != nil {
				Warn.Println(err)
			}
		}
	}

	// Maintain time of last pool process
	poolProcessTime := time.Now()
	poolProcessDelay := time.Duration(cfg.Pool.Loop) * time.Second

	// Make a note of what day it is
	today := time.Now()
	oneday := time.Duration(dayLength) * time.Second

	// Actually start the server loop
	if cfg.Remailer.Daemon || flag_daemon {
		Info.Printf("Starting YAMN server: %s", cfg.Remailer.Name)
	} else {
		Info.Printf("Performing routine remailer functions for: %s",
			cfg.Remailer.Name)
	}
	for {
		if flag_daemon && time.Now().Before(poolProcessTime) {
			mailRead(public, secret, id)
			// Don't do anything beyond this point until poolProcessTime
			time.Sleep(60 * time.Second)
			continue
		} else if ! flag_daemon {
			/*
			When not running as a Daemon, always read mail first. Otherwise, the
			loop will terminate before mail is ever read.
			*/
			mailRead(public, secret, id)
		}
		// Test if it's time to do daily events
		if generate || time.Since(today) > oneday {
			Info.Println("Performing daily events")
			// Try to validate the advertised key on Secring
			if ! generate {
				valid, err := secret.Validate()
				if err != nil {
					Warn.Printf("%s: Failed to validate key in Secring", cfg.Files.Secring)
					generate = true
				} else if valid {
					Info.Printf("Advertising current keyid: %s", secret.GetMyKeyidStr())
				} else {
					Info.Printf("%s has expired, will generate a new key pair", secret.GetMyKeyidStr())
					generate = true
				}
			}
			// Create a new key pair
			if generate {
				Info.Println("Generating and advertising a new key pair")
				pub, sec := eccGenerate()
				err = secret.Publish(pub, sec, keyValidityDays)
				if err != nil {
					Error.Printf("Aborting! Key generation failure: %s", err)
					return
				}
				Info.Printf("Advertising new Keyid: %s", secret.GetMyKeyidStr())
				generate = false
			}

			//TODO Make this a flag function
			secret.Purge("test.txt")

			// Complain about excessively small loop values.
			if cfg.Pool.Loop < 60 {
				Warn.Println(
					fmt.Sprintf("Loop time of %d is excessively low. ", cfg.Pool.Loop),
					"Will loop every 60 seconds. A higher setting is recommended.")
			}
			// Complain about high pool rates.
			if cfg.Pool.Rate > 90 {
				Warn.Println(
					fmt.Sprintf("Your pool rate of %d is excessively", cfg.Pool.Rate),
					"high. Unless testing, a lower setting is recommended.")
			}
			// Reset today so we don't do these tasks for the next 24 hours.
			today = time.Now()
		}
		// Test if in-memory pubring is current
		if public.KeyRefresh() {
			// Time to re-read the pubring file
			Info.Printf("Reimporting keyring: %s", cfg.Files.Pubring)
			public.ImportPubring()
		}
		filenames, err = poolRead()
		for _, file := range filenames {
			//TODO Read some files here!
			if err != nil {
				Info.Printf("Discarding message: %s", err)
			}
			Info.Printf("Do something with: %s", file)
			err = mailFile(path.Join(cfg.Files.Pooldir, file))
			if err != nil {
				Warn.Printf("Pool mailing failed: %s", err)
			} else {
				poolDelete(file)
			}
		}
		poolProcessTime = time.Now().Add(poolProcessDelay)
		// Break out of the loop if we're not running as a daemon
		if ! flag_daemon && ! cfg.Remailer.Daemon {
			break
		}
	} // End of server loop
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

// randhop is a simplified client function that does single-hop encodings
func randhop(message []byte, public *keymgr.Pubring) (err error) {
	msglen := len(message)
	if msglen == 0 {
		Info.Println("Zero-byte message during randhop, ignoring it.")
		return
	}
	// Make a single hop chain with a random node
	in_chain := []string{"*"}
	final := new(slotFinal)
	final.deliveryMethod = 0
	final.messageID = randbytes(16)
	final.chunkNum = uint8(1)
	final.numChunks = uint8(1)
	var chain []string
	chain, err = chain_build(in_chain, public)
	if err != nil {
		panic(err)
	}
	if len(chain) != 1 {
		err = fmt.Errorf("Randhop chain must be single hop.  Got=%d", len(chain))
		panic(err)
	}
	Trace.Printf("Performing a random hop to an Exit Remailer: %s.", chain[0])
	packetid := randbytes(16)
	encmsg, sendto := mixmsg(message, packetid, chain, *final, public)
	err = cutmarks(encmsg, sendto)
	if err != nil {
		Warn.Println(err)
	}
	return
}

// dummy is a simplified client function that sends dummy messages
func dummy(public *keymgr.Pubring) (err error) {
	message := []byte("I hope Len approves")
	// Make a single hop chain with a random node
	in_chain := []string{"*","*"}
	final := new(slotFinal)
	final.deliveryMethod = 255
	final.messageID = randbytes(16)
	final.chunkNum = uint8(1)
	final.numChunks = uint8(1)
	var chain []string
	chain, err = chain_build(in_chain, public)
	if err != nil {
		panic(err)
	}
	Trace.Printf("Sending dummy through: %s.", strings.Join(chain, ","))
	packetid := randbytes(16)
	encmsg, sendto := mixmsg(message, packetid, chain, *final, public)
	err = cutmarks(encmsg, sendto)
	if err != nil {
		Warn.Println(err)
	}
	return
}
