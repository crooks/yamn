// vim: tabstop=2 shiftwidth=2

package main

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
	"fmt"
	"encoding/hex"
	"crypto/rand"
	"github.com/codahale/blake2"
	"code.google.com/p/go.crypto/nacl/box"
)

type keyinfo struct {
	name string // Remailer Shortname
	//address is the next field in pubring but we'll use this as the key
	keyid []byte // 16 Byte Mixmaster KeyID
	version string // Mixmaster version
	caps string // Remailer capstring
	pk []byte // Curve25519 Public Key
	latent int // Latency (minutes)
	uptime int // Uptime (10ths of a %)
}

func import_mlist2(filename string, pub map[string]keyinfo, xref map[string]string) (count int) {
	var err error
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(f)
	var elements []string
	var line string //Each line in mlist2.txt
	var rem_name string //Remailer name in stats
	var rem_addy string //Remailer address from xref
	var lat []string //Latency hours:minutes
	var lathrs int //Latent Hours
	var latmin int //Latent Minutes
	var exists bool //Test for presence of remailer in xref
	stat_phase := 0
	count = 0
	/* Stat phases are:
	0 Expecting long string of dashes
	*/
	for scanner.Scan() {
		line = scanner.Text()
		switch stat_phase {
		case 0:
			// Expecting dashes
			if strings.HasPrefix(line, "----------") {
				stat_phase = 1
			}
		case 1:
			// Expecting stats
			line = strings.Split(line, "%")[0]
			elements = strings.Fields(line)
			if len(elements) == 5 {
				rem_name = elements[0]
				_, exists = xref[rem_name]
				if exists {
					rem_addy = xref[rem_name]
					// Element 2 is Latency in the format (hrs:mins)
					lat = strings.Split(elements[2], ":")
					if lat[0] == "" {
						lathrs = 0
					} else {
						lathrs, err = strconv.Atoi(lat[0])
						if err != nil {
							fmt.Fprintf(os.Stderr, "%s: Invalid latent hours\n", rem_name)
							continue
						}
						if lathrs < 0 || lathrs > 99 {
							fmt.Fprintf(os.Stderr, "%s: Latent hours out of range\n", rem_name)
							continue
						}
					}
					latmin, err = strconv.Atoi(lat[1])
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s: Invalid latent minutes\n", rem_name)
						continue
					}
					if latmin < 0 || latmin > 59 {
						fmt.Fprintf(os.Stderr, "%s: Latent minutes out of range\n", rem_name)
						continue
					}
					// Element 4 is Uptime in format (xxx.xx)
					uptmp, err := strconv.ParseFloat(elements[4], 32)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s: Invalid uptime\n", rem_name)
						continue
					}
					if uptmp < 0 || uptmp > 100 {
						fmt.Fprintf(os.Stderr, "%s: Uptime out of range\n", rem_name)
						continue
					}
					tmp := pub[rem_addy]
					tmp.latent = (lathrs * 60) + latmin
					tmp.uptime = int(uptmp * 10)
					pub[rem_addy] = tmp
					count += 1 // Increment count of processed remailers
				} else {
					fmt.Fprintf(os.Stderr, "%s: Unknown remailer\n", rem_name)
				}
			} else {
				stat_phase = 2
			}
		case 2:
			// Reserved for future mlist2.txt processing
			break
		}
	}
	return
}

// import_secring reads a YAML secring.mix file
func import_secring() (sec map[string][]byte) {
	var err error
	f, err := os.Open(cfg.Files.Secring)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(f)
	sec = make(map[string][]byte)
	var line string //Each line within secring.mix
	var skdata []byte // Decoded secret key
	var valid time.Time
	var expire time.Time
	var keyid string
	now := time.Now().UTC()
	key_phase := 0
	/* Key phases are:
	0 Expecting Begin cutmark
	1 Expecting Valid-from date
	2 Expecting Valid-to date
	3 Expecting Keyid line
	4	Expecting secret key
	5 Got End cutmark
	*/

	for scanner.Scan() {
		line = scanner.Text()
		switch key_phase {
		case 0:
			// Expecting begin cutmark
			if line == "-----Begin YAMN Secret Key-----" {
				key_phase = 1
			}
		case 1:
			// Valid-from date
			if line[:9] == "Created: " {
				valid, err = time.Parse(date_format, line[9:])
			} else {
				fmt.Fprintln(os.Stderr, "Expected Created line")
				key_phase = 0
				continue
			}
			if err != nil {
				// Invalid valid-from date
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
				continue
			}
			if valid.After(now) {
				// Key is not yet valid
				key_phase = 0
				continue
			}
			key_phase = 2
		case 2:
			// Expire date
			if line[:9] == "Expires: " {
				expire, err = time.Parse(date_format, line[9:])
			} else {
				fmt.Fprintln(os.Stderr, "Expected Expires line")
				key_phase = 0
				continue
			}
			if err != nil {
				// Invalid expiry date
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
				continue
			}
			if expire.Before(now) {
				// Key has expired
				key_phase = 0
				continue
			}
			key_phase = 3
		case 3:
			if len(line) != 32 {
				// Invalid keyid length
				key_phase = 0
				continue
			}
			_, err = hex.DecodeString(line)
			if err != nil {
				// Non hex keyid
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
				continue
			}
			keyid = line
			key_phase = 4
		case 4:
			// Expecting Private key
			skdata, err = hex.DecodeString(line)
			if err != nil {
				// Non hex Private key
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
			}
			if len(skdata) != 32 {
				errmsg := fmt.Sprintf("Incorrect key length found in %s", cfg.Files.Secring)
				fmt.Fprintln(os.Stderr, errmsg)
				key_phase = 0
				continue
			}
			key_phase = 5
		case 5:
			// Expecting end cutmark
			if line == "-----End YAMN Secret Key-----" {
				sec[keyid] = skdata
				keyid = ""
				skdata = make([]byte, 32)
				key_phase = 0
			}
		}
	}
	return
}

// import_pubring reads a YAML pubring.mix file
// pub is a map of keyinfo keyed by remailer address
// xref is a cross-reference of short names to addresses
func import_pubring() (pub map[string]keyinfo,
																		  xref map[string]string) {
	var err error
	// pub = map of pubring structs
	pub = make(map[string]keyinfo)
	// xref = map of shortnames to addresses
	xref = make(map[string]string)
	f, err := os.Open(cfg.Files.Pubring)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(f)
	var elements []string
	var num_elements int
	var line string //Each line within pubring.mix
	var addy string //Remailer's address (The map key)
	var rem *keyinfo //A specific remailer's pubring struct
	var pkdata []byte // Decoded Public key
	key_phase := 0
	/* Key phases are:
	0	Expecting header line
	1 Expecting Begin cutmark
	2 Expecting Keyid line
	3	Expecting public key
	4 Got End cutmark
	*/

	for scanner.Scan() {
		line = scanner.Text()
		switch key_phase {
		case 0:
			// Expecting key header line
			elements = strings.Split(line, " ")
			num_elements = len(elements)
			// 7 elements indicates a remailer header line in pubring.mix
			if num_elements == 7 {
				//TODO Decide if validity dates should be authenticated here
				rem = new(keyinfo)
				rem.name = elements[0]
				rem.keyid, err = hex.DecodeString(elements[2])
				if err != nil {
					// keyid is not valid hex
					fmt.Fprintln(os.Stderr, "Keyid in header is not hex")
					key_phase = 0
					continue
				}
				rem.version = elements[3]
				rem.caps = elements[4]
				addy = elements[1]
				key_phase = 1
			}
		case 1:
			// Expecting Begin cutmark
			if line == "-----Begin YAMN Public Key-----" {
				key_phase = 2
			}
		case 2:
			// Expecting Keyid line
			keyid, err := hex.DecodeString(line)
			if err != nil {
				// keyid is not valid hex
				fmt.Fprintln(os.Stderr, "Keyid in pubkey is not hex")
				key_phase = 0
				continue
			}
			if ! bytes.Equal(keyid, rem.keyid) {
				// Corrupt keyblock - header keyid doesn't match keyid in block
				fmt.Fprintln(os.Stderr, "Keyid in header differs from keyid in pubkey")
				key_phase = 0
				continue
			}
			key_phase = 3
		case 3:
			// Expecting Public key
			pkdata, err = hex.DecodeString(line)
			if err != nil {
				// Public key is not valid hex
				fmt.Fprintln(os.Stderr, "Unable to decode Public key")
				key_phase = 0
				continue
			}
			if len(pkdata) != 32 {
				fmt.Fprintln(os.Stderr, "Public key is not 32 bits")
				key_phase = 0
				continue
			}
			rem.pk = pkdata
			key_phase = 4
		case 4:
			// Expecting end cutmark
			if line == "-----End YAMN Public Key-----" {
				pub[addy] = *rem
				xref[rem.name] = addy
			}
		}
	}
	return
}

// getmykey validates and returns the keyid defined in key.txt
func getmykey(sec map[string][]byte) (key string) {
	dat, err:= ioutil.ReadFile(cfg.Files.Pubkey)
	if err != nil {
		panic(err)
	}
	elements := strings.Split(string(dat), "\n")
	if len(elements) != 7 {
		fmt.Fprintln(os.Stderr, "Public keyfile is corrupted")
		os.Exit(1)
	}
	key = elements[3]
	if len(key) != 32 {
		errmsg := fmt.Sprintf("Incorrect key length found in %s", cfg.Files.Pubkey)
		fmt.Fprintln(os.Stderr, errmsg)
		os.Exit(1)
	}
	// Test this key is on the local Secret Keyring
	_, onsecring := sec[key]
	if ! onsecring {
		fmt.Fprintln(os.Stderr, "My key is not on my Secret Keyring")
		os.Exit(1)
	}
	return
}

// make_keyid returns a 128 bit Blake2 hash of the Public Key
func make_keyid(public []byte) []byte {
	h := blake2.New(&blake2.Config{Size: 16})
	h.Write(public[:])
	return h.Sum(nil)
}

// keygen generates a Curve25519 Public/Private key pair
/*
All the box functions work on 32 Byte arrays, not slices.  Internally they're
converted to slices for convenience.
*/
func keygen() (public, private []byte) {
	puba, priva, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	copy(public, puba[:])
	copy(private, priva[:])
	return
}

// write_key writes public and private keys to their respective files
func write_key(public, private []byte) {
	/*
	Each time this function is called, the passed public key is written to
	key.txt.  This implies that the most recently created key is always
	advertised, without consideration of validity dates.  The private key
	is appended to the secring.mix file.
	*/

	// Keyid
	keyid := hex.EncodeToString(make_keyid(public))
	// Validity dates
	ctime := time.Now()
	etime := ctime.Add(time.Duration(key_validity_days * 24) * time.Hour)

	// Public Key first
	f, err := os.Create(cfg.Files.Pubkey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	w := bufio.NewWriter(f)
	var capstring string
	// M = Middle, E = Exit
	if ! cfg.Remailer.Exit {
		capstring += "M"
	} else {
		capstring += "E"
	}
	header := cfg.Remailer.Name + " "
	header += cfg.Remailer.Address + " "
	header += keyid + " "
	header += "4:" + version + " "
	header += capstring + " "
	header += ctime.UTC().Format(date_format) + " "
	header += etime.UTC().Format(date_format)

	fmt.Fprintln(w, header)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "-----Begin YAMN Public Key-----")
	fmt.Fprintln(w, keyid)
	fmt.Fprintln(w, hex.EncodeToString(public))
	fmt.Fprintln(w, "-----End YAMN Public Key-----")
	err = w.Flush()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Secret Keyring next
	f, err = os.OpenFile(cfg.Files.Secring, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	keydata := "\n-----Begin YAMN Secret Key-----\n"
	keydata += fmt.Sprintf("Created: %s\n", ctime.UTC().Format(date_format))
	keydata += fmt.Sprintf("Expires: %s\n", etime.UTC().Format(date_format))
	keydata += keyid  + "\n"
	keydata += hex.EncodeToString(private) + "\n"
	keydata += "-----End YAMN Secret Key-----\n"
	_, err = f.WriteString(keydata)
	if err != nil {
		panic(err)
	}
}
