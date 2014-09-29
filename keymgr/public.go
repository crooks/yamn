// vim: tabstop=2 shiftwidth=2

package keymgr

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"time"
	"fmt"
	"encoding/hex"
	//"crypto/rand"
	//"github.com/codahale/blake2"
	//"code.google.com/p/go.crypto/nacl/box"
)

const (
	date_format string = "2006-01-02"
)

type remailer struct {
	name string // Remailer Shortname
	Address string // Remailer Address
	Keyid []byte // 16 Byte Mixmaster KeyID
	version string // Mixmaster version
	caps string // Remailer capstring
	PK []byte // Curve25519 Public Key
	from time.Time // Valid-from date
	until time.Time // Valid until date
	latent int // Latency (minutes)
	uptime int // Uptime (10ths of a %)
}

type Pubring struct {
	pub map[string]remailer
	xref map[string]string // A cross-reference of shortnames to addresses
	advertised string // The keyid we're currently advertising
}

func NewPubring() *Pubring {
	return &Pubring{
		pub: make(map[string]remailer),
		xref: make(map[string]string),
	}
}

// Candidates provides a list of remailer addresses that match the specified criteria
func (p Pubring) Candidates(minlat, maxlat int, minrel float32, exit bool) (c []string) {
	for addy := range(p.pub) {
		stats := p.pub[addy]
		if exit {
			if strings.Contains(stats.caps, "M") {
		    // Exits are required and this is a Middle
	  	  continue
			}
		}
		if stats.latent < minlat || stats.latent > maxlat {
			continue
		}
		if stats.uptime < int(minrel * 10) {
			continue
		}
		c = append(c, addy)
	}
	return
}

// Put inserts a new remailer struct into the Keyring
func (p Pubring) Put(r remailer) {
	p.pub[r.Address] = r
	p.xref[r.name] = r.Address
}

// Get returns a remailer's public info when requested by name or address
func (p Pubring) Get(ref string) (r remailer, err error) {
	var exists bool
	if strings.Contains(ref, "@") {
		r, exists = p.pub[ref]
		if ! exists {
			err = fmt.Errorf("%s: Remailer address not found in public keyring", ref)
			return
		}
	} else {
		var addy string
		addy, exists = p.xref[ref]
		if ! exists {
			err = fmt.Errorf("%s: Remailer name not found in public keyring", ref)
			return
		}
		r = p.pub[addy]
	}
	return
}

// Advertising returns keyid defined in key.txt
func (p Pubring) Advertising(filename string) (keyid string, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	found := false
	var elements []string
	for scanner.Scan() {
		line := scanner.Text()
		elements = strings.Split(line, " ")
		if len(elements) == 7 {
			found = true
			break
		}
	}
	if ! found {
		err = fmt.Errorf("%s: No key header found", filename)
		return
	}
	keyid = elements[2]
	if len(keyid) != 32 {
		err = fmt.Errorf("%s: Corrupted keyid. Not 32 chars.", filename)
		return
	}
	_, err = hex.DecodeString(keyid)
	if err != nil {
		err = fmt.Errorf("%s: Corrupted keyid. Not valid hexadecimal", filename)
		return
	}
	return
}

func (p Pubring) ImportStats(filename string)  (err error) {
	f, err := os.Open(filename)
	if err != nil {
		return
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
				_, exists = p.xref[rem_name]
				if exists {
					rem_addy = p.xref[rem_name]
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
					tmp := p.pub[rem_addy]
					tmp.latent = (lathrs * 60) + latmin
					tmp.uptime = int(uptmp * 10)
					p.pub[rem_addy] = tmp
				} else {
					fmt.Fprintf(os.Stderr, "%s: Stats for unknown remailer\n", rem_name)
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

// ImportPubring reads a YAMN Pubring.mix file
func (p Pubring) ImportPubring(filename string) (err error) {
	var f *os.File
	f, err = os.Open(filename)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	var elements []string
	var num_elements int
	var line string //Each line within Pubring.mix
	var rem *remailer
	var pkdata []byte // Decoded Public key
	now := time.Now() // Current time for key validity testing
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
			// 7 elements indicates a remailer header line in Pubring.mix
			if num_elements == 7 {
				//TODO Decide if validity dates should be authenticated here
				from, err := time.Parse(date_format, elements[5])
				if err != nil {
					fmt.Fprintln(os.Stderr, "Malformed valid-from date")
					key_phase = 0
					continue
				}
				if now.Before(from) {
					fmt.Fprintln(os.Stderr, elements[0] + ": Key not yet valid")
					key_phase = 0
					continue
				}
				until, err := time.Parse(date_format, elements[6])
				if err != nil {
					fmt.Fprintln(os.Stderr, "Malformed valid-to date")
					key_phase = 0
					continue
				}
				if now.After(until) {
					fmt.Fprintln(os.Stderr, elements[0] + ": Key expired")
					key_phase = 0
					continue
				}
				rem = new(remailer)
				rem.name = elements[0]
				rem.Keyid, err = hex.DecodeString(elements[2])
				if err != nil {
					// keyid is not valid hex
					fmt.Fprintln(os.Stderr, "Keyid in header is not hex")
					key_phase = 0
					continue
				}
				rem.version = elements[3]
				rem.caps = elements[4]
				rem.Address = elements[1]
				key_phase = 1
			}
		case 1:
			// Expecting Begin cutmark
			if line == "-----Begin Mixmaster Public Key-----" {
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
			if ! bytes.Equal(keyid, rem.Keyid) {
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
			rem.PK = pkdata
			key_phase = 4
		case 4:
			// Expecting end cutmark
			if line == "-----End Mixmaster Public Key-----" {
				p.Put(*rem)
				key_phase = 0
			}
		} // End of phases
	}// End of file scan loop
	return
}
