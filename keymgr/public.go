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
)

const (
	date_format string = "2006-01-02"
	generatedFormat string = "Mon 02 Jan 2006 15:04:05 GMT"
)

type Remailer struct {
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
	pubringFile string // Pubring filename
	statsFile string // mlist type file
	pub map[string]Remailer
	xref map[string]string // A cross-reference of shortnames to addresses
	Stats bool // Have current reliability stats been imported?
	advertised string // The keyid a local server is currently advertising
	keysImported time.Time // Timestamp on most recently read pubring.mix file
	statsImported time.Time // Timestamp on most recently read mlist2.txt file
	statsGenerated time.Time // Generated timestamp on mlist2.txt file
}

func NewPubring(pubfile, statfile string) *Pubring {
	return &Pubring{
		pubringFile: pubfile,
		statsFile: statfile,
		pub: make(map[string]Remailer),
		xref: make(map[string]string),
		Stats: false,
	}
}

// StatsStale returns true if stats are over h hours old
func (p *Pubring) StatsStale(h int) bool {
	if p.Stats && int((time.Since(p.statsGenerated).Hours())) > h {
		return true
	}
	return false
}

// KeyRefresh returns True if the Pubring file has been modified
func (p *Pubring) KeyRefresh() bool {
	stat, err := os.Stat(p.pubringFile)
	if err != nil {
		panic(err)
	}
	if stat.ModTime().After(p.keysImported) {
		return true
	}
	return false
}

// StatRefresh returns True if the mlist2.txt file has been modified
func (p *Pubring) StatRefresh() (refresh bool, err error) {
	stat, err := os.Stat(p.statsFile)
	if err != nil {
		// Cannot read the stats file
		err = fmt.Errorf("%s: File not found", p.statsFile)
		return
	}
	if stat.ModTime().After(p.statsImported) {
		refresh = true
	}
	return
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

// Count returns the number of known Public keys
func (p Pubring) Count() int {
	return len(p.pub)
}

// Produces a list of public key headers
func (p Pubring) KeyList() (addresses []string) {
	for addy := range(p.pub) {
		key := p.pub[addy]
		header := key.name + " "
		header += key.Address + " "
		header += hex.EncodeToString(key.Keyid) + " "
		header += key.version + " "
		header += key.caps + " "
		header += key.from.UTC().Format(date_format) + " "
		header += key.until.UTC().Format(date_format)
		addresses = append(addresses, header)
	}
	return
}

// Put inserts a new remailer struct into the Keyring
func (p Pubring) Put(r Remailer) {
	p.pub[r.Address] = r
	p.xref[r.name] = r.Address
}

// Get returns a remailer's public info when requested by name or address
func (p Pubring) Get(ref string) (r Remailer, err error) {
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

func (p *Pubring) ImportStats()  (err error) {
	f, err := os.Open(p.statsFile)
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
	0 Want Generated timestamp
	1 Expecting long string of dashes
	2 Expecting stats lines
	*/
	for scanner.Scan() {
		line = scanner.Text()
		switch stat_phase {
		case 0:
			// Generated: Tue 07 Oct 2014 10:50:01 GMT
			if strings.HasPrefix(line, "Generated: ") {
				p.statsGenerated, err = time.Parse(generatedFormat, line[11:])
				if err != nil {
					err = fmt.Errorf("Failed to parse Generated date: %s", err)
					return
				}
				stat_phase++
			}
		case 1:
			// Expecting dashes
			if strings.HasPrefix(line, "----------") {
				stat_phase++
			}
		case 2:
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
				stat_phase++
			}
		case 3:
			// Reserved for future mlist2.txt processing
			break
		}
	}
	// Update last-imported timestamp for stats
	stat, err := os.Stat(p.statsFile)
	if err != nil {
		panic(err)
	}
	p.statsImported = stat.ModTime()
	p.Stats = true
	return
}

func Headers(filename string) (headers []string, err error) {
	var f *os.File
	f, err = os.Open(filename)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(strings.Split(line, " ")) == 7 {
			headers = append(headers, line)
		}
	}
	return
}

// ImportPubring reads a YAMN Pubring.mix file
func (p *Pubring) ImportPubring() (err error) {
	var f *os.File
	f, err = os.Open(p.pubringFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	var elements []string
	var num_elements int
	var line string //Each line within Pubring.mix
	var rem *Remailer
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
					fmt.Fprintf(
						os.Stderr,
						"Key expired: Name=%s, Key=%s, Date=%s\n",
						elements[0],
						elements[2],
						elements[6],
					)
					// Rejecting expired keys is likely to break Echolot so just Warn
					//key_phase = 0
					//continue
				}
				rem = new(Remailer)
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
			if line == "-----Begin Mix Key-----" {
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
			if line == "-----End Mix Key-----" {
				p.Put(*rem)
				key_phase = 0
			}
		} // End of phases
	}// End of file scan loop

	// Set key imported timestamp
	stat, err := os.Stat(p.pubringFile)
	if err != nil {
		panic(err)
	}
	p.keysImported = stat.ModTime()
	return
}
