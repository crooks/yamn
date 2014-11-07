// vim: tabstop=2 shiftwidth=2

package keymgr

import (
	"bufio"
	"os"
	"time"
	"fmt"
	"strings"
	"encoding/hex"
	"crypto/sha256"
	//"github.com/codahale/blake2"
)

type secret struct {
	keyid []byte // keyid
	sk []byte // Secret Key
	from time.Time // Valid from
	until time.Time // Valid Until
}

type Secring struct {
	secringFile string // Filename of secret keyring
	pubkeyFile string // Public keyfile (key.txt)
	sec map[string]secret
	name string // Local remailer's name
	address string // Local remailer's email address
	myKeyid []byte // Keyid this remailer is advertising
	exit bool // Is this an Exit type remailer?
	version string // Yamn version string
}

func NewSecring(secfile, pubkey string) *Secring {
	return &Secring{
		secringFile: secfile,
		pubkeyFile: pubkey,
		sec: make(map[string]secret),
	}
}

// SetName validates and sets the remailer name
func (s *Secring) SetName(name string) {
	var err error
	l := len(name)
	if l < 2 || l > 12 {
		err = fmt.Errorf("Remailer name must be between 2 and 12 chars, not %d.", l)
		panic(err)
	}
	s.name = strings.ToLower(name)
}

// SetAddress validates and sets the remailer address
func (s *Secring) SetAddress(addy string) {
	var err error
	l := len(addy)
	if l < 3 || l > 80 {
		err = fmt.Errorf(
			"Remailer address must be between 2 and 80 chars, not %d.", l)
		panic(err)
	}
	index := strings.Index(addy, "@")
	if index == -1 {
		err = fmt.Errorf("%s: Remailer address doesn't contain an @.", addy)
		panic(err)
	} else if index == 0 || l - index < 3 {
		err = fmt.Errorf("%s: Invalid remailer address.", addy)
		panic(err)
	}
	s.address = strings.ToLower(addy)
}

// SetExit defines if this is a Middle or Exit remailer
func (s *Secring) SetExit(exit bool) {
	s.exit = exit
}

// SetVersion sets the version string used on keys
func (s *Secring) SetVersion(v string) {
	s.version = "4:" + v
}

// Count returns the number of secret keys in memory
func (s *Secring) Count() int {
	return len(s.sec)
}

// Publish takes a key pair, does some basic validation and writes
// public/private keys to their respective files.
func (s *Secring) Publish(pub, sec []byte, valid int) {
	/*
	Each time this function is called, the passed public key is written to
	key.txt.  This implies that the most recently created key is always
	advertised, without consideration of validity dates.  The private key
	is appended to the secring.mix file.
	*/
	var err error
	if len(pub) != 32 {
		err = fmt.Errorf("Invalid pubkey length. Wanted=32, Got=%d", len(pub))
		panic(err)
	}
	if len(sec) != 32 {
		err = fmt.Errorf("Invalid seckey length. Wanted=32, Got=%d", len(pub))
		panic(err)
	}
	key := new(secret)
	key.sk = sec
	// Create Keyid
	//digest := blake2.New(&blake2.Config{Size: 16})
	digest := sha256.New()
	digest.Write(pub)
	key.keyid = digest.Sum(nil)[:16]
	keyidstr := hex.EncodeToString(key.keyid)
	// Validity dates
	key.from = time.Now()
	key.until = time.Now().Add(time.Duration(24 * valid) * time.Hour)

	// Public Key first
	f, err := os.Create(s.pubkeyFile)
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	var capstring string
	// M = Middle, E = Exit
	if s.exit {
		capstring += "E"
	} else {
		capstring += "M"
	}
	header := s.name + " "
	header += s.address + " "
	header += keyidstr + " "
	header += s.version + " "
	header += capstring + " "
	header += key.from.UTC().Format(date_format) + " "
	header += key.until.UTC().Format(date_format)

	fmt.Fprintln(w, header)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "-----Begin Mix Key-----")
	fmt.Fprintln(w, keyidstr)
	fmt.Fprintln(w, hex.EncodeToString(pub))
	fmt.Fprintln(w, "-----End Mix Key-----")
	err = w.Flush()
	if err != nil {
		panic(err)
	}

	// Secret Keyring next
	f, err = os.OpenFile(s.secringFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	keydata := "\n-----Begin Mixmaster Secret Key-----\n"
	keydata += fmt.Sprintf("Created: %s\n", key.from.UTC().Format(date_format))
	keydata += fmt.Sprintf("Expires: %s\n", key.until.UTC().Format(date_format))
	keydata += keyidstr  + "\n"
	keydata += hex.EncodeToString(key.sk) + "\n"
	keydata += "-----End Mixmaster Secret Key-----\n"
	_, err = f.WriteString(keydata)
	if err != nil {
		panic(err)
	}
	// Add the new key to the in memory secret keyring
	s.sec[keyidstr] = *key
	// Advertise the new keyid
	s.myKeyid = key.keyid
}

// WriteMyKey writes the local public key to filename with current
// configurtaion settings.
func (s *Secring) WriteMyKey(filename string) (err error) {
	infile, err := os.Open(s.pubkeyFile)
	if err != nil {
		return
	}
	defer infile.Close()
	// Create a tmp file rather than overwriting directly
	outfile, err := os.Create(filename)
	if err != nil {
		return
	}
	defer outfile.Close()
	in := bufio.NewScanner(infile)
	out := bufio.NewWriter(outfile)
	var line string
  for in.Scan() {
		line = in.Text()
		elements := strings.Fields(line)
		if len(elements) == 7 {
			var capstring string
			// M = Middle, E = Exit
			if s.exit {
				capstring += "E"
			} else {
				capstring += "M"
			}
			header := s.name + " "
			header += s.address + " "
			header += hex.EncodeToString(s.myKeyid) + " "
			header += s.version + " "
			header += capstring + " "
			header += elements[5] + " "
			header += elements[6]
			fmt.Fprintln(out, header)
		} else {
			fmt.Fprintln(out, line)
		}
	}
	err = out.Flush()
	if err != nil {
		return
	}
	return
}

// Return the Secret struct that corresponds to the requested Keyid
func (s *Secring) Get(keyid string) (sec secret, err error) {
	var exists bool
	sec, exists = s.sec[keyid]
	if ! exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	return
}

// Return the Secret Key that corresponds to the requested Keyid
func (s *Secring) GetSK(keyid string) (sk []byte, err error) {
	sec, exists := s.sec[keyid]
	if ! exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	sk = sec.sk
	return
}

// GetMyKeyidStr returns the string version of the advertised keyid
func (s *Secring) GetMyKeyidStr() string {
	return hex.EncodeToString(s.myKeyid)
}

// SetMyKeyid imports keyid currently being advertised
func (s *Secring) SetMyKeyid() (err error) {
	f, err := os.Open(s.pubkeyFile)
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
		err = fmt.Errorf("%s: No key header found", s.pubkeyFile)
		return
	}
	keyidstr := elements[2]
	if len(keyidstr) != 32 {
		err = fmt.Errorf("%s: Corrupted keyid. Not 32 chars.", s.pubkeyFile)
		return
	}
	s.myKeyid, err = hex.DecodeString(keyidstr)
	if err != nil {
		err = fmt.Errorf("%s: Corrupted keyid. Not valid hexadecimal", s.pubkeyFile)
		return
	}
	return
}

// Validate tests if the advertised keyid has minimum of 7 days validity
func (s *Secring) Validate() (valid bool, err error) {
	keyid := hex.EncodeToString(s.myKeyid)
	sec, exists := s.sec[keyid]
	if ! exists {
		err = fmt.Errorf(
			"%s: Validation failed: Keyid not found in secret keyring",
			keyid)
		return
	}
	days7 := time.Now().Add(time.Duration(24 * 7) * time.Hour)
	if sec.until.Before(days7) {
		valid = false
	} else {
		valid = true
	}
	return
}

// Purge writes the in-memory Secring to a file, excluding keys that expired
// more than 28 days ago.
func (s *Secring) Purge(filename string) (err error) {
	f, err := os.Create(filename)
  if err != nil {
		err = fmt.Errorf("%s: Cannot create file")
		return
	}
	defer f.Close()
	days28 := time.Hour * 24 * 28
	plus28Days := time.Now().Add(days28)
	// Iterate key and value of Secring
	for k, m := range s.sec {
		if m.until.Before(plus28Days) {
			delete(s.sec, k)
			continue
		}
		keydata := "-----Begin Mixmaster Secret Key-----\n"
		keydata += fmt.Sprintf("Created: %s\n", m.from.Format(date_format))
		keydata += fmt.Sprintf("Expires: %s\n", m.until.Format(date_format))
		keydata += hex.EncodeToString(m.keyid)  + "\n"
		keydata += hex.EncodeToString(m.sk) + "\n"
		keydata += "-----End Mixmaster Secret Key-----\n\n"
		_, err = f.WriteString(keydata)
		if err != nil {
			return
		}
	}
	return
}

// ImportSecring reads a YAML secring.mix file into memory
func (s *Secring) ImportSecring() (err error) {
	var f *os.File
	f, err = os.Open(s.secringFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
	var line string //Each line within secring.mix
	var skdata []byte // Decoded secret key
	var keyidMapKey string // String representation of keyid to key map with
	var valid time.Time
	var expire time.Time
	var sec *secret
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
			if line == "-----Begin Mixmaster Secret Key-----" {
				sec = new(secret)
				key_phase = 1
			}
		case 1:
			// Valid-from date
			if line[:9] == "Created: " {
				valid, err = time.Parse(date_format, line[9:])
				if err != nil {
					fmt.Fprintln(os.Stderr, "Malformed Created date")
					key_phase = 0
					continue
				}
			} else {
				fmt.Fprintln(os.Stderr, "Expected Created line")
				key_phase = 0
				continue
			}
			if valid.After(now) {
				// Key is not yet valid
				fmt.Fprintln(os.Stderr, "Key is not valid yet")
				key_phase = 0
				continue
			}
			sec.from = valid
			key_phase = 2
		case 2:
			// Expire date
			if line[:9] == "Expires: " {
				expire, err = time.Parse(date_format, line[9:])
				if err != nil {
					fmt.Fprintln(os.Stderr, "Malformed Expires date")
					key_phase = 0
					continue
				}
			} else {
				fmt.Fprintln(os.Stderr, "Expected Expires line")
				key_phase = 0
				continue
			}
			if expire.Before(now) {
				// Key has expired (but we don't really care)
				fmt.Fprintln(os.Stderr, "Expired key on secret")
			}
			sec.until = expire
			key_phase = 3
		case 3:
			if len(line) != 32 {
				// Invalid keyid length
				key_phase = 0
				continue
			}
			var keyid []byte
			keyid, err = hex.DecodeString(line)
			if err != nil {
				// Non hex keyid
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
				continue
			}
			sec.keyid = keyid
			// Retain a textual representation to key the secring map with
			keyidMapKey = line
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
				fmt.Fprintln(os.Stderr, "Incorrect key length")
				key_phase = 0
				continue
			}
			sec.sk = skdata
			key_phase = 5
		case 5:
			// Expecting end cutmark
			if line == "-----End Mixmaster Secret Key-----" {
				s.sec[keyidMapKey] = *sec
				key_phase = 0
			}
		}
	}
	return
}
