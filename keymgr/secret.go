// vim: tabstop=2 shiftwidth=2

package keymgr

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	//"github.com/codahale/blake2"
)

type secret struct {
	keyid []byte    // keyid
	sk    []byte    // Secret Key
	from  time.Time // Valid from
	until time.Time // Valid Until
}

type Secring struct {
	secringFile string // Filename of secret keyring
	pubkeyFile  string // Public keyfile (key.txt)
	sec         map[string]secret
	name        string        // Local remailer's name
	address     string        // Local remailer's email address
	myKeyid     []byte        // Keyid this remailer is advertising
	validity    time.Duration // Period of key validity
	grace       time.Duration // Period of grace after key expiry
	exit        bool          // Is this an Exit type remailer?
	version     string        // Yamn version string
}

// NewSecring is a constructor for the Secret Keyring
func NewSecring(secfile, pubkey string) *Secring {
	return &Secring{
		secringFile: secfile,
		pubkeyFile:  pubkey,
		sec:         make(map[string]secret),
	}
}

// ListKeyids returns a string slice of all in-memory secret keyids
func (s *Secring) ListKeyids() (keyids []string) {
	keyids = make([]string, 0, len(s.sec))
	for k := range s.sec {
		keyids = append(keyids, k)
	}
	return
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
	} else if index == 0 || l-index < 3 {
		err = fmt.Errorf("%s: Invalid remailer address.", addy)
		panic(err)
	}
	s.address = strings.ToLower(addy)
}

// SetExit defines if this is a Middle or Exit remailer
func (s *Secring) SetExit(exit bool) {
	s.exit = exit
}

// SetValidity defines the time duration over which a key is deemed valid
func (s *Secring) SetValidity(valid, grace int) {
	s.validity = time.Duration(24*valid) * time.Hour
	s.grace = time.Duration(24*grace) * time.Hour
}

// SetVersion sets the version string used on keys
func (s *Secring) SetVersion(v string) {
	s.version = "4:" + v
}

// Count returns the number of secret keys in memory
func (s *Secring) Count() int {
	return len(s.sec)
}

// Insert puts a new secret key into memory and returns its keyid
func (s *Secring) Insert(pub, sec []byte) (keyidstr string) {
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
	digest := sha256.New()
	digest.Write(pub)
	key.keyid = digest.Sum(nil)[:16]
	keyidstr = hex.EncodeToString(key.keyid)
	// Validity dates
	key.from = time.Now()
	key.until = time.Now().Add(s.validity)
	// The secret key itself
	key.sk = sec
	s.sec[keyidstr] = *key
	return
}

func (s *Secring) WritePublic(pub []byte, keyidstr string) {
	var err error
	if len(pub) != 32 {
		err = fmt.Errorf("Invalid pubkey length. Wanted=32, Got=%d", len(pub))
		panic(err)
	}

	var capstring string
	// M = Middle, E = Exit
	if s.exit {
		capstring += "E"
	} else {
		capstring += "M"
	}

	key, exists := s.sec[keyidstr]
	if !exists {
		err = fmt.Errorf("%s: Keyid does not exist", keyidstr)
		panic(err)
	}

	header := s.name + " "
	header += s.address + " "
	header += keyidstr + " "
	header += s.version + " "
	header += capstring + " "
	header += key.from.UTC().Format(date_format) + " "
	header += key.until.UTC().Format(date_format)

	// Open the file for writing
	f, err := os.Create(s.pubkeyFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
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
}

// WriteSecret adds the selected secret key to the secret keyring file
func (s *Secring) WriteSecret(keyidstr string) {
	var err error
	key, exists := s.sec[keyidstr]
	if !exists {
		err = fmt.Errorf("%s: Keyid does not exist", keyidstr)
		panic(err)
	}
	f, err := os.OpenFile(
		s.secringFile,
		os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	keydata := "\n-----Begin Mixmaster Secret Key-----\n"
	keydata += fmt.Sprintf("Created: %s\n", key.from.UTC().Format(date_format))
	keydata += fmt.Sprintf("Expires: %s\n", key.until.UTC().Format(date_format))
	keydata += keyidstr + "\n"
	keydata += hex.EncodeToString(key.sk) + "\n"
	keydata += "-----End Mixmaster Secret Key-----\n"
	_, err = f.WriteString(keydata)
	if err != nil {
		panic(err)
	}
}

// WriteMyKey writes the local public key to filename with current
// configurtaion settings.
func (s *Secring) WriteMyKey(filename string) (keyidstr string) {
	infile, err := os.Open(s.pubkeyFile)
	if err != nil {
		panic(err)
	}
	defer infile.Close()
	// Create a tmp file rather than overwriting directly
	outfile, err := os.Create(filename)
	if err != nil {
		panic(err)
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
			// Extract the keyid so we can return it
			keyidstr = elements[2]
			if len(keyidstr) != 32 {
				err = fmt.Errorf(
					"Invalid public keyid length.  Expected=32, Got=%d.",
					len(keyidstr))
				panic(err)
			}
			header := s.name + " "
			header += s.address + " "
			header += keyidstr + " "
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
		panic(err)
	}
	return
}

// Return the Secret struct that corresponds to the requested Keyid
func (s *Secring) Get(keyid string) (sec secret, err error) {
	var exists bool
	sec, exists = s.sec[keyid]
	if !exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	return
}

// Return the Secret Key that corresponds to the requested Keyid
func (s *Secring) GetSK(keyid string) (sk []byte, err error) {
	sec, exists := s.sec[keyid]
	if !exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	sk = sec.sk
	return
}

// Purge deletes expired keys and writes current ones to a backup secring
func (s *Secring) Purge() (active, expired, purged int) {
	/*
		active - Keys that have not yet expired
		expired - Keys that have expired but not yet exceeded their grace period
		purged - Keys that are beyond their grace period
	*/
	// Rename the secring file to a tmp name, just in case this screws up.
	err := os.Rename(s.secringFile, s.secringFile+".tmp")
	if err != nil {
		panic(err)
	}

	// Create a new secring file
	f, err := os.Create(s.secringFile)
	if err != nil {
		panic(err)
		return
	}
	defer f.Close()

	// Iterate key and value of Secring in memory
	for k, m := range s.sec {
		purgeDate := m.until.Add(s.grace)
		if time.Now().After(purgeDate) {
			delete(s.sec, k)
			purged++
		} else {
			keydata := "-----Begin Mixmaster Secret Key-----\n"
			keydata += fmt.Sprintf("Created: %s\n", m.from.Format(date_format))
			keydata += fmt.Sprintf("Expires: %s\n", m.until.Format(date_format))
			keydata += hex.EncodeToString(m.keyid) + "\n"
			keydata += hex.EncodeToString(m.sk) + "\n"
			keydata += "-----End Mixmaster Secret Key-----\n\n"
			_, err = f.WriteString(keydata)
			if err != nil {
				panic(err)
			}
			if time.Now().After(m.until) {
				expired++
			} else {
				active++
			}
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
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var line string        //Each line within secring.mix
	var skdata []byte      // Decoded secret key
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
		} // End of switch
	} // End of file lines loop
	return
}
