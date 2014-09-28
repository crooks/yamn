// vim: tabstop=2 shiftwidth=2

package keymgr

import (
	"bufio"
	//"io/ioutil"
	"os"
	"time"
	"fmt"
	"encoding/hex"
	//"crypto/rand"
	//"github.com/codahale/blake2"
	//"code.google.com/p/go.crypto/nacl/box"
)

type secret struct {
	keyid []byte // keyid
	sk []byte // Secret Key
	from time.Time // Valid from
	until time.Time // Valid Until
}

type Secring struct {
	sec map[string]secret
}

func NewSecring() *Secring {
	return &Secring{sec: make(map[string]secret)}
}

func (s Secring) Get(keyid string) (sec secret, err error) {
	var exists bool
	sec, exists = s.sec[keyid]
	if ! exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	return
}

func (s Secring) GetSK(keyid string) (sk []byte, err error) {
	sec, exists := s.sec[keyid]
	if ! exists {
		err = fmt.Errorf("%s: Keyid not found in secret keyring", keyid)
		return
	}
	sk = sec.sk
	return
}

func (s Secring) Purge(filename string) (err error) {
	f, err := os.Create(filename)
  if err != nil {
		err = fmt.Errorf("%s: Cannot create file")
		return
	}
	defer f.Close()
	days28 := time.Hour * 24 * 28
	plus28Days := time.Now().Add(days28)
	for _, k := range s.sec {
		if k.until.Before(plus28Days) {
			continue
		}
		keydata := "-----Begin Mixmaster Secret Key-----\n"
		keydata += fmt.Sprintf("Created: %s\n", k.from.Format(date_format))
		keydata += fmt.Sprintf("Expires: %s\n", k.until.Format(date_format))
		keydata += hex.EncodeToString(k.keyid)  + "\n"
		keydata += hex.EncodeToString(k.sk) + "\n"
		keydata += "-----End Mixmaster Secret Key-----\n\n"
		_, err = f.WriteString(keydata)
		if err != nil {
			return
		}
	}
	return
}



// ImportSecring reads a YAML secring.mix file
func (s Secring) ImportSecring(filename string) (err error) {
	var f *os.File
	f, err = os.Open(filename)
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
