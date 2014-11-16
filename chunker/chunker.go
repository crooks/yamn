package chunker

import (
	"fmt"
	"strings"
	"github.com/syndtr/goleveldb/leveldb"
	"time"
	"path"
	"os"
	"io/ioutil"
)

const (
	dateFmt string = "20060102"
)

type Chunk struct {
	db *leveldb.DB // A level DB instance
	expireDays time.Duration // How long to retain keys
	poolDir string // Directory where chunks are stored
}

func New(filename string) *Chunk {
	levelDB, err := leveldb.OpenFile(filename, nil)
	if err != nil {
		panic(err)
	}
	return &Chunk{db: levelDB}
}

// Close closes the levelDB
func (chunk *Chunk) Close() {
	chunk.db.Close()
}

// SetExpire defines how long keys should be retained in the DB
func (chunk *Chunk) SetExpire(days int) {
	chunk.expireDays = time.Duration(days * 24) * time.Hour
}

//SetDir defines which directory contains the chunk files
func (chunk *Chunk) SetDir(dir string) {
	chunk.poolDir = dir
}

// Get returns the content associated with messageID.  If messageID is
// unknown, an empty slice of len numChunks is returned.
func (chunk *Chunk) Get(messageID []byte, numChunks int) (items []string) {
	var err error
	var content []byte
	content, err = chunk.db.Get(messageID, nil)
	if err != nil {
		if err.Error() == "leveldb: not found" {
			items = make([]string, numChunks)
		} else {
			panic(err)
		}
	} else {
		// Ignore the first item in the DB, it's the date field and
		// only used internally.
		items = strings.Split(string(content), ",")[1:]
	}
	return
}

// Insert writes an entry to the DB
func (chunk *Chunk) Insert(messageid []byte, items []string) {
	if chunk.expireDays == 0 {
		panic("Expiry duration not defined")
	}
	t := time.Now().Add(chunk.expireDays)
	chunk.db.Put(
		messageid,
		[]byte(fmt.Sprintf(
			"%s,%s",
			t.Format(dateFmt),
			strings.Join(items, ","),
		)),
		nil,
	)
}

// IsPopulated returns true if all elements of items are populated
func IsPopulated(items []string) bool {
	for _, n := range(items) {
		if n == "" {
			return false
		}
	}
	return true
}

// Assemble takes all the file chunks, assembles them in order and stores the
// result back into the pool.
func (chunk *Chunk) Assemble(filename string, items []string) (err error) {
	//outfile := path.Join(chunk.poolDir, filename)
	f, err := os.Create(filename)
	if err != nil {
		return
	}
	defer f.Close()
	var content []byte
	for _, c := range(items) {
		infile := path.Join(chunk.poolDir, c)
		content, err = ioutil.ReadFile(infile)
		if err != nil {
			return
		}
		f.Write(content)
		err = os.Remove(infile)
		if err != nil {
			return
		}
	}
	return
}

// Delete removes the specified Message ID from the DB
func (chunk *Chunk) Delete(messageid []byte) {
	err := chunk.db.Delete(messageid, nil)
	if err != nil {
		panic(err)
	}
}

// DeleteItems removes all the filename defined in items
func (chunk *Chunk) DeleteItems(items []string) (deleted, failed int) {
	for _, file := range items {
		fqfn := path.Join(chunk.poolDir, file)
		err := os.Remove(fqfn)
		if err != nil {
			failed++
		} else {
			deleted++
		}
	}
	return
}

func (chunk *Chunk) Expire() (retained, deleted int) {
	now := time.Now()
	iter := chunk.db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		items := strings.Split(string(iter.Value()), ",")
		stamp := items[0]
		// Now we have the timestamp, strip it from the slice
		copy(items, items[1:])
		expire, err := time.Parse(dateFmt, stamp)
		if err != nil {
			// If the timestamp is invalid, delete the record
			chunk.DeleteItems(items)
			chunk.Delete(key)
		}
		if expire.Before(now) {
			chunk.DeleteItems(items)
			chunk.Delete(key)
			deleted++
		} else {
			retained++
		}
	}
	return
}
