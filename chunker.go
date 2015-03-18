package main

import (
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
)

type Chunk struct {
	db         *leveldb.DB   // A level DB instance
	expireDays time.Duration // How long to retain keys
	deleteDays time.Duration // Age of partial files before deletion
}

func OpenChunk(filename string) *Chunk {
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
	chunk.expireDays = time.Duration(days*24) * time.Hour
	chunk.deleteDays = time.Duration(days*24*2) * time.Hour
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
			t.Format("20060102"),
			strings.Join(items, ","),
		)),
		nil,
	)
}

// IsPopulated returns true if all elements of items are populated
func IsPopulated(items []string) bool {
	for _, n := range items {
		if n == "" {
			return false
		}
	}
	return true
}

// Housekeep deletes files over a given age
func (chunk *Chunk) Housekeep() (ret, del int) {
	files, err := ioutil.ReadDir(cfg.Files.Pooldir)
	if err != nil {
		Warn.Printf("Chunk housekeeping failed: %s", err)
		return
	}
	expire := time.Now().Add(-chunk.deleteDays)
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "p") {
			// Don't do anything unless the file begins with "p"
			continue
		}
		if file.ModTime().Before(expire) {
			os.Remove(path.Join(cfg.Files.Pooldir, file.Name()))
			del++
		} else {
			ret++
		}
	}
	return
}

// Assemble takes all the file chunks, assembles them in order and stores the
// result back into the pool.
func (chunk *Chunk) Assemble(filename string, items []string) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return
	}
	defer f.Close()
	var content []byte
	for _, c := range items {
		infile := path.Join(cfg.Files.Pooldir, c)
		content, err = ioutil.ReadFile(infile)
		if err != nil {
			Warn.Printf("Chunk assembler says: %s", err)
			continue
		}
		f.Write(content)
		err = os.Remove(infile)
		if err != nil {
			Warn.Printf("Assembler chunk delete failed: %s", err)
			continue
		}
	}
	return
}

// Delete removes the specified Message ID from the DB
func (chunk *Chunk) Delete(messageid []byte) {
	err := chunk.db.Delete(messageid, nil)
	if err != nil {
		Warn.Printf("Could not delete MsgID: %s. %s", messageid, err)
	}
}

// DeleteItems removes all the filename defined in items
func (chunk *Chunk) DeleteItems(items []string) (deleted, failed int) {
	for _, file := range items {
		fqfn := path.Join(cfg.Files.Pooldir, file)
		err := os.Remove(fqfn)
		if err != nil {
			failed++
		} else {
			deleted++
		}
	}
	return
}

// Expire iterates the DB and deletes entries (and files) that exceed the
// defined age.
func (chunk *Chunk) Expire() (retained, deleted int) {
	now := time.Now()
	iter := chunk.db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		items := strings.Split(string(iter.Value()), ",")
		stamp := items[0]
		// Now we have the timestamp, strip it from the slice
		copy(items, items[1:])
		expire, err := time.Parse("20060102", stamp)
		if err != nil {
			Warn.Printf("Could not parse timestamp: %s", err)
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
