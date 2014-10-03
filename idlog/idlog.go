package idlog

import (
	"time"
	"github.com/syndtr/goleveldb/leveldb"
)

type IDLog struct {
	db *leveldb.DB // A level DB instance
}

func NewInstance(filename string) (i IDLog, err error) {
	i.db, err = leveldb.OpenFile(filename, nil)
	if err != nil {
		return
	}
	return
}

func (i IDLog) Close() {
	i.db.Close()
}

// Unique tests the existance of a key and inserts if it's not there.
// The data inserted is a Gob'd expiry date
func (i IDLog) Unique(key []byte, expire int) (unique bool) {
	var err error
	_, err = i.db.Get(key, nil)
	if err != nil {
		if err.Error() == "leveldb: not found" {
			// This condition indicates we don't know this key
			unique = true
			expireDate := time.Now().Add(time.Duration(24 * expire) * time.Hour)
			insertTimestamp, err := expireDate.GobEncode()
			err = i.db.Put(key, insertTimestamp, nil)
			if err != nil {
				panic(err)
			}
		} else {
			// It's not an error we anticipated
			panic(err)
		}
	} else {
		/*
		The DB already contains the key we're trying to insert. This
		implies that we've already processed this packet and don't
		want to process it again.
		*/
		unique = false
	}
	return
}

func (i IDLog) Expire() (count, deleted int) {
	var err error
	now := time.Now()
	iter := i.db.NewIterator(nil, nil)
	var timestamp time.Time
	for iter.Next() {
		key := iter.Key()
		err = timestamp.GobDecode(iter.Value())
		if err != nil {
			panic(err)
		}
		if now.After(timestamp) {
			i.db.Delete(key, nil)
			deleted++
		} else {
			count++
		}
	}
	iter.Release()
	err = iter.Error()
	if err != nil {
		panic(err)
	}
	return
}

