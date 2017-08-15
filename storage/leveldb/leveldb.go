// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package leveldb

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/yahoo/bftkv/storage"
)

type ldb struct {
	db *leveldb.DB
}

func New(path string) storage.Storage {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		log.Panic(err)
	}
	return &ldb{db: db}
}

func (db *ldb) Read(variable []byte, t uint64) (value []byte, err error) {
	if t == 0 {
		iter := db.db.NewIterator(util.BytesPrefix(variable), nil)
		if iter.Last() {
			value = iter.Value()
		} else {
			err = storage.ErrNotFound
		}
		iter.Release()
		return
	} else {
		var buf bytes.Buffer
		buf.Write(variable)
		binary.Write(&buf, binary.BigEndian, t)
		return db.db.Get(buf.Bytes(), nil)
	}
}

func (db *ldb) Write(variable []byte, t uint64, value []byte) error {
	var buf bytes.Buffer
	buf.Write(variable)
	binary.Write(&buf, binary.BigEndian, t)
	return db.db.Put(buf.Bytes(), value, &opt.WriteOptions{Sync: true})
}
