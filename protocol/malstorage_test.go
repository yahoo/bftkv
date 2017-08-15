// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"encoding/hex"
	"github.com/yahoo/bftkv/storage"
	storage_plain "github.com/yahoo/bftkv/storage/plain"
	"io/ioutil"
	_ "math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

type MalStorage interface {
	storage.Storage
	MalRead(variable []byte, t uint64) (value []byte, err error)
	MalWrite(variable []byte, t uint64, value []byte) error
}

type malPlain struct {
	path string
	plain storage.Storage
}

func MalStorageNew(path string) MalStorage {
	return &malPlain{
		path: path,
		plain: storage_plain.New(path),
	}
}

func (p *malPlain) getMalMaxT(fname string) (uint64, error) {
	stats, err := ioutil.ReadDir(p.path + "/mal")
	if err != nil {
		return 0, err
	}
	fname += "."
	maxn := uint64(0)
	for _, st := range stats {
		if strings.HasPrefix(st.Name(), fname) {
			n, err := strconv.ParseUint(st.Name()[len(fname):], 10, 64)
			if err == nil && n > maxn {
				maxn = n
			}
		}
	}
	return maxn, nil
}

func (p *malPlain) constructMalPath(variable []byte, t uint64) (string, error) {
	fname := hex.EncodeToString(variable)
	if t == 0 {
		// read the latest one
		maxt, err := p.getMalMaxT(fname)
		if err != nil {
			return "", err
		}
		t = maxt
	}
	fname += "." + strconv.FormatUint(t, 10)
	return p.path + "/mal/" + fname, nil
}

func (p *malPlain) MalRead(variable []byte, t uint64) (value []byte, err error) {
	path, err := p.constructMalPath(variable, t)
	if err != nil {
		return nil, err
	}
	responses, err := ioutil.ReadDir(path)
	if err != nil {
		return value, storage.ErrNotFound
	}
	//rand.Seed(time.Now().UTC().UnixNano())
	//index := rand.Intn(len(responses)) //cannot randomize index for now
	index := 0
	value, err = ioutil.ReadFile(path + "/" + responses[index].Name())
	if err != nil && os.IsNotExist(err) {
		err = storage.ErrNotFound
		value = nil
	}
	return value, err
}

func (p *malPlain) MalWrite(variable []byte, t uint64, value []byte) error {
	path, err := p.constructMalPath(variable, t)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0777); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path+"/"+strconv.FormatInt(unixMilli(time.Now()), 10), value, 0644)
}

func unixMilli(t time.Time) int64 {
	return t.Round(time.Millisecond).UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))
}

func (p *malPlain) Read(variable []byte, t uint64) (value []byte, err error) {
	return p.plain.Read(variable, t)
}

func (p *malPlain) Write(variable []byte, t uint64, value []byte) error {
	return p.plain.Write(variable, t, value)
}
