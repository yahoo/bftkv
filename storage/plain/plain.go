// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package plain

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/yahoo/bftkv/storage"
)

type plain struct {
	path  string
	mutex sync.Mutex
}

func New(path string) storage.Storage {
	return &plain{
		path: path,
	}
}

func (p *plain) getMaxT(fname string) (uint64, error) {
	p.mutex.Lock()
	stats, err := ioutil.ReadDir(p.path)
	p.mutex.Unlock()
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

func (p *plain) constructPath(variable []byte, t uint64) (string, error) {
	fname := hex.EncodeToString(variable)
	if t == 0 {
		// read the latest one
		maxt, err := p.getMaxT(fname)
		if err != nil {
			return "", err
		}
		t = maxt
	}
	fname += "." + strconv.FormatUint(t, 10)
	return p.path + "/" + fname, nil
}

func (p *plain) Read(variable []byte, t uint64) (value []byte, err error) {
	path, err := p.constructPath(variable, t)
	if err == nil {
		p.mutex.Lock()
		value, err = ioutil.ReadFile(path)
		p.mutex.Unlock()
	}
	if err != nil && os.IsNotExist(err) {
		err = storage.ErrNotFound
		value = nil
	}
	return value, err
}

func (p *plain) Write(variable []byte, t uint64, value []byte) error {
	if _, err := os.Stat(p.path); err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(p.path, 0777); err != nil {
			return err
		}
	}
	path, err := p.constructPath(variable, t)
	if err != nil {
		return err
	}
	p.mutex.Lock()
	err = ioutil.WriteFile(path, value, 0644)
	p.mutex.Unlock()
	return err
}
