// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package storage

import (
	"errors"
)

var (
	ErrNotFound = errors.New("storage: not found")
)

type Storage interface {
	Read(variable []byte, t uint64) (value []byte, err error)
	Write(variable []byte, t uint64, value []byte) error
}
