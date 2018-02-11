// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package dsa

import (
	gocrypto "crypto"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
)

func Distribute(key interface{}, n, k int) ([][]byte, error) {
	return nil, crypto.ErrUnsupported
}

func Sign(sec []byte, req []byte) ([]byte, error) {
	return nil, crypto.ErrUnsupported
}

func NewProcess(nodes []node.Node, k int, tbs []byte, hash gocrypto.Hash) (crypto.ThresholdProcess, error) {
	return nil, crypto.ErrUnsupported
}
