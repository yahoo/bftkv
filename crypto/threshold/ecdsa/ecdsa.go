// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package ecdsa

import (
	gocrypto "crypto"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
)

type ecdsaContext struct {
	crypt *crypto.Crypto
	n, k int
	nodes []node.Node
}

func New(crypt *crypto.Crypto) crypto.Threshold {
	return &ecdsaContext{
		crypt: crypt,
	}
}

func (ctx *ecdsaContext) Distribute(key interface{}, nodes []node.Node, k int) ([][]byte, crypto.ThresholdAlgo, error) {
	return nil, crypto.TH_UNKNOWN, crypto.ErrUnsupported
}

func (ctx *ecdsaContext) Sign(sec []byte, req []byte, peerId, selfId uint64) ([]byte, error) {
	return nil, crypto.ErrUnsupported
}

func (ctx *ecdsaContext) NewProcess(tbs []byte, algo crypto.ThresholdAlgo, hash gocrypto.Hash) (crypto.ThresholdProcess, error) {
	return nil, crypto.ErrUnsupported
}
