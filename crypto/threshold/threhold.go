// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package threshold

import (
	gocrypto "crypto"
	godsa "crypto/dsa"
	goecdsa "crypto/ecdsa"
	gorsa "crypto/rsa"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/threshold/dsa"
	"github.com/yahoo/bftkv/crypto/threshold/ecdsa"
	"github.com/yahoo/bftkv/crypto/threshold/rsa"
	"github.com/yahoo/bftkv/node"
)

type ThresholdInstance struct {
	rsa   crypto.Threshold
	dsa   crypto.Threshold
	ecdsa crypto.Threshold
}

func New(crypt *crypto.Crypto) crypto.Threshold {
	return &ThresholdInstance{
		rsa:   rsa.New(crypt),
		dsa:   dsa.New(crypt),
		ecdsa: ecdsa.New(crypt),
	}
}

func (instance *ThresholdInstance) Distribute(key interface{}, nodes []node.Node, k int) (shares [][]byte, algo crypto.ThresholdAlgo, err error) {
	var th crypto.Threshold
	switch key.(type) {
	case *gorsa.PrivateKey:
		th = instance.rsa
	case *godsa.PrivateKey:
		th = instance.dsa
	case *goecdsa.PrivateKey:
		th = instance.ecdsa
	default:
		return nil, algo, crypto.ErrUnsupported
	}
	return th.Distribute(key, nodes, k)
}

func (instance *ThresholdInstance) Sign(aux []byte, m []byte, peerId, selfId uint64) (sig []byte, err error) {
	algo, params := ParseParams(aux)
	var th crypto.Threshold
	switch algo {
	case crypto.TH_RSA:
		th = instance.rsa
	case crypto.TH_DSA:
		th = instance.dsa
	case crypto.TH_ECDSA:
		th = instance.ecdsa
	default:
		return nil, crypto.ErrUnsupported
	}
	return th.Sign(params, m, peerId, selfId)
}

func (instance *ThresholdInstance) NewProcess(tbs []byte, algo crypto.ThresholdAlgo, hash gocrypto.Hash) (crypto.ThresholdProcess, error) {
	var th crypto.Threshold
	switch algo {
	case crypto.TH_RSA:
		th = instance.rsa
	case crypto.TH_DSA:
		th = instance.dsa
	case crypto.TH_ECDSA:
		th = instance.ecdsa
	default:
		return nil, crypto.ErrUnsupported
	}
	return th.NewProcess(tbs, algo, hash)
}

func ParseParams(aux []byte) (algo crypto.ThresholdAlgo, data []byte) {
	return crypto.ThresholdAlgo(aux[0]), aux[1:]
}

func SerializeParams(algo crypto.ThresholdAlgo, data []byte) []byte {
	aux := make([]byte, len(data)+1)
	aux[0] = byte(algo)
	copy(aux[1:], data)
	return aux
}
