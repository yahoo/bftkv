// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package threshold

import (
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/threshold/rsa"
	"github.com/yahoo/bftkv/crypto/threshold/dsa"
	"github.com/yahoo/bftkv/crypto/threshold/ecdsa"
)

type Algo byte
const (
	UNKNOWN Algo = iota
	RSA
	DSA
	ECDSA
)

func Sign(aux []byte, m []byte) (sig []byte, err error) {
	algo, params := ParseParams(aux)
	var f func([]byte, []byte) ([]byte, error)
	switch algo {
	case RSA:
		f = rsa.Sign
	case DSA:
		f = dsa.Sign
	case ECDSA:
		f = ecdsa.Sign
	default:
		return nil, crypto.ErrUnsupported
	}
	return f(params, m)
}

func ParseParams(aux []byte) (algo Algo, data []byte) {
	return Algo(aux[0]), aux[1:]
}

func SerializeParams(algo Algo, data []byte) []byte {
	aux := make([]byte, len(data) + 1)
	aux[0] = byte(algo)
	copy(aux[1:], data)
	return aux
}
