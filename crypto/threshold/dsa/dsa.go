// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package dsa

import (
	"bytes"
	godsa "crypto/dsa"
	"math/big"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/packet"
)

type dsaGroupOperations struct {
	params *godsa.Parameters
}

type dsaGroup struct {
}

func New(crypt *crypto.Crypto) crypto.Threshold {
	return NewWithGroup(crypt, &dsaGroup{}, crypto.TH_DSA)
}

func (g *dsaGroupOperations) CalculatePartialR(ai *big.Int) []byte {
	// ri = g^ai mod p
	ri := new(big.Int).Exp(g.params.G, ai, g.params.P)
	return ri.Bytes()
}

func (g *dsaGroupOperations) CalculateR(rs []*PartialR) *big.Int {
	// r = \Pi (ri)^li mod p mod q
	var xs []int
	for _, ri := range rs {
		xs = append(xs, ri.X)
	}
	r := big.NewInt(1) // r = g^a mod p
	v := big.NewInt(0) // v = a*k mod q
	t := new(big.Int)
	for _, ri := range rs {
		l := sss.Lagrange(ri.X, xs, g.params.Q)
		t.Exp(new(big.Int).SetBytes(ri.Ri), l, g.params.P)
		r.Mod(r.Mul(r, t), g.params.P)
		t.Mod(t.Mul(ri.Vi, l), g.params.Q)
		v.Mod(v.Add(v, t), g.params.Q)
	}
	v.ModInverse(v, g.params.Q) // v = v^-1 mod q
	r.Exp(r, v, g.params.P)     // r = r^v mod q
	return r.Mod(r, g.params.Q)
}

func (g *dsaGroupOperations) SubGroupOrder() *big.Int {
	return g.params.Q
}

func (g *dsaGroupOperations) Serialize(bp *bytes.Buffer) error {
	if err := packet.WriteBigInt(bp, g.params.P); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.Q); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.G); err != nil {
		return err
	}
	return nil
}
func (g *dsaGroupOperations) OS2I(os []byte) *big.Int {
	orderSize := (g.params.Q.BitLen() + 7) / 8
	return new(big.Int).SetBytes(os[:orderSize])
}

func (g *dsaGroup) ParseKey(key interface{}) (GroupOperations, *big.Int) {
	priv := key.(*godsa.PrivateKey)
	return &dsaGroupOperations{&priv.Parameters}, priv.X
}

func (g *dsaGroup) ParseParams(r *bytes.Reader) (group GroupOperations, err error) {
	var params godsa.Parameters
	params.P, err = packet.ReadBigInt(r)
	if err != nil {
		return nil, err
	}
	params.Q, err = packet.ReadBigInt(r)
	if err != nil {
		return nil, err
	}
	params.G, err = packet.ReadBigInt(r)
	if err != nil {
		return nil, err
	}
	return &dsaGroupOperations{&params}, nil
}
