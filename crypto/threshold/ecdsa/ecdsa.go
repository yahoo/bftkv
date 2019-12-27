// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package ecdsa

import (
	"bytes"
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"math/big"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/crypto/threshold/dsa"
	"github.com/yahoo/bftkv/packet"
)

type ecdsaGroup struct {
}

type ecdsaGroupOperations struct {
	curve  elliptic.Curve
	params *elliptic.CurveParams
}

func New(crypt *crypto.Crypto) crypto.Threshold {
	return dsa.NewWithGroup(crypt, &ecdsaGroup{}, crypto.TH_ECDSA)
}

func (g *ecdsaGroupOperations) CalculatePartialR(ai *big.Int) []byte {
	x, y := g.curve.ScalarBaseMult(ai.Bytes())
	return elliptic.Marshal(g.curve, x, y)
}

func (g *ecdsaGroupOperations) CalculateR(rs []*dsa.PartialR) *big.Int {
	var xs []int
	for _, ri := range rs {
		xs = append(xs, ri.X)
	}
	var x, y *big.Int
	v := big.NewInt(0) // v = a*k mod q
	t := new(big.Int)
	for _, ri := range rs {
		l := sss.Lagrange(ri.X, xs, g.params.N)
		x1, y1 := elliptic.Unmarshal(g.curve, ri.Ri)
		x1, y1 = g.curve.ScalarMult(x1, y1, l.Bytes())
		if x == nil {
			x, y = x1, y1
		} else {
			x, y = g.curve.Add(x, y, x1, y1) // P += li*ai*P
		}
		t.Mod(t.Mul(ri.Vi, l), g.params.N)
		v.Mod(v.Add(v, t), g.params.N)
	}
	v.ModInverse(v, g.params.N)
	x, y = g.curve.ScalarMult(x, y, v.Bytes())
	return x.Mod(x, g.params.N)
}

func (g *ecdsaGroupOperations) SubGroupOrder() *big.Int {
	return g.params.N
}

func (g *ecdsaGroupOperations) Serialize(bp *bytes.Buffer) error {
	if err := packet.WriteBigInt(bp, g.params.P); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.N); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.B); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.Gx); err != nil {
		return err
	}
	if err := packet.WriteBigInt(bp, g.params.Gy); err != nil {
		return err
	}
	if err := binary.Write(bp, binary.BigEndian, uint32(g.params.BitSize)); err != nil {
		return err
	}
	// ignore string
	return nil
}

func (g *ecdsaGroupOperations) OS2I(os []byte) *big.Int {
	// copied from https://golang.org/src/crypto/ecdsa/ecdsa.go
	orderSize := (g.params.N.BitLen() + 7) / 8
	os = os[:orderSize]
	ret := new(big.Int).SetBytes(os)
	excess := len(os)*8 - g.params.N.BitLen()
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func (g *ecdsaGroup) ParseKey(key interface{}) (dsa.GroupOperations, *big.Int) {
	priv := key.(*goecdsa.PrivateKey)
	return &ecdsaGroupOperations{priv.Curve, priv.Curve.Params()}, priv.D
}

func (g *ecdsaGroup) ParseParams(r *bytes.Reader) (group dsa.GroupOperations, err error) {
	var params elliptic.CurveParams
	if params.P, err = packet.ReadBigInt(r); err == nil {
		if params.N, err = packet.ReadBigInt(r); err == nil {
			if params.B, err = packet.ReadBigInt(r); err == nil {
				if params.Gx, err = packet.ReadBigInt(r); err == nil {
					if params.Gy, err = packet.ReadBigInt(r); err == nil {
						var sz uint32
						if err = binary.Read(r, binary.BigEndian, &sz); err == nil {
							params.BitSize = int(sz)
							group = &ecdsaGroupOperations{&params, &params}
						}
					}
				}
			}
		}
	}
	return
}
