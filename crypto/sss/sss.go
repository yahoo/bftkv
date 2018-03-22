// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package sss

import (
	"math/big"
	"crypto/rand"
)

type Coordinate struct {
	X int
	Y *big.Int
}

type SSSProcess struct {
	n, k int
	m *big.Int
	res []*Coordinate
	S []byte
}

func Distribute(secret *big.Int, n, k int, m *big.Int) ([]*Coordinate, error) {
	// generate a (k-1)-degree polynomial (on m)
	poly := make([]*big.Int, k)
	poly[0] = secret
	for i := 1; i < k; i++ {
		coeff, err := rand.Int(rand.Reader, m)
		if err != nil {
			return nil, err
		}
		poly[i] = coeff
	}
	t := new(big.Int)
	res := make([]*Coordinate, n)
	for i := 0; i < n; i++ {
		x0 := big.NewInt(int64(i + 1))
		x := new(big.Int).Set(x0)
		f := new(big.Int).Set(poly[0])
		for j := 1; j < k; j++ {
			f.Mod(f.Add(f, t.Mul(poly[j], x)), m)
			x.Mul(x, x0)
		}
		res[i] = &Coordinate{i + 1, f}
	}
	return res, nil
}

func NewProcess(secrets []*Coordinate, n, k int, m *big.Int) (*SSSProcess, error) {
	p := &SSSProcess{
		n: n,
		k: k,
		m: m,
		res: nil,
		S: nil,
	}
	for _, secret := range secrets {
		S, err := p.ProcessResponse(secret)
		if err != nil {
			return nil, err
		}
		if S != nil {
			break
		}
	}
	return p, nil
}

func (p *SSSProcess) ProcessResponse(coordinate *Coordinate) ([]byte, error) {
	if p.S != nil {
		return p.S, nil
	}
	p.res = append(p.res, coordinate)
	if len(p.res) == p.k {
		S := p.calculateSecret()
		p.S = S.Bytes()
	}
	return p.S, nil
}

func (p *SSSProcess) calculateSecret() *big.Int {
	var xs []int
	for _, r := range p.res {
		xs = append(xs, r.X)
	}
	S := big.NewInt(0)
	for _, r := range p.res {
		l := Lagrange(r.X, xs, p.m)
		S.Mod(S.Add(S, l.Mul(l, r.Y)), p.m)
	}
	return S
}

func Lagrange(x int, results []int, m *big.Int) *big.Int {
	a := big.NewInt(1)
	b := big.NewInt(1)
	xj := big.NewInt(int64(x))
	for _, res := range results {
		if res == x {
			continue
		}
		xm := big.NewInt(int64(res))
		a.Mul(a, xm)
		b.Mul(b, xm.Sub(xm, xj))
	}
	return a.Mod(a.Mul(a, b.ModInverse(b, m)), m)
}
