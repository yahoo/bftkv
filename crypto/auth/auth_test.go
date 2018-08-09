// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package auth

import (
	"testing"
	"bytes"
	"crypto/rand"
	"math/big"
	"fmt"
)

func testAuth(t *testing.T, password []byte, proof []byte) {
	k := 7
	n := 10

	ss, err := GeneratePartialAuthenticationParams(password, n, k)
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(password, n, k)

	X, err := c.GenerateX()
	if err != nil {
		t.Fatal(err)
	}

	var Xis map[uint64][]byte
	for i := 0; i < n; i++ {
		Yi, err := MakeYi(ss[i], X)
		if err != nil {
			t.Fatal(err)
		}

		Xis, err = c.ProcessYi(Yi, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if Xis != nil {
			break
		}
	}
	if Xis == nil {
		t.Error("not enough responses")
		return
	}

	for id, Xi := range Xis {
		Bi, err := MakeBi(ss[id], Xi, proof)
		if err != nil {
			t.Fatal(err)
		}
		Pi, err := c.ProcessBi(Bi, id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(Pi, proof) {
			t.Error("decryption failed")
		}
	}
}

func TestAuth(t *testing.T) {
	var password [8]byte
	var plainData [16]byte
	for ntests := 10; ntests > 0; ntests-- {
		rand.Read(password[:])
		rand.Read(plainData[:])
		testAuth(t, password[:], plainData[:])
		if t.Failed() {
			break
		}
	}
}

type SharedSecret struct {
	x int
	y *big.Int
}

func TestSSS(t *testing.T) {
	n := 6
	k := 4
	q := big.NewInt(1237)
	poly := make([]*big.Int, k)
	poly[0] = big.NewInt(1234)
	poly[1] = big.NewInt(166)
	poly[2] = big.NewInt(94)
	poly[3] = big.NewInt(666)
	var sss []*SharedSecret
	for i := 1; i <= n; i++ {
		x0 := big.NewInt(int64(i))
		x := new(big.Int).Set(x0)
		f := new(big.Int).Set(poly[0])
		for j := 1; j < k; j++ {
			f.Mod(f.Add(f, new(big.Int).Mul(poly[j], x)), q)
			x.Mul(x, x0)
		}
		sss = append(sss, &SharedSecret{i, f})
		fmt.Printf("(%d, %d)\n", i, f)
	}

	samples := []int{1, 3, 4, 5}
	var results []*SharedSecret
	for _, i := range samples {
		results = append(results, sss[i])
	}
	s := big.NewInt(0)
	for _, res := range results {
		l := lagrange(res.x, results, q)
		s.Mod(s.Add(s, new(big.Int).Mod(new(big.Int).Mul(l, res.y), q)), q)
		fmt.Printf("l = %d\n", l)
	}
	fmt.Printf("%d\n", s)
}

func lagrange(x int, sss []*SharedSecret, q *big.Int) *big.Int {
	a := big.NewInt(1)
	b := big.NewInt(1)
	xj := big.NewInt(int64(x))
	for _, ss := range sss {
		if ss.x == x {
			continue
		}
		xm := big.NewInt(int64(ss.x))
		a.Mod(a.Mul(a, xm), q)
		b.Mod(b.Mul(b, xm.Sub(xm, xj)), q)
	}
	a.Mod(a.Mul(a, b.ModInverse(b, q)), q)
	return a
}
