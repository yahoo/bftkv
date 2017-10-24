// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package auth

import (
	"testing"
	"bytes"
	"math/big"
	"crypto/rand"
)

var password = []byte("password")
var plainData = []byte("plain")

func setupParameters(t *testing.T) {
	// setup the parameters
	p = new(big.Int).SetBytes(pb)
	phi = new(big.Int).Sub(p, big.NewInt(1))
	g = big.NewInt(3)
	// check if p is a safe prime
	q = new(big.Int).Div(phi, big.NewInt(2))
	if !q.ProbablyPrime(64) {
		t.Fatalf("p is not a safe prime! %d\n", p)
	}
}

func TestAuth(t *testing.T) {
	k := 3
	n := 6
	auth := NewAuth()

	ss, err := auth.GeneratePartialAuthenticationData(password, n, k)
	if err != nil {
		t.Fatal(err)
	}

	c := auth.NewClient(password)

	challenge, err := c.GenerateAuthenticationData()
	if err != nil {
		t.Fatal(err)
	}

	var ciphers [][]byte
	for i := 0; i < n; i++ {
		res, cipher, err := auth.MakeResponse(ss[i], challenge, plainData)
		if err != nil {
			t.Fatal(err)
		}
		ciphers = append(ciphers, cipher)

		finished, err := c.ProcessAuthResponse(res, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if finished {
			t.Logf("finished at %d\n", i)
		}
	}

	for i := 0; i < n; i++ {
		plain, err := c.Decrypt(uint64(i), ciphers[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, plainData) {
			t.Error("decryption failed")
		}
	}
}

func testProtocol(t *testing.T) {
//	n := 6
	k := 3

	poly := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		coeff, err := rand.Int(rand.Reader, q)
		if err != nil {
			t.Fatal(err)
		}
		poly[i] = coeff
	}
	salt := make([]byte, SALT_SIZE)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	pi := PI(password, salt)
	gpi := new(big.Int).Exp(g, pi, q)
	x := big.NewInt(1)
	f := new(big.Int).Set(poly[0])
	for j := 1; j < k; j++ {
		f.Add(f, new(big.Int).Mul(poly[j], x))
		f.Mod(f, q)
		x.Mul(x, x)
	}
	y := new(big.Int).Mod(new(big.Int).Add(f, gpi), q)
	// fmt.Printf("f(%d) = %d, y = %d, gpi = %d\n", x, f, y, gpi)

	// generate a challenge
	a, err := rand.Int(rand.Reader, q)
	if err != nil {
		t.Fatal(err)
	}
	X := new(big.Int).Exp(g, a, p)
	// fmt.Printf("X = %d\n", X)

	// make a response
	Yi := new(big.Int).Exp(X, y, p)
	// fmt.Printf("Yi = %d\n", Yi)

	// process the reponse
	inv := new(big.Int).ModInverse(a, q)	// t = a^-1 mod q
	gy := new(big.Int).Exp(Yi, inv, p)		// Yi^t = g^y mod p
	// fmt.Printf("g^y = %d, a = %d, inv = %d\n", gy, a, inv)
		
	expect := new(big.Int).Exp(g, y, p)
	if expect.Cmp(gy) != 0 {
		t.Errorf("failed to inverse:\nexpect = %d\ngot = %d\n", expect, gy)
	}

	gpii := new(big.Int).Exp(g, new(big.Int).Sub(q, gpi), p)		// g^(-g^pi)
	gy.Mod(gy.Mul(gy, gpii), p)			// g^y * g^(-g^pi) = g^(y-g^pi) = g^f(i)

	expect = new(big.Int).Exp(g, f, p)
	if expect.Cmp(gy) != 0 {
		t.Errorf("failed to reduce:\nexpect = %d\ngot = %d\n", expect, gy)
	}
}

func TestProtocol(t *testing.T) {
	setupParameters(t)

	for ntests := 10; ntests > 0; ntests-- {
		testProtocol(t)
	}
}

func TestInverse(t *testing.T) {
	setupParameters(t)

	for ntests := 100; ntests > 0; ntests-- {

		a, err := rand.Int(rand.Reader, q)
		if err != nil {
			t.Fatal(err)
		}
		X := new(big.Int).Exp(g, a, p)	// X = g^a mod p

		y, err := rand.Int(rand.Reader, q)
		Y := new(big.Int).Exp(X, y, p)	// Y = X^y mod p

		inv := new(big.Int).ModInverse(a, q)	// t = a^-1 mod q
		gy := new(big.Int).Exp(Y, inv, p)	// Y^t = g^y mod p

		expect := new(big.Int).Exp(g, y, p)
		if expect.Cmp(gy) != 0 {
			t.Fatal("failed to inverse:\nexpect = %d\ngot = %d\n", expect, gy)
		}
	}
}
