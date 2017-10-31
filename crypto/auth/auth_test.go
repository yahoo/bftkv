// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package auth

import (
	"testing"
	"bytes"
	"crypto/rand"
)

func testAuth(t *testing.T, password []byte, plainData []byte) {
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
