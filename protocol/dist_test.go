// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"testing"
	"bytes"
	"io/ioutil"
	"encoding/pem"
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"github.com/yahoo/bftkv/crypto/threshold"
)

const (
	caname = "testCA"
	cakey = "../crypto/threshold/rsa/test.pkcs8"
	testData = "TBS"
)

func TestDist(t *testing.T) {
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)

	c := newClient(keyPath + "/u01")
	c.Joining()

	priv := readPKCS8(cakey)
	if priv == nil {
		t.Fatal("couldn't read the key")
	}
	err := c.Distribute(caname, threshold.RSA, priv)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := c.DistSign(caname, []byte(testData), threshold.RSA, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// calculate the standard sig
	h := crypto.SHA256.New()
	h.Write([]byte(testData))
	hashed := h.Sum(nil)
	want, err := rsa.SignPKCS1v15(nil, priv.(*rsa.PrivateKey), crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sig, want) {
		t.Fatal("sig mismatch")
	}
}

func readPKCS8(path string) interface{} {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil {
		if block.Type != "PRIVATE KEY" {
			return nil
		}
		der = block.Bytes
	} else {	// not PEM, assume the data is DER
		der = data
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil
	}
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return key
	default:
		return nil
	}
}
