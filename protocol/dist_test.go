// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"bytes"
	gocrypto "crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/yahoo/bftkv/crypto"
)

const (
	rsakey   = "../crypto/threshold/rsa/test.pkcs8"
	dsakey   = "../crypto/threshold/dsa/test.pkcs8"
	testData = "TBS"
)

func TestDist(t *testing.T) {
	t.Skip("skip failing test - FIXME")
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)

	c := newClient(keyPath + "/u01")
	c.Joining()

	doTest(t, c, "testRSA", crypto.TH_RSA)
	doTest(t, c, "testDSA", crypto.TH_DSA)
	doTest(t, c, "testECDSA", crypto.TH_ECDSA)
}

func doTest(t *testing.T, c *Client, caname string, algo crypto.ThresholdAlgo) {
	var key interface{}
	var err error
	switch algo {
	case crypto.TH_RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case crypto.TH_DSA:
		var dsaPriv dsa.PrivateKey
		if err = dsa.GenerateParameters(&dsaPriv.Parameters, rand.Reader, dsa.L1024N160); err == nil {
			if err = dsa.GenerateKey(&dsaPriv, rand.Reader); err == nil {
				key = &dsaPriv
			}
		}
	case crypto.TH_ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Distribute(caname, key); err != nil {
		t.Fatal(err)
	}

	sig, err := c.DistSign(caname, []byte(testData), algo, gocrypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// calculate the standard sig
	h := gocrypto.SHA256.New()
	h.Write([]byte(testData))
	hashed := h.Sum(nil)
	switch algo {
	case crypto.TH_RSA:
		want, err := rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), gocrypto.SHA256, hashed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig, want) {
			t.Fatal("sig mismatch")
		}
	default:
		// simply divide the sig into two
		n := len(sig)
		r := new(big.Int).SetBytes(sig[:n/2])
		s := new(big.Int).SetBytes(sig[n/2:])
		h := gocrypto.SHA256.New()
		h.Write([]byte(testData))
		dgst := h.Sum(nil)
		switch algo {
		case crypto.TH_DSA:
			priv := key.(*dsa.PrivateKey)
			orderSize := (priv.Q.BitLen() + 7) / 8
			if !dsa.Verify(&priv.PublicKey, dgst[:orderSize], r, s) {
				t.Fatal("dsa fail")
			}
		case crypto.TH_ECDSA:
			priv := key.(*ecdsa.PrivateKey)
			if !ecdsa.Verify(&priv.PublicKey, dgst, r, s) {
				t.Fatal("ecdsa fail")
			}
		}
	}
}

func readPKCS8(path string) (algo crypto.ThresholdAlgo, key interface{}, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil {
		if block.Type != "PRIVATE KEY" {
			return
		}
		der = block.Bytes
	} else { // not PEM, assume the data is DER
		der = data
	}
	key, err = x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		algo = crypto.TH_RSA
	case *dsa.PrivateKey:
		algo = crypto.TH_DSA
	case *ecdsa.PrivateKey:
		algo = crypto.TH_ECDSA
	default:
		return
	}
	return
}
