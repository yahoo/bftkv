// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"flag"
	"os"
        "strings"
	"fmt"
	"io/ioutil"
	"encoding/pem"
	"encoding/asn1"
	"encoding/hex"
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ecdsa"
	"errors"

	"github.com/yahoo/bftkv/api"
	"github.com/yahoo/bftkv/crypto/threshold"
)

var prefixes = []string{"a", "rw"}

func main() {
	keyp := flag.String("key", "key", "path to the self key directory")
	passp := flag.String("password", "", "password")
	pathp := flag.String("path", "../scripts/run/keys", "path to the peer keys directory")
	hexp := flag.Bool("hex", false, "key in hex")
	flag.Parse()
	key := *keyp
	pass := *passp
	path := *pathp

	client, err := api.OpenClient(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", path, err)
		return
	}
	defer client.CloseClient()

	av := flag.Args()
	ac := len(av)
	if ac == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-path path] [-password password ] {register|read|write|ca|sign} ...\n", os.Args[0])
		return
	}
	switch (av[0]) {
	case "register":
		err := register(client, path, pass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	case "read":
		for i := 1; i < ac; i++ {
			key, err := toKey(av[i], *hexp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				break
			}
			val, err := client.Read(key, pass)
			if err == nil {
				fmt.Printf("%s\n", string(val))
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	case "write":
		for i := 1; i + 1 < ac; i += 2 {
			key, err := toKey(av[i], *hexp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				break
			}
			err = client.Write(key, []byte(av[i + 1]), pass)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	case "ca":
		if ac < 2 {
			return
		}
		caname := av[1]
		for i := 2; i < ac; i++ {
			err := ca(client, caname, av[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	case "sign":
		if ac < 2 {
			return
		}
		caname := av[1]
		for i := 2; i < ac; i++ {
			err := sign(client, caname, av[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %s\n", av[0])
	}
}

func register(client *api.API, path string, pass string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	var certs []string
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				certs = append(certs, path + "/" + f.Name())
			}
		}
	}
	fmt.Printf("registering with %v\n", certs)
	if err := client.Register(certs, pass); err != nil {
		return err
	}
	return client.UpdateCert()
}

func ca(client *api.API, caname string, path string) error {
	// support pkcs8 only for now
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil {
		if block.Type != "PRIVATE KEY" {
			return errors.New("not a PKCS8")
		}
		der = block.Bytes
	} else {	// not PEM, assume the data is DER
		der = data
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	var algo threshold.Algo
	switch key.(type) {
	case *rsa.PrivateKey:
		algo = threshold.RSA
	case *ecdsa.PrivateKey:
		algo = threshold.ECDSA
	default:	// no DSA!?
		return errors.New("unsupported algorithm")
	}
	return client.Distribute(caname, algo, key)
}

type certificate struct {
  	TBSCertificate     asn1.RawValue
  	SignatureAlgorithm asn1.RawValue
  	SignatureValue     asn1.BitString
}

func sign(client *api.API, caname string, path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return errors.New("not a certificate")
		}
		der = block.Bytes
	} else {
		der = data
	}
	crt, err := x509.ParseCertificate(der)	// template
	if err != nil {
		return err
	}
	var alg threshold.Algo
	var hash crypto.Hash
	switch crt.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		alg = threshold.RSA
		hash = crypto.SHA256
	case x509.SHA384WithRSA:
		alg = threshold.RSA
		hash = crypto.SHA384
	case x509.SHA512WithRSA:
		alg = threshold.RSA
		hash = crypto.SHA512
	case x509.ECDSAWithSHA256:
		alg = threshold.ECDSA
		hash = crypto.SHA256
	case x509.ECDSAWithSHA384:
		alg = threshold.ECDSA
		hash = crypto.SHA384
	case x509.ECDSAWithSHA512:
		alg = threshold.ECDSA
		hash = crypto.SHA512
	default:
		return errors.New("unsupported signature algorithm")
	}

	sig, err := client.Sign(caname, crt.RawTBSCertificate, alg, hash)
	if err != nil {
		return err
	}

	// get raw signatureAlgorithm
	// because of a bug we can't unmarshal SEQUENCE into []RawValue https://github.com/golang/go/issues/17321
	var raw, tbs, sigalg asn1.RawValue
	// strip the outmost SEQ
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return err
	}
	// skip the TBS SEQ
	rest, err = asn1.Unmarshal(raw.Bytes, &tbs)
	if err != nil {
		return err
	}
	_, err = asn1.Unmarshal(rest, &sigalg)
	if err != nil {
		return err
	}

	der, err = asn1.Marshal(certificate{
		tbs,
		sigalg,
		asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return err
	}

	// register the new cert to SKI
	if err := client.Write(crt.SubjectKeyId, der, ""); err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type: "CERTIFICATE",
		Headers: nil,
		Bytes: der,
	})
}

func toKey(s string, hexp bool) ([]byte, error) {
	if hexp {
		return hex.DecodeString(s)
	} else {
		return []byte(s), nil
	}
}
