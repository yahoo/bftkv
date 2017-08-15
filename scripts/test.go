// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"os"
	"flag"
	"log"
	"bytes"
	"strconv"

	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node/graph"
        "github.com/yahoo/bftkv/quorum/wotqs"
        "github.com/yahoo/bftkv/transport"
        transport_http "github.com/yahoo/bftkv/transport/http"
)


func main() {
	defaultPath := os.Getenv("HOME") + "/.gnupg/"
	pathp := flag.String("home", defaultPath, "path to home")
	keyp := flag.String("key", "key", "key")
	np := flag.Int("n", 1, "num keys")
	mp := flag.Int("m", 1, "num values")
	readonlyp := flag.Bool("ro", false, "readonly")

	flag.Parse()
	key := *keyp
	n := *np
	m := *mp

	c := newClient(*pathp)
	c.Joining()

	value := []byte("value1")
	for ; n > 0; n-- {
		key := []byte(key + strconv.Itoa(n))
		for ; m > 0; m-- {
			if !*readonlyp {
				value = []byte("value" + strconv.Itoa(m))
				if err := c.Write(key, value); err != nil {
					log.Fatal(err)
				}
			}
			res, err := c.Read(key)
			if err != nil {
				log.Fatal(err)
			}
			if !bytes.Equal(res, value) {
				log.Printf("Got %s, expected %s\n", res, value)
			}
		}
	}
}

func newClient(path string) *protocol.Client {
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path + "/pubring.gpg", false)
	readCerts(g, crypt, path + "/secring.gpg", true)
	qs := wotqs.New(g)
	var tr transport.Transport
	tr = transport_http.New(crypt)
	return protocol.NewClient(node.SelfNode(g), qs, tr, crypt)
}

func readCerts(g *graph.Graph, crypt *crypto.Crypto, path string, sec bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	certs, err := crypt.Certificate.ParseStream(f)
	if err != nil {
		f.Close()
		log.Fatal(err)
	}
	if sec {
		g.SetSelfNodes(certs)
	} else {
		g.AddNodes(certs)
	}
	crypt.Keyring.Register(certs, sec)
	f.Close()
}
