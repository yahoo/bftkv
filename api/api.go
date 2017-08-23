// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package api

import (
	"os"

	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/quorum/wotqs"
	transport_http "github.com/yahoo/bftkv/transport/http"
)

func OpenClient(path string) (*protocol.Client, error) {
	// crypt package
	crypt := pgp.New()

	// construct a graph from pgp keys
	g := graph.New()
	if err := readCerts(g, crypt, path + "/pubring.gpg", false); err != nil {
		return nil, err
	}
	if err := readCerts(g, crypt, path + "/secring.gpg", true); err != nil {
		return nil, err
	}

	// make a quorum system from the graph
	qs := wotqs.New(g)
	tr := transport_http.New(crypt)
	client := protocol.NewClient(node.SelfNode(g), qs, tr, crypt)
	if err := client.Joining(); err != nil {
		return nil, err
	}
	return client, nil
}

func CloseClient(client *protocol.Client) {
	client.Leaving()
}

func readCerts(g *graph.Graph, crypt *crypto.Crypto, path string, sec bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	certs, err := crypt.Certificate.ParseStream(f)
	if err != nil {
		return err
	}
	if sec {
		g.SetSelfNodes(certs)
	} else {
		g.AddNodes(certs)
	}
	return crypt.Keyring.Register(certs, sec, true)
}
