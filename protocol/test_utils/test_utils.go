// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package test_utils

import (
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/quorum/wotqs"
	storage_plain "github.com/yahoo/bftkv/storage/plain"
	"github.com/yahoo/bftkv/transport"
	transport_http "github.com/yahoo/bftkv/transport/http"
)

const (
	scriptPath      = "../scripts" // any way to specify the absolute path?
	KeyPath         = scriptPath + "/run/keys"
	serverKeyPrefix = "a"
	ClientKey       = "u01"
	dbPrefix        = scriptPath + "/run/db."
	testKey         = "test"
	testValue       = "test"
)

func NewServer(path string, dbPath string) *protocol.Server {
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path+"/pubring.gpg", false)
	readCerts(g, crypt, path+"/secring.gpg", true)
	qs := wotqs.New(g)
	var tr transport.Transport
	tr = transport_http.New(crypt)
	storage := storage_plain.New(dbPath)
	return protocol.NewServer(node.SelfNode(g), qs, tr, crypt, storage)
}

func NewClient(path string) *protocol.Client {
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path+"/pubring.gpg", false)
	readCerts(g, crypt, path+"/secring.gpg", true)
	qs := wotqs.New(g)
	var tr transport.Transport
	tr = transport_http.New(crypt)
	return protocol.NewClient(node.SelfNode(g), qs, tr, crypt)
}

func RunServers(t *testing.T, prefixes ...string) []*protocol.Server {
	files, err := ioutil.ReadDir(KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	var servers []*protocol.Server
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				s := NewServer(KeyPath+"/"+f.Name(), dbPrefix+f.Name())
				if err := s.Start(); err != nil {
					t.Fatal(err)
				}
				servers = append(servers, s)
			}
		}
	}

	return servers
}

func StopServers(servers []*protocol.Server) {
	for _, s := range servers {
		s.Stop()
	}
}

func readCerts(g *graph.Graph, crypt *crypto.Crypto, path string, sec bool) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
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
	crypt.Keyring.Register(certs, sec, true)
	f.Close()
}
