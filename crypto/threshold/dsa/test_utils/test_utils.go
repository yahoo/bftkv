// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package test_utils

import (
        "os"
	"io/ioutil"
        "strings"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
)

const (
	scriptPath = "../../../scripts"
	keyPath = scriptPath + "/run/keys"
	clientKey = keyPath + "/u01"
)

type Server struct {
	Self node.SelfNode
	Th crypto.Threshold
}

func NewServers(newf func(crypt *crypto.Crypto) crypto.Threshold, prefixes ...string, ) (map[uint64]*Server, error) {
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		return nil, err
	}
	servers := make(map[uint64]*Server)
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				path := keyPath + "/" + f.Name()
				g := graph.New()
				crypt := pgp.New()
				if err := readPeers(g, crypt, files, prefixes); err != nil {
					return nil, err
				}
				if err := readCerts(g, crypt, path + "/secring.gpg", true); err != nil {
					return nil, err
				}
				servers[g.Id()] = &Server{
					Self: node.SelfNode(g),
					Th: newf(crypt),
				}
			}
		}
	}
	return servers, nil
}

func readPeers(g *graph.Graph, crypt *crypto.Crypto, files []os.FileInfo, prefixes []string) error {
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				path := keyPath + "/" + f.Name()
				if err := readCerts(g, crypt, path + "/pubring.gpg", false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func NewClient(crypt *crypto.Crypto, path string) (node.Node, error) {
	g := graph.New()
	if err := readCerts(g, crypt, path + "/pubring.gpg", false); err != nil {
		return nil, err
	}
	if err := readCerts(g, crypt, path + "/secring.gpg", true); err != nil {
		return nil, err
	}
	return node.Node(g), nil
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
	crypt.Keyring.Register(certs, sec, true)
	return nil
}
