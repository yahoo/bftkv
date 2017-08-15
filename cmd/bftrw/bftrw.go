// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"flag"
	"os"
	"log"
	"fmt"

	"runtime/pprof"

	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/quorum/wotqs"
	transport_http "github.com/yahoo/bftkv/transport/http"
)

func main() {
	defaultPath := os.Getenv("HOME") + "/.gnupg/"
	pathp := flag.String("home", defaultPath, "path to home")
	interp := flag.Int("n", 1, "iter")
	prof := flag.String("p", "", "profile")
	flag.Parse()
	path := *pathp
	iter := *interp

	if *prof != "" {
		f, err := os.Create(*prof)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path + "/pubring.gpg", false)
	readCerts(g, crypt, path + "/secring.gpg", true)
	client := protocol.NewClient(g, wotqs.New(g), transport_http.New(crypt), crypt)
	client.Joining()

	av := flag.Args()
	if len(av) == 0 {
		return
	}
	if len(av) > 1 {
		for ; iter > 0; iter-- {
			err := client.Write([]byte(av[0]), []byte(av[1]))
			if err != nil {
				fmt.Printf("%s: %s\n", av[0], err)
				return
			}
		}
		iter = 1
	}
	var res []byte
	for ; iter > 0; iter-- {
		r, err := client.Read([]byte(av[0]))
		if err != nil {
			fmt.Printf("%s: %s\n", av[0], err)
			return
		}
		res = r
	}
	fmt.Printf("%s\n", string(res))
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
	crypt.Keyring.Register(certs, sec)
	f.Close()
}
