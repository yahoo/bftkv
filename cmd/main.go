// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"context"
	"time"
	"net/http"
	"io/ioutil"
	"strings"
	"strconv"
	"log"
	"fmt"

	"net/http/pprof"

	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/quorum/wotqs"
	"github.com/yahoo/bftkv/storage"
	storage_plain "github.com/yahoo/bftkv/storage/plain"
	storage_leveldb "github.com/yahoo/bftkv/storage/leveldb"
	"github.com/yahoo/bftkv/transport"
	transport_http "github.com/yahoo/bftkv/transport/http"
	transport_http_visual "github.com/yahoo/bftkv/transport/http-visual"
)

func main() {
	defaultPath := os.Getenv("HOME") + "/.gnupg/"
	pathp := flag.String("home", defaultPath, "path to home")
	secringp := flag.String("sec", "", "secret key ring")
	pubringp := flag.String("pub", "", "public key ring")
	revocationp := flag.String("rev", "", "revocation list")
	dbPathp := flag.String("db", "db", "database path")
	ldbPathp := flag.String("ldb", "", "level db path")
	apiPortp := flag.Int("api", 0, "http api address")
	wsPortp := flag.Int("ws", 0, "web socket port")

	flag.Parse()
	path := *pathp
	secring := *secringp
	if secring == "" {
		secring = path + "/secring.gpg"
	}
	pubring := *pubringp
	if pubring == "" {
		pubring = path + "/pubring.gpg"
	}

	revocation := *revocationp
	if revocation == "" {
		revocation = path + "/revocation.gpg"
	}

	wsPort := *wsPortp

	// crypt package
	crypt := pgp.New()

	// construct a graph from pgp keys
	g := graph.New()
	readCerts(g, crypt, pubring, false)
	readCerts(g, crypt, secring, true)
	readRevocationList(g, crypt, revocation)

	// make a quorum system from the graph
	qs := wotqs.New(g)

	var tr transport.Transport
	if wsPort == 0 {
		tr = transport_http.New(crypt)
	} else {
		// create a HTTP visual transport layer with PGP security
		tr = transport_http_visual.New(crypt, g, qs, strconv.Itoa(wsPort))
	}

	// create a storage for the server
	var storage storage.Storage
	if *ldbPathp != "" {
		storage = storage_leveldb.New(*dbPathp)
	} else {
		storage = storage_plain.New(*dbPathp)
	}

	// create BFTKV client and server, and start the server
	bftClient := protocol.NewClient(node.SelfNode(g), qs, tr, crypt)
	bftServer := protocol.NewServer(node.SelfNode(g), qs, tr, crypt, storage)

	if err := bftServer.Start(); err != nil {
		log.Fatal(err)
	}

	var apiServer *apiService
	if *apiPortp != 0 {
		// start HTTP API
		apiServer = &apiService{bftClient: bftClient, g: g}
		apiServer.Start(*apiPortp)
	}

	// wait for a signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)
	<-ch

	// stop servers
	if apiServer != nil {
		apiServer.Stop()
	}
	bftServer.Stop()
	
	// save pubring and revocation list
	// writeCerts(g, crypt, pubring)	// don't write it back for now, as all nodes leave when this program terminates
	// writeRevocationList(g, crypt, revocation)
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
	crypt.Keyring.Register(certs, sec, true)
	f.Close()
}

func readRevocationList(g *graph.Graph, crypt *crypto.Crypto, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	certs, err := crypt.Certificate.ParseStream(f)
	if err == nil {
		g.RevokeNodes(certs)
	}
	f.Close()
}

func writeCerts(g *graph.Graph, crypt *crypto.Crypto, path string) {
	log.Printf("writing back certs: %s\n", path)
	os.Rename(path, path + "~")
	f, err := os.Create(path)
	if err != nil {
		log.Print(err)
	} else {
		err := g.SerializeNodes(f)
		f.Close()
		if err != nil {
			log.Print(err)
		}
	}
}

func writeRevocationList(g *graph.Graph, crypt *crypto.Crypto, path string) {
	log.Printf("saving the revocation list: %s\n", path)
	os.Rename(path, path + "~")
	f, err := os.Create(path)
	if err != nil {
		log.Print(err)
	} else {
		err := g.SerializeRevokedNodes(f)
		f.Close()
		if err != nil {
			log.Print(err)
		}
	}
}


//
// HTTP API
//

type apiService struct {
	bftClient *protocol.Client
	g *graph.Graph
	httpServer *http.Server
}

func (s *apiService) Start(port int) {
	s.httpServer = &http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: s,
	}
	go s.httpServer.ListenAndServe()
}

func (s *apiService) Stop() {
	ctx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
	s.httpServer.Shutdown(ctx)
	s.httpServer.Close()
}

func (s *apiService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodGet {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	path := strings.ToLower(r.URL.Path)
	var res []byte
	var err error
	a := strings.Split(path, "/")
	switch a[1] {
	case "read":
		err = s.bftClient.Joining()
		if err == nil {
			res, err = s.bftClient.Read([]byte(a[2]))
			s.bftClient.Leaving()
		}
	case "write":
		fallthrough
	case "writeonce":
		body, err2 := ioutil.ReadAll(r.Body)
		if err2 != nil {
			http.Error(w, err2.Error(), http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		err = s.bftClient.Joining()
		if err == nil {
			if a[1] == "writeonce" {
				err = s.bftClient.WriteOnce([]byte(a[2]), body)
			} else {
				err = s.bftClient.Write([]byte(a[2]), body)
			}
			s.bftClient.Leaving()
		}
	case "joining":
		err = s.bftClient.Joining()
	case "leaving":
		err = s.bftClient.Leaving()
	case "show":
		s.dump()
	case "debug":
		pprof.Profile(w, r)
		return
	default:
		fmt.Printf("unknown path: %s\n", a[1])
		return
	}
	if err == nil {
		fmt.Printf("\"%s\" success\n", a[1])
	} else {
		fmt.Printf("\"%s\" error: %s\n", a[1], err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(res)
}

func (s *apiService) dump() {
	fmt.Printf(">>> %s <<<\n", s.g.Self[0].Instance.Name())
	for _, v := range s.g.Vertices {
		n := v.Instance
		if n == nil {
			continue
		}
		instance := ""
		if n.Instance() == nil {
			instance = "nil"
		}
		fmt.Printf("  %s [%x] %s\n", n.Name(), n.Id(), instance)
		for _, e := range v.Edges {
			if e.Instance != nil {
				fmt.Printf("    %s\n", e.Instance.Name())
			} else {
				fmt.Printf("    ---\n")
			}
		}
	}
}
