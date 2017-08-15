// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/quorum/wotqs"
	"github.com/yahoo/bftkv/transport"
	transport_http "github.com/yahoo/bftkv/transport/http"
	// transport_http_visual "github.com/yahoo/bftkv/transport/http-visual"
)

func TestMaliciousCollusion(t *testing.T) {
	// malicious client writes <x, t, v> and <x, t, v'> to colluding servers
	// read is attempted for key x => insufficient responses expected
	mal = []string{"http://localhost:5705", "http://localhost:5708", "http://localhost:5709", "http://localhost:5706", "http://localhost:5707"}
	files, err := ioutil.ReadDir(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	// create test servers
	var servers []*MalServer
	wsPort := wsPortStart
	for _, f := range files {
		if strings.HasPrefix(f.Name(), serverKeyPrefix) {
			s := newMalServer(scriptPath+"/"+f.Name(), dbPath+f.Name()[len(serverKeyPrefix):], wsPort)
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			servers = append(servers, s)
			wsPort++
		}
	}

	for _, s := range servers {
		s.Joining()
	}

	defer func() {
		for _, s := range servers {
			s.Stop()
		}
	}()

	// create a client
	c := newClient(scriptPath+"/"+clientKey, wsPort)
	c.Joining()

	key := []byte(testKey)
	value := []byte("honesttestvalue")
	if err := c.WriteMal(key, value); err != nil {
		t.Fatal(err)
	}

	res, err := c.Read(key)
	time.Sleep(time.Second * 1) // sleep to leave time for revoke check
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Key: %s, Value: %s\n", string(key), string(res))
}

// to test tofu --- run 'go test -run=TOFU -v'

func TestTOFU(t *testing.T) {
	// tests must run in following order

	//unique time stamp is key
	uts := time.Now().String()

	// exp: successful --- the client will write <x, t, v> for the first time
	// exp: successful --- the client will wrtie <x, t', v'>
	wsPort := 5040
	servers := runServers(t, &wsPort, "gnupg.a")
	c1 := newClient(scriptPath+"/gnupg.u1", wsPort)
	c1.Joining()
	c1.checkTofu(uts, t, &wsPort, "original write successful")
	c1.checkTofu(uts, t, &wsPort, "self overwrite successful")
	stopServers(servers)

	// exp: successful bc > 2f + 1 of the same servers who signed for u1 will sign for u2
	wsPort = 5050
	servers = runServers(t, &wsPort, "gnupg.a")
	c2 := newClient(scriptPath+"/gnupg.u2", wsPort)
	c2.Joining()
	c2.checkTofu(uts, t, &wsPort, "trusted entity overwrite successful")
	stopServers(servers)

	// exp: permission denied --- diff servers will sign for c01 than u1
	wsPort = 5060
	servers = runServers(t, &wsPort, "gnupg.b")
	c3 := newClient(scriptPath+"/gnupg.c01", wsPort)
	c3.Joining()
	c3.checkTofu(uts, t, &wsPort, "untrusted entity overwrite successful - expected error")
	stopServers(servers)
}

func runServers(t *testing.T, port *int, prefix string) []*Server {
	files, err := ioutil.ReadDir(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	var servers []*Server
	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			s := newServer(scriptPath+"/"+f.Name(), dbPath+f.Name()[len(serverKeyPrefix):] /*port*/, 0)
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			servers = append(servers, s)
			*port += 1
		}
	}

	for _, s := range servers {
		s.Joining()
	}

	return servers
}

func stopServers(servers []*Server) {
	for _, s := range servers {
		s.Stop()
	}
}

func (c *Client) checkTofu(key string, t *testing.T, port *int, exp string) {
	if err := c.Write([]byte(key), []byte(testValue)); err != nil {
		t.Log(err)
	} else {
		t.Log(exp)
	}
	*port += 1
}

func newMalClient(path string, wsPort int) *Client {
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path+"/pubring.gpg", false)
	readCerts(g, crypt, path+"/secring.gpg", true)
	qs := wotqs.New(g)
	var tr transport.Transport
	tr = transport_http.New(crypt)
	return NewClient(node.SelfNode(g), qs, tr, crypt)
}

func newMalServer(path string, dbPath string, wsPort int) *MalServer {
	crypt := pgp.New()
	g := graph.New()
	readCerts(g, crypt, path+"/pubring.gpg", false)
	readCerts(g, crypt, path+"/secring.gpg", true)
	qs := wotqs.New(g)
	var tr transport.Transport
	/*
	   if wsPort != 0 {
	           tr = transport_http_visual.New(crypt, g, qs, strconv.Itoa(wsPort))
	   } else {
	           tr = transport_http.New(crypt)
	   }
	*/
	tr = transport_http.MalNew(crypt)
	storage := MalStorageNew(dbPath)
	return NewMalServer(node.SelfNode(g), qs, tr, crypt, storage)
}
