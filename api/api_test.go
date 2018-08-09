// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package api

import (
	"fmt"
	"testing"
	"bytes"
	"os"

	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/protocol/test_utils"
)

var (
	testValue = []byte("testvalue")
)

const password = "1234"

var certlist = []string{
	test_utils.KeyPath + "/a01",
	test_utils.KeyPath + "/a02",
	test_utils.KeyPath + "/a03",
	test_utils.KeyPath + "/a04",
	test_utils.KeyPath + "/a05",
	test_utils.KeyPath + "/a06",
	test_utils.KeyPath + "/a07",
	test_utils.KeyPath + "/a08",
	test_utils.KeyPath + "/a09",
	test_utils.KeyPath + "/a10",
	test_utils.KeyPath + "/rw01",
	test_utils.KeyPath + "/rw02",
	test_utils.KeyPath + "/rw03",
	test_utils.KeyPath + "/rw04",
	test_utils.KeyPath + "/rw05",
	test_utils.KeyPath + "/rw06",
}

const (
	preRegisteredKey = "u01"
	virginKey = "test1"
)

func testRW(t *testing.T, clientKey string, variable string) {
	client, err := OpenClient(test_utils.KeyPath + "/" + clientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseClient()

	// plain read/write
	plainVariable := []byte(variable)
	if err := client.Write(plainVariable, testValue, ""); err != nil {
		t.Fatal(err)
	}
	val, err := client.Read(plainVariable, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val, testValue) {
		t.Error("value mismatch")
	}
	t.Logf("plain read/write done. move on to auth read/write\n")

	// authorized read/write
	authVariable := []byte(variable + "_auth")
	if err := client.Write(authVariable, testValue, password); err != nil {
		t.Fatal(err)
	}
	val, err = client.Read(authVariable, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val, testValue) {
		t.Error("auth read/write mistmatch")
	}

	// auth read with a wrong password
	val, err = client.Read(authVariable, "123");
	if err == nil {
		t.Error("auth succeeded with a wrong key!?")
	}
	t.Logf("auth read/write done.")
}

func testRegistration(t *testing.T, clientKey string) {
	client, err := OpenClient(test_utils.KeyPath + "/" + clientKey)		// should be a virgin key
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseClient()

	if err := client.Register(certlist, password); err != nil {
		t.Fatal(err)
	}

	// test if the self cert has the signature from the quorum
	signers := client.crypt.Certificate.Signers(node.SelfNode(client.g))
	sm := make(map[uint64]node.Node)
	for _, sig := range signers {
		sm[sig.Id()] = sig
	}
	q := client.qs.ChooseQuorum(quorum.AUTH)
	for _, qm := range q.Nodes() {
		if _, ok := sm[qm.Id()]; !ok {
			t.Logf("couldn't find the signature of %s\n", qm.Name())
		}
	}
	if err := client.UpdateCert(); err != nil {	// update the pubring
		t.Error(err)
	}

	// double-check if the password auth went through
	if _, _, err := client.client.Authenticate([]byte(client.UId()), []byte(password)); err != nil {
		t.Error(err)
	}
}

func TestAPI(t *testing.T) {
	servers := test_utils.RunServers(t, "a", "rw")
	defer test_utils.StopServers(servers)

	testRW(t, preRegisteredKey, "testkey")	// use the pre-registered key
	if t.Failed() {
		return
	}
	testRegistration(t, virginKey)	// register the virgin key
	if !t.Failed() {
		defer func() {
			path := test_utils.KeyPath + "/" + virginKey + "/pubring.gpg"
			os.Rename(path + "~", path)
		}()
		testRW(t, virginKey, "virginkey")	// to check the registration has finished in success
	}
}

func dump(g *graph.Graph, prompt string) {
	fmt.Printf(">>> %s <<<\n", prompt)
	for _, v := range g.Vertices {
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

func (api *API) isSelf(v *graph.Vertex) bool {
	for _, s := range api.g.Self {
		if v == s {
			return true
		}
	}
	return false
}

func (api *API) dump2(prompt string) {
	fmt.Printf(">>> %s <<<\n", prompt)
	for _, v := range api.g.Self {
		if v.Instance == nil {
			continue
		}
		fmt.Printf("self: %s (%x)\n", v.Instance.Name(), v.Instance)
		for _, s := range api.crypt.Certificate.Signers(v.Instance) {
			fmt.Printf("  %s\n", s.Name())
		}
	}
	for _, v := range api.g.Vertices {
		if v.Instance == nil || api.isSelf(v) {
			continue
		}
		fmt.Printf("peer: %s (%x)\n", v.Instance.Name(), v.Instance)
		for _, s := range api.crypt.Certificate.Signers(v.Instance) {
			fmt.Printf("  %s\n", s.Name())
		}
	}
}
