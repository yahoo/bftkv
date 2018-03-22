// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"testing"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/quorum"
)

var (
	variable = []byte("authtestkey")
	cred = []byte("1234")
)

func TestAuth(t *testing.T) {
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)

	// create a client
	c := newClient(keyPath + "/u01")
	c.Joining()

	q := c.qs.ChooseQuorum(quorum.AUTH)
	auth := c.auth.NewClient(cred, len(q.Nodes()), q.GetThreshold())
	_, err := c.doAuthentication(auth, variable, q)
	if err == crypto.ErrNoAuthenticationData {
		t.Logf("setting up partial parameters\n")
		if err := c.setupAuthenticationParameters(variable, cred, q); err != nil {
			t.Fatal(err)
		}
		_, err := c.doAuthentication(auth, variable, q)
		if err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestAuth2(t *testing.T) {
	servers := runServers(t, "a", "b", "rw")
	defer stopServers(servers)

	// create a client
	c := newClient(keyPath + "/u01")
	c.Joining()

	_, _, err := c.Authenticate(variable, cred)
	if err != nil {
		t.Fatal(err)
	}
}
