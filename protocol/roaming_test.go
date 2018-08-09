// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"testing"
)

var (
	variable = []byte("authtestkey")
	cred = []byte("1234")
)

func TestAuth(t *testing.T) {
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
