// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package api

import (
	"testing"
	"bytes"
)

const (
	testKey = "test"
	testValue = "value"
)

func TestAPI(t *testing.T) {
	client, err := OpenClient("../scripts/run/keys/u01")
	if err != nil {
		t.Fatal(err)
	}
	defer CloseClient(client)
	key := []byte(testKey)
	value := []byte(testValue)

	if err := client.Write(key, value); err != nil {
		t.Fatal(err)
	}
	v, err := client.Read(key)
	if !bytes.Equal(v, value) {
		t.Error("value didn't round trip\n")
	}
}
