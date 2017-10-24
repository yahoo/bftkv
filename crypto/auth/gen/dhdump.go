// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"os"
	"bufio"
	"io/ioutil"
	"fmt"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
)

func main() {
	// read up all data from stdin
	r := bufio.NewReader(os.Stdin)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Errorf("%s\n", err)
		os.Exit(1)
	}

	pem, _ := pem.Decode(b)
	// the asn1/der must be a SEQUENCE of INTEGER
	var val []*big.Int
	if _, err := asn1.Unmarshal(pem.Bytes, &val); err != nil {
		fmt.Errorf("%s\n", err)
		os.Exit(1)
	}
	p := val[0].Bytes()
	for i := 0; i < len(p); i++ {
		fmt.Printf("0x%02x, ", p[i])
	}
	fmt.Printf("\n")
}
