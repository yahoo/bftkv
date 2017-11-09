// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package main

import (
	"flag"
	"os"
        "strings"
	"fmt"
	"io/ioutil"

	"github.com/yahoo/bftkv/api"
)

var prefixes = []string{"a", "rw"}

func main() {
	keyp := flag.String("key", "key", "path to the key directory")
	passp := flag.String("password", "", "password")
	pathp := flag.String("path", "../scripts/run/keys", "path to the key directory")
	flag.Parse()
	key := *keyp
	pass := *passp
	path := *pathp

	client, err := api.OpenClient(key)
	if err != nil {
		fmt.Errorf("%s: %s\n", path, err)
		return
	}
	defer client.CloseClient()

	av := flag.Args()
	ac := len(av)
	if ac == 0 {
		fmt.Errorf("Usage: %s [-path path] [-password password ] {register|read|write|} ...\n", os.Args[0])
		return
	}
	switch (av[0]) {
	case "register":
		err := register(client, path, pass)
		if err != nil {
			fmt.Errorf("%s\n", err)
		}
	case "read":
		for i := 1; i < ac; i++ {
			val, err := client.Read([]byte(av[i]), pass)
			if err == nil {
				fmt.Printf("%s\n", string(val))
			} else {
				fmt.Errorf("%s\n", err)
			}
		}
	case "write":
		for i := 1; i + 1 < ac; i += 2 {
			err := client.Write([]byte(av[i]), []byte(av[i + 1]), pass)
			if err != nil {
				fmt.Errorf("%s\n", err)
			}
		}
	}
}

func register(client *api.API, path string, pass string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	var certs []string
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				certs = append(certs, path + "/" + f.Name())
			}
		}
	}
	fmt.Printf("registering with %v\n", certs)
	if err := client.Register(certs, pass); err != nil {
		return err
	}
	return client.UpdateCert()
}
