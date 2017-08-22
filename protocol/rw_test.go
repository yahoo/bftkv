// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"flag"
	"fmt"
	"strconv"
	"testing"
	"time"
)

var rounds int

func init() {
	// optional flag
	num_rounds := flag.String("r", "10", "number of reads/writes")
	flag.Parse()
	rounds, _ = strconv.Atoi(*num_rounds)
}

func TestConflict(t *testing.T) {
	// make writes for new value from several different clients concurrently
	// expecting invalid signature request twice and ultimately successful read
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)
	var clients []*Client
	startManyClients([]string{"u01", "u02", "u03"}, &clients)

	ch := make(chan int, len(clients))
	k := time.Now().String()
	for _, client := range clients {
		go func(client *Client) {
			err := client.Write([]byte(k), []byte(client.self.Name()))
			if err != nil {
				t.Log(err)
			} else {
				t.Log("Winner: ", client.self.Name())
			}
			ch <- 1
		}(client)
	}
	for i := 0; i < len(clients); i++ {
		<-ch
	}

	c4 := newClient(keyPath + "/u04")
	c4.Joining()
	_, err := c4.Read([]byte(k))
	if err != nil {
		t.Log(err)
	}
}

func TestManyWrites(t *testing.T) {
	// prints average time of writes
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)
	c := newClient(keyPath + "/u01")
	c.Joining()
	start := time.Now()
	for n := 0; n < rounds; n++ {
		err := c.Write([]byte("abc"), []byte("def"))
		if err != nil {
			t.Log(err)
		}
	}
	duration := time.Since(start)
	fmt.Printf("Avg write: %.6f seconds\n", duration.Seconds()/float64(rounds))
}

func TestManyReads(t *testing.T) {
	// prints average time of reads
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)
	c := newClient(keyPath + "/u01")
	c.Joining()
	err := c.Write([]byte("ghi"), []byte("jkl"))
	if err != nil {
		t.Log(err)
	}
	start := time.Now()
	for n := 0; n < rounds; n++ {
		_, err := c.Read([]byte("ghi"))
		if err != nil {
			t.Log(err)
		}
	}
	duration := time.Since(start)
	fmt.Printf("Avg read: %.6f seconds\n", duration.Seconds()/float64(rounds))
}

func TestManyClientsConcurrentReads(t *testing.T) {
	// concurrent reads by different clients to the same quorum for the same <x, t>
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)
	c1 := newClient(keyPath + "/u01")
	c1.Joining()
	err := c1.Write([]byte("mno"), []byte("pqr"))
	if err != nil {
		t.Log(err)
	}
	clients := []*Client{c1}
	startManyClients([]string{"u01"}, &clients)
	num_clients := len(clients)
	ch := make(chan int, num_clients)
	for _, client := range clients {
		go func(c *Client) {
			_, err := c.Read([]byte("mno"))
			if err != nil {
				t.Log(err)
			}
			ch <- 1
		}(client)
	}
	for i := 0; i < num_clients; i++ {
		<-ch
	}
}

func startManyClients(c_paths []string, clients *[]*Client) {
	for _, c_path := range c_paths {
		c := newClient(keyPath + "/" + c_path)
		c.Joining()
		*clients = append(*clients, c)
	}
}

func TestManyClientsConcurrentWrites(t *testing.T) {
	// multiple different clients will write to different keys multiple times concurrently
	// no maximum - crashes when exceeding max # of open files
	servers := runServers(t, "a", "rw")
	defer stopServers(servers)
	var clients []*Client
	startManyClients([]string{"u01"}, &clients)

	ch_len := len(clients)
	ch := make(chan int, ch_len)
	for uid, c := range clients {
		go func(c *Client, uid int) {
			// byte array uid will always be unique
			err := c.Write([]byte{byte(uid)}, []byte("dummyval"))
			if err != nil {
				t.Log(err)
			}
			ch <- 1
		}(c, uid)
	}
	for i := 0; i < ch_len; i++ {
		<-ch
	}
}
