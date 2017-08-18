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

func TestManyWrites(t *testing.T) {
	// prints average time of writes
	wsPort := 7010
	servers := runServers(t, &wsPort, "bftkv.a", "bftkv.r")
	defer stopServers(servers)
	c := newClient(scriptPath+"/bftkv.a01", wsPort)
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
	wsPort := 7020
	servers := runServers(t, &wsPort, "bftkv.a", "bftkv.r")
	defer stopServers(servers)
	c := newClient(scriptPath+"/bftkv.a01", wsPort)
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
	wsPort := 7040
	servers := runServers(t, &wsPort, "bftkv.a", "bftkv.r")
	defer stopServers(servers)
	c1 := newClient(scriptPath+"/bftkv.a01", wsPort)
	c1.Joining()
	wsPort += 1
	err := c1.Write([]byte("mno"), []byte("pqr"))
	if err != nil {
		t.Log(err)
	}
	clients := []*Client{c1}
	startManyClients([]string{"a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09"}, &clients, 7041)
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

func startManyClients(c_paths []string, clients *[]*Client, wsPort int) {
	for _, c_path := range c_paths {
		c := newClient(scriptPath+"/bftkv."+c_path, wsPort)
		c.Joining()
		*clients = append(*clients, c)
		wsPort += 1
	}
}

func TestManyClientsConcurrentWrites(t *testing.T) {
	// multiple different clients will write to different keys multiple times concurrently
	// no maximum - crashes when exceeding max # of open files
	wsPort := 7060
	servers := runServers(t, &wsPort, "bftkv.a", "bftkv.r")
	defer stopServers(servers)
	var clients []*Client
	startManyClients([]string{"a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09"}, &clients, 7061)

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
