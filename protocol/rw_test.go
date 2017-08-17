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
	servers := runServers(t, &wsPort, "bftkv.a")
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
	servers := runServers(t, &wsPort, "bftkv.a")
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

func TestConcurrentReads(t *testing.T) {
	// concurrent reads by the same client to the same quorum for the same <x, t>
	// no maximum - crashes when exceeding max # of open files
	wsPort := 7030
	servers := runServers(t, &wsPort, "bftkv.a")
	stopServers(servers)
	c := newClient(scriptPath+"/bftkv.a01", wsPort)
	c.Joining()
	err := c.Write([]byte("mno"), []byte("pqr"))
	if err != nil {
		t.Log(err)
	}
	ch := make(chan int, rounds)
	for n := 0; n < rounds; n++ {
		go func() {
			_, err := c.Read([]byte("mno"))
			if err != nil {
				t.Log(err)
			}
			ch <- 1
		}()
	}
	for i := 0; i < rounds; i++ {
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

func TestManyClientsConcurrentReads(t *testing.T) {
	// concurrent reads by multiple different clients multiple times for the same value
	// no maximum - crashes when exceeding max # of open files
	wsPort := 7090
	servers := runServers(t, &wsPort, "bftkv.a")
	defer stopServers(servers)

	c1 := newClient(scriptPath+"/bftkv.a01", wsPort)
	c1.Joining()
	clients := []*Client{c1}

	err := c1.Write([]byte("mno"), []byte("pqr"))
	if err != nil {
		t.Log(err)
	}

	startManyClients([]string{"a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09"}, &clients, 7091)

	ch_len := rounds * len(clients)
	ch := make(chan int, ch_len)

	// multiple different clients
	for _, c := range clients {
		// multiple concurrent reads for the same key per client
		for n := 0; n < rounds; n++ {
			go func(c *Client) {
				_, err := c.Read([]byte("mno"))
				if err != nil {
					t.Log(err)
				}
				ch <- 1
			}(c)
		}
	}
	for i := 0; i < ch_len; i++ {
		<-ch
	}
}

func TestManyClientsConcurrentWrites(t *testing.T) {
	// multiple different clients will write to different keys multiple times concurrently
	// no maximum - crashes when exceeding max # of open files
	wsPort := 7060
	servers := runServers(t, &wsPort, "bftkv.a")
	defer stopServers(servers)
	var clients []*Client
	startManyClients([]string{"a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"}, &clients, 7061)

	ch_len := len(clients) * rounds
	ch := make(chan int, ch_len)
	for uid, c := range clients {
		for n := 0; n < rounds; n++ {
			go func(c *Client, uid int, n int) {
				// byte array [uid, n] will always be unique
				err := c.Write([]byte{byte(uid), byte(n)}, []byte("dummyval"))
				if err != nil {
					t.Log(err)
				}
				ch <- 1
			}(c, uid, n)
		}
	}
	for i := 0; i < ch_len; i++ {
		<-ch
	}
}
