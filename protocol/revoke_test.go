// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"fmt"
	"testing"

	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/quorum/wotqs"
)

func getClient(client_loc string) *Client {
	path := "../scripts/gnupg." + client_loc
	crypt := pgp.New()
	g := graph.New()
	pubring := path + "/pubring.gpg"
	secring := path + "/secring.gpg"
	readCerts(g, crypt, pubring, false)
	readCerts(g, crypt, secring, true)

	qs := wotqs.New(g)
	return NewClient(node.SelfNode(g), qs, nil, crypt)
}

type info struct {
	m       map[uint64]map[string][]*signedValue
	signers []string
	value   string
}

func TestRevokeNone(t *testing.T) {
	// all clients/servers are honest -> none should be revoked
	m := make(map[uint64]map[string][]*signedValue)
	client := "a01"
	c := getClient(client)
	clients := []string{"a02", "a03", "a04", "a05"}
	c.forgeMap(info{m, clients, "test1"})
	c.revokeTest(m)
}

func TestRevokeMaliciousClientColludingServer(t *testing.T) {
	// Malicious clients a01, a02, a03 write two values at time 1 to colluding servers
	// a03, a04, a05 which sign both values -> writers/signers a01-a05 should be revoked
	m := make(map[uint64]map[string][]*signedValue)
	clients := []string{"a01", "a02", "a03", "a04", "a05", "a06", "a07"}
	var c *Client
	for i, client := range clients {
		c = getClient(client)
		signers := []string{"a02", "a03", "a04", "a05", "a06", "a09", "a10"}
		c.forgeMap(info{m, signers, "test1"})
		if i < 3 {
			c.forgeMap(info{m, signers[1:4], "test2"})
		}
	}
	c.revokeTest(m)
}

func (c *Client) forgeMap(i info) {
	// adding values at time 1
	_, ok := i.m[1]
	if !ok {
		i.m[1] = make(map[string][]*signedValue)
	}
	sig := c.getWriterSig()
	ss := c.getSignerSigs(i.signers)
	i.m[1][i.value] = append(i.m[1][i.value], &signedValue{c.self, sig, ss, nil})
}

func (c *Client) getWriterSig() *packet.SignaturePacket {
	// returns client's signatures
	req := []byte("test request writer")
	ss, err := c.crypt.CollectiveSignature.Sign(req)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	return ss
}

func (c *Client) getSignerSigs(signers []string) *packet.SignaturePacket {
	// returns signatures of all nodes in clients
	req := []byte("test request signer")

	var ss packet.SignaturePacket
	for _, s := range signers {
		signer := getClient(s)
		s, err := signer.crypt.CollectiveSignature.Sign(req)
		if err != nil {
			fmt.Println(err.Error())
			return nil
		}
		ss.Data = append(ss.Data, s.Data...)
	}
	return &ss
}

func (c *Client) revokeTest(m map[uint64]map[string][]*signedValue) {
        // if two different values at the same timestamp have some signers
        // in common ->> those signers should be revokes
        revoked := make([]uint64, 0)
        for t, vl := range m {
                if t == 0 {
                        // temp solution
                        continue
                }
                dup_map := make(map[string][]int)
                round := 0
                same_writer := make(map[uint64][]int)
                for _, l := range vl {
                        for _, signedVal := range l {
                                writer := c.crypt.CollectiveSignature.Signers(signedVal.sig)[0]
                                if v, exists := same_writer[writer.Id()]; exists {
                                        writer_revoked:
                                        for _, r := range v {
                                                if r != round {
                                                        for _, j := range revoked {
                                                                if j == writer.Id() {
                                                                        break writer_revoked
                                                                }
                                                        }
                                                        revoked = c.doRevoke(writer, revoked, "writer")
                                                }
                                        }
                                } else {
                                        same_writer[writer.Id()] = append(same_writer[writer.Id()], round)
                                }
                                nodes := c.crypt.CollectiveSignature.Signers(signedVal.ss)
                                prev_revoked:
                                for _, i := range nodes {
                                        address := i.Address()
                                        if v, exists := dup_map[address]; exists {
                                                for _, iter_num := range v {
                                                        if iter_num != round {
                                                                // signer signed another value too
                                                                for _, j := range revoked {
                                                                        if j == i.Id() {
                                                                                continue prev_revoked
                                                                        }
                                                                }
                                                                revoked = c.doRevoke(i, revoked, "signer")
                                                        }
                                                }
                                        } else {
                                                dup_map[address] = append(dup_map[address], round)
                                        }
                                }
			}
                        round += 1
                }
        }
}

