// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
)

var sMal []string
var rwMal []string
var mal []string

type nodeGroup struct {
	honest1   []node.Node
	honest2   []node.Node
	mal_nodes []node.Node
}

func getCliques(g *graph.Graph) ([]node.Node, []node.Node) {
	cliques := g.GetCliques(g.GetSelfId(), -1)
	// choose cliques that have only sufficient number of nodes
	var signers []node.Node
	var rw []node.Node
	for _, clique := range cliques {
		n := len(clique.Nodes)
		if n == 0 {
			continue
		}
		if len(clique.Nodes) > 1 {
			for _, i := range clique.Nodes {
				signers = append(signers, i)
			}
		} else {
			rw = append(rw, clique.Nodes[0])
		}
	}
	return signers, rw
}

func (c *Client) getNodeGroups() (nodeGroup, nodeGroup) {
	// the following block splits up each clique into two different groups
	// and isolates the malicious nodes further
	s, rw := getCliques(c.self.(*graph.Graph))
	return getGroup(s, sMal), getGroup(rw, rwMal)
}

func getGroup(nodes []node.Node, mal_array []string) nodeGroup {
	var group nodeGroup
	ctr := true
	for _, client := range nodes {
		flag := true
		for _, malicious := range mal_array {
			if strings.Compare(malicious, client.Address()) == 0 {
				group.mal_nodes = append(group.mal_nodes, client)
				flag = false
				break
			}
		}
		if flag {
			if ctr {
				group.honest1 = append(group.honest1, client)
				ctr = false
			} else {
				group.honest2 = append(group.honest2, client)
				ctr = true
			}
		}
	}
	return group
}

func (c *Client) WriteMal(variable []byte, value []byte) error {
	// writes two different values for the same variable at the same time to colluding servers
	// note colluding servers (mal) defined in mal_test.go
	quorum := c.qs.ChooseQuorum(quorum.AUTH)
	maxt := uint64(0)
	s, rw := c.getNodeGroups()
	group_a := append(s.honest1, s.mal_nodes...)
	group_b := append(s.honest2, s.mal_nodes...)
	group_c := append(rw.honest1, rw.mal_nodes...)
	group_d := append(rw.honest2, rw.mal_nodes...)

	var actives, failure []node.Node
	c.tr.Multicast(transport.Time, quorum.Nodes(), variable, func(res *transport.MulticastResponse) bool {
		if res.Err == nil && len(res.Data) > 0 && len(res.Data) <= 8 {
			t := binary.BigEndian.Uint64(res.Data)
			if t > maxt {
				maxt = t
			}
			actives = append(actives, res.Peer)
			return quorum.IsThreshold(actives)
		} else {
			failure = append(failure, res.Peer)
			return quorum.Reject(failure)
		}
	})
	if !quorum.IsThreshold(actives) {
		return bftkv.ErrInsufficientNumberOfQuorum
	}

	if maxt == math.MaxUint64 {
		return bftkv.ErrInvalidTimestamp
	}
	maxt++

	err1 := c.signAndWrite(group_a, group_c, value, variable, maxt, quorum)
	if err1 != nil {
		return err1
	}
	err2 := c.signAndWrite(group_b, group_d, []byte("second value"), variable, maxt, quorum)
	if err2 != nil {
		return err2
	}

	return nil
}

func (c *Client) signAndWrite(s_group []node.Node, rw_group []node.Node, value []byte, variable []byte, maxt uint64, quorum quorum.Quorum) error {
	s := make([]node.Node, len(s_group))
	copy(s, s_group)

	rw := make([]node.Node, len(rw_group))
	copy(rw, rw_group)

	fmt.Println("Client: WriteMal - writing: ", string(value))

	// self-sign over <x, v>
	tbs, err := packet.Serialize(variable, value)
	if err != nil {
		return err
	}
	sig, err := c.crypt.Signature.Sign(tbs)
	if err != nil {
		return err
	}
	tbss, err := packet.Serialize(variable, value, sig, maxt)
	if err != nil {
		return err
	}
	ss, err := c.crypt.CollectiveSignature.Sign(tbss) // the first one is self-signed
	if err != nil {
		return err
	}
	pkt, err := packet.Serialize(variable, value, sig, maxt, ss)
	if err != nil {
		return err
	}

	var failure []node.Node
	var errs []error
	c.tr.Multicast(transport.Sign, s, pkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			s, err := packet.ParseSignature(res.Data)
			if err == nil {
				return c.crypt.CollectiveSignature.Combine(ss, s, quorum) // whatever the response is
			}
			errs = append(errs, err)
		} else {
			errs = append(errs, res.Err)
		}
		failure = append(failure, res.Peer)
		return quorum.Reject(failure)
	})
	if err := c.crypt.CollectiveSignature.Verify(tbss, ss, quorum); err != nil {
		return majorityError(errs, err)
	}

	pkt, err = packet.Serialize(variable, value, sig, maxt, ss)
	if err != nil {
		return err
	}

	c.tr.Multicast(transport.Write, rw, pkt, func(res *transport.MulticastResponse) bool {
		return false
	})

	return nil
}
