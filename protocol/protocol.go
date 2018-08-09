// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
)

type Protocol struct {
	self node.SelfNode
	qs quorum.QuorumSystem
	tr transport.Transport
	crypt *crypto.Crypto
	threshold crypto.Threshold
}

func (p *Protocol) Joining() error {
	m := make(map[uint64]bool)
	pkt, err := p.self.SerializeSelf()
	if err != nil {
		return err
	}
	for {
		peers := make([]node.Node, 0)
		for _, n := range p.self.GetPeers() {
			if _, ok := m[n.Id()]; !ok {
				peers = append(peers, n)
				m[n.Id()] = true
			}
		}
		if len(peers) == 0 {
			break
		}
		p.tr.Multicast(transport.Join, peers, pkt, func(res *transport.MulticastResponse) bool {
			if res.Data != nil {	// ignore res.Err as it might be bacause the peer certificate hasn't been registered yet
				nodes, err := p.crypt.Certificate.Parse(res.Data)
				if err == nil {
					nodes = p.self.AddPeers(nodes)
					if p.crypt.Keyring.Register(nodes, false, false) != nil {
						p.self.RemovePeers(nodes)
					}
				}
			}
			return false	// go through all nodes
		})
	}
	return nil
}

func (p *Protocol) Leaving() error {
	pkt, err := p.self.SerializeSelf()
	if err == nil {
		p.tr.Multicast(transport.Leave, p.self.GetPeers(), pkt, nil)
	}
	return err
}
