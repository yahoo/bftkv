// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"encoding/binary"
	"math"
	"bytes"
	"errors"
	"log"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
	"github.com/yahoo/bftkv/packet"
)

type Client struct {
	Protocol
}

func majorityError(errs []error, fallback error) error {
	m := make(map[string]struct{
		err error
		n int
	})
	max := 0
	var maj error
	for _, err := range errs {
		s, _ := m[err.Error()]
		s.err = err
		s.n++
		m[err.Error()] = s
		if s.n > max {
			max = s.n
			maj = err
		}
	}
	if maj == nil {
		return fallback
	} else {
		return maj
	}
}

func NewClient(self node.SelfNode, qs quorum.QuorumSystem, tr transport.Transport, crypt *crypto.Crypto) *Client {
	return &Client{Protocol{
		self: self,
		qs: qs,
		tr: tr,
		crypt: crypt,
	}}
}

func (c *Client) Write(variable []byte, value []byte) error {
	// collect timestamps from a quorum
	qr := c.qs.ChooseQuorum(quorum.READ|quorum.AUTH)
	maxt := uint64(0)
	var actives, failure []node.Node
	c.tr.Multicast(transport.Time, qr.Nodes(), variable, func(res *transport.MulticastResponse) bool {
		if res.Err == nil && len(res.Data) > 0 && len(res.Data) <= 8 {
			t := binary.BigEndian.Uint64(res.Data)
			if t > maxt {
				maxt = t
			}
			actives = append(actives, res.Peer)
			return qr.IsThreshold(actives)
		} else {
			failure = append(failure, res.Peer)
			return qr.Reject(failure)
		}
	})
	if !qr.IsThreshold(actives) {
		return bftkv.ErrInsufficientNumberOfQuorum
	}
	if maxt == math.MaxUint64 {
		return bftkv.ErrInvalidTimestamp
	}
	maxt++

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

	// collect sigantures from the quorum
	ss, err := c.crypt.CollectiveSignature.Sign(tbss)	// the first one is self-signed
	if err != nil {
		return err
	}
	pkt, err := packet.Serialize(variable, value, sig, maxt, ss)
	if err != nil {
		return err
	}
	qa := c.qs.ChooseQuorum(quorum.AUTH)
	failure = nil
	var errs []error
	c.tr.Multicast(transport.Sign, c.PeerNodes(qa.Nodes()), pkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			s, err := packet.ParseSignature(res.Data)
			if err == nil {
				return c.crypt.CollectiveSignature.Combine(ss, s, qa)	// whatever the response is
			}
			errs = append(errs, err)
		} else {
			errs = append(errs, res.Err)
		}
		failure = append(failure, res.Peer)
		return qa.Reject(failure)
	})
	if err := c.crypt.CollectiveSignature.Verify(tbss, ss, qa); err != nil {
		return majorityError(errs, err)
	}

	// write signed value to another quorum
	qw := c.qs.ChooseQuorum(quorum.WRITE)
	pkt, err = packet.Serialize(variable, value, sig, maxt, ss)
	if err != nil {
		return err
	}
	var nodes []node.Node
	failure = nil
	errs = nil
	c.tr.Multicast(transport.Write, qw.Nodes(), pkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			nodes = append(nodes, res.Peer)
			return qw.IsThreshold(nodes)
		} else {
			failure = append(failure, res.Peer)
			errs = append(errs, res.Err)
			return qw.Reject(failure)
		}
	})
	if qw.IsThreshold(nodes) {
		return nil
	} else {
		return majorityError(errs, bftkv.ErrInsufficientNumberOfResponses)
	}
}

type signedValue struct {
	node node.Node
	sig *packet.SignaturePacket
	ss *packet.SignaturePacket
	packet []byte
}

var errInProgress = errors.New("")

func (c *Client) maxTimestampedValue(m map[uint64]map[string][]*signedValue, q quorum.Quorum) ([]byte, uint64, error) {
	// first, check if we have enough responses
	var nodes []node.Node
	for _, vl := range m {
		for _, l := range vl {
			for _, sv := range l {
				nodes = append(nodes, sv.node)
			}
		}
	}
	if !q.IsThreshold(nodes) {
		return nil, 0, errInProgress
	}

	// here, we are interested in only the values that have maxt
	maxt := uint64(0)
	var maxvl map[string][]*signedValue
	for t, vl := range m {
		if t > maxt {
			maxt = t
			maxvl = vl
		}
	}
	// @@ should we check equivocation for other timestamps here?
	if len(maxvl) > 1 {
		return nil, 0, bftkv.ErrEquivocation
	}
	for v, _ := range maxvl {
		// must have only one key (value)
		return []byte(v), maxt, nil
	}
	return nil, 0, nil
}

func (c *Client) processResponse(res *transport.MulticastResponse, m map[uint64]map[string][]*signedValue, q quorum.Quorum) error {
	if res.Err != nil {
		log.Printf("Read: error from %s: %s\n", res.Peer.Name(), res.Err)
		return res.Err
	}
	if res.Data == nil || len(res.Data) == 0 {
		return nil
	}
	_, val, sig, t, ss, err := packet.Parse(res.Data)
	if err != nil {
		return err
	}
	// collect <t, v>
	vl, ok := m[t]
	if !ok {
		vl = make(map[string][]*signedValue)
		m[t] = vl
	}
	vl[string(val)] = append(vl[string(val)], &signedValue{res.Peer, sig, ss, res.Data})	// string([]byte) = ""
	return nil
}

type readResult struct {
	value []byte
	err error
}

func (c *Client) Read(variable []byte) ([]byte, error) {
	qa := c.qs.ChooseQuorum(quorum.AUTH)
	qb := c.qs.ChooseQuorum(quorum.READ)
	ch := make(chan(readResult))
	go func() {
		m := make(map[uint64]map[string][]*signedValue)
		var value []byte
		maxt := uint64(0)
		var failure []node.Node
		var errs []error
		c.tr.Multicast(transport.Read, qb.Nodes(), variable, func(res *transport.MulticastResponse) bool {
			if err := c.processResponse(res, m, qa); err == nil {
				if ch != nil {
					value, maxt, err = c.maxTimestampedValue(m, qb)
					if err == nil || err != errInProgress {
						ch <- readResult{value, err}
						ch = nil
					}
				}
			} else {
				failure = append(failure, res.Peer)
				errs = append(errs, err)
				if ch != nil && qb.Reject(failure) {
					ch <- readResult{nil, majorityError(errs, bftkv.ErrInsufficientNumberOfValidResponses)}
					ch = nil
				}
			}
			return false	// go through all members in the quorum
		})
		if ch != nil {
			ch <- readResult{nil, bftkv.ErrInsufficientNumberOfResponses}
		}
		c.revoke(m)
		if value != nil && len(value) > 0 {	// @@ how can we distinguish nil (no variable) from an empty value?
			c.writeBack(qb.Nodes(), m, value, maxt)
		}
	}()
	res := <- ch
	return res.value, res.err
}

func (c *Client) writeBack(u []node.Node, m map[uint64]map[string][]*signedValue, value []byte, t uint64) {
	// must be thread-safe
	// write it back to all nodes that haven't responded with the latest <t, val>
	var q []node.Node
	for _, n := range u {
		found := false
		for _, sv := range m[t][string(value)] {
			if sv.node.Id() == n.Id() {
				found = true
				break
			}
		}
		if !found {
			q = append(q, n)
		}
	}
	if len(q) == 0 {
		return
	}
	pkt := m[t][string(value)][0].packet
	c.tr.Multicast(transport.Write, q, pkt, nil)
}

func (c *Client) revoke(m map[uint64]map[string][]*signedValue) {
	// if two different values at the same timestamp have some signers
	// in common ->> those signers should be revokes
	// @@ verify signatures before revoking suspecious nodes as Read no longer check ss
	revoked := make([]uint64, 0)
	for t, vl := range m {
		if t == 0 {
			// temp solution
			continue
		}
		dup_map := make(map[uint64][]int)
		round := 0
		for _, l := range vl {
			for _, signedVal := range l {
				nodes := c.crypt.CollectiveSignature.Signers(signedVal.ss)
				prev_revoked:
				for _, i := range nodes {
					id := i.Id()
					if v, exists := dup_map[id]; exists {
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
						dup_map[id] = append(dup_map[id], round)
					}
				}
			}
			round += 1
		}
	}
	var buf bytes.Buffer
	if c.self.SerializeRevokedNodes(&buf) != nil {
		c.tr.Multicast(transport.Notify, c.self.GetPeers(), buf.Bytes(), nil)
	}
}

func (c *Client) doRevoke(tbr node.Node, revoked []uint64, node_type string) []uint64 {
	c.self.Revoke(tbr);
	revoked = append(revoked, tbr.Id())
	log.Printf("Revoked %s node: %s\n", node_type, tbr.Name())
	return revoked
}
