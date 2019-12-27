// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"bytes"
	gocrypto "crypto"
	"encoding/binary"
	"errors"
	"log"
	"math"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/auth"
	"github.com/yahoo/bftkv/crypto/threshold"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
)

type Client struct {
	Protocol
}

func majorityError(errs []error, fallback error) error {
	m := make(map[string]int)
	max := 0
	var maj error
	for _, err := range errs {
		n, ok := m[err.Error()]
		if ok {
			n++
		} else {
			n = 1
		}
		m[err.Error()] = n
		if n > max {
			max = n
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
		self:      self,
		qs:        qs,
		tr:        tr,
		crypt:     crypt,
		threshold: threshold.New(crypt),
	}}
}

func (c *Client) Write(variable []byte, value []byte, proof *packet.SignaturePacket) error {
	// collect timestamps from a quorum
	qr := c.qs.ChooseQuorum(quorum.READ | quorum.AUTH)
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

	return c.writeWithTimestamp(variable, value, maxt+1, proof)
}

func (c *Client) WriteOnce(variable []byte, value []byte, proof *packet.SignaturePacket) error {
	return c.writeWithTimestamp(variable, value, math.MaxUint64, proof)
}

func (c *Client) writeWithTimestamp(variable []byte, value []byte, t uint64, proof *packet.SignaturePacket) error {
	sig, ss, _, err := c.collectSignatures(variable, value, t, proof)
	if err != nil {
		return err
	}

	// write signed value to another quorum
	qw := c.qs.ChooseQuorum(quorum.WRITE)
	pkt, err := packet.Serialize(variable, value, t, sig, ss)
	if err != nil {
		return err
	}
	var nodes, failure []node.Node
	var errs []error
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

func (c *Client) collectSignatures(variable []byte, value []byte, t uint64, proof *packet.SignaturePacket) (sig, ss *packet.SignaturePacket, secret []byte, err error) {
	// self-sign over <x, v>
	tbs, err := packet.Serialize(variable, value, t)
	if err != nil {
		return
	}
	sig, err = c.crypt.Signature.Sign(tbs)
	if err != nil {
		return
	}
	tbss, err := packet.Serialize(variable, value, t, sig)
	if err != nil {
		return
	}

	// collect sigantures from the quorum
	qa := c.qs.ChooseQuorum(quorum.AUTH | quorum.PEER)
	pkt, err := packet.Serialize(variable, value, t, sig, proof)
	var failure []node.Node
	var errs []error
	ss = new(packet.SignaturePacket)
	c.tr.Multicast(transport.Sign, qa.Nodes(), pkt, func(res *transport.MulticastResponse) bool {
		err := res.Err
		if err == nil {
			if res.Data != nil {
				var s *packet.SignaturePacket
				s, err = packet.ParseSignature(res.Data)
				if err == nil {
					return c.crypt.CollectiveSignature.Combine(ss, s, qa) // whatever the response is
				}
			}
		}
		if err == nil {
			return false
		} else {
			errs = append(errs, err)
			failure = append(failure, res.Peer)
			return qa.Reject(failure)
		}
	})
	err = c.crypt.CollectiveSignature.Verify(tbss, ss, qa)
	if err != nil {
		err = majorityError(errs, err)
	}
	return
}

type signedValue struct {
	node   node.Node
	sig    *packet.SignaturePacket
	ss     *packet.SignaturePacket
	packet []byte
}

var errInProgress = errors.New("")

func isThreshold(l []*signedValue, q quorum.Quorum) bool {
	var nodes []node.Node
	for _, sv := range l {
		nodes = append(nodes, sv.node)
	}
	return q.IsThreshold(nodes)
}

func (c *Client) maxTimestampedValue(m map[uint64]map[string][]*signedValue, q quorum.Quorum) ([]byte, uint64, error) {
	// here, we are interested in only the values that have maxt
	maxt := uint64(0)
	var maxvl map[string][]*signedValue
	for t, vl := range m {
		if t >= maxt {
			maxt = t
			maxvl = vl
		}
	}
	for v, l := range maxvl {
		if isThreshold(l, q) {
			return []byte(v), maxt, nil
		}
	}
	return nil, 0, errInProgress
}

func (c *Client) processResponse(res *transport.MulticastResponse, m map[uint64]map[string][]*signedValue) error {
	if res.Err != nil {
		log.Printf("Read: error from %s: %s\n", res.Peer.Name(), res.Err)
		return res.Err
	}
	var val []byte
	var sig, ss *packet.SignaturePacket
	var t uint64
	var err error
	if res.Data != nil && len(res.Data) > 0 {
		_, val, t, sig, ss, _, err = packet.Parse(res.Data)
		if err != nil {
			return err
		}
	}
	// collect <t, v>
	vl, ok := m[t]
	if !ok {
		vl = make(map[string][]*signedValue)
		m[t] = vl
	}
	vl[string(val)] = append(vl[string(val)], &signedValue{res.Peer, sig, ss, res.Data}) // string([]byte) = ""
	return nil
}

type readResult struct {
	value []byte
	err   error
}

func (c *Client) Read(variable []byte, proof *packet.SignaturePacket) ([]byte, error) {
	q := c.qs.ChooseQuorum(quorum.READ)
	ch := make(chan (readResult))
	pkt, err := packet.Serialize(variable, nil, uint64(0), nil, proof)
	if err != nil {
		return nil, err
	}
	go func() {
		m := make(map[uint64]map[string][]*signedValue)
		var value []byte
		maxt := uint64(0)
		var failure []node.Node
		var errs []error
		c.tr.Multicast(transport.Read, q.Nodes(), pkt, func(res *transport.MulticastResponse) bool {
			if err := c.processResponse(res, m); err == nil {
				if ch != nil {
					value, maxt, err = c.maxTimestampedValue(m, q)
					if err == nil || err != errInProgress {
						ch <- readResult{value, err}
						ch = nil
					}
				}
			} else {
				failure = append(failure, res.Peer)
				errs = append(errs, err)
				if ch != nil && q.Reject(failure) {
					ch <- readResult{nil, majorityError(errs, bftkv.ErrInsufficientNumberOfValidResponses)}
					ch = nil
				}
			}
			return false // go through all members in the quorum
		})
		if ch != nil {
			ch <- readResult{nil, bftkv.ErrInsufficientNumberOfResponses}
		}
		c.revoke(m)
		if value != nil && len(value) > 0 { // @@ how can we distinguish nil (no variable) from an empty value?
			c.writeBack(q.Nodes(), m, value, maxt)
		}
	}()
	res := <-ch
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
	c.self.Revoke(tbr)
	revoked = append(revoked, tbr.Id())
	log.Printf("Revoked %s node: %s\n", node_type, tbr.Name())
	return revoked
}

//
// TPA
//

func (c *Client) Authenticate(variable []byte, cred []byte) (proof *packet.SignaturePacket, key []byte, err error) {
	q := c.qs.ChooseQuorum(quorum.AUTH | quorum.PEER)
	aclient := auth.NewClient(cred, len(q.Nodes()), q.GetThreshold())
	proof, err = c.doAuthentication(aclient, variable, q)
	if err == crypto.ErrNoAuthenticationData {
		// need to register first
		if err := c.setupAuthenticationParameters(variable, cred, q); err != nil {
			return nil, nil, err
		}
		proof, err = c.doAuthentication(aclient, variable, q)
		if err != nil {
			return nil, nil, err
		}
	}
	if err == nil {
		key, err = aclient.GetCipherKey()
	}
	return proof, key, err
}

func (c *Client) doAuthentication(aclient *auth.AuthClient, variable []byte, q quorum.Quorum) (*packet.SignaturePacket, error) {
	nodes := q.Nodes()
	pdata, err := aclient.Initiate(nodes)
	if err != nil {
		return nil, err
	}
	for phase := 0; !aclient.Done(phase); phase++ {
		mpkt := make([][]byte, len(nodes))
		for i, peer := range nodes {
			data, ok := pdata[peer.Id()]
			if !ok {
				continue
			}
			pkt, err := packet.SerializeAuthenticationRequest(phase, variable, data)
			if err != nil {
				return nil, err
			}
			mpkt[i] = pkt
		}
		var succ, failure []node.Node
		var errs []error
		pdata = nil
		c.tr.MulticastM(transport.Auth, nodes, mpkt, func(res *transport.MulticastResponse) bool {
			if res.Err == nil {
				pdata, err = aclient.ProcessResponse(phase, res.Data, res.Peer)
				if err == nil {
					succ = append(succ, res.Peer)
				}
				if pdata != nil {
					return true
				}
			} else {
				err = res.Err
			}
			if err != nil {
				errs = append(errs, err)
				failure = append(failure, res.Peer)
				return q.Reject(failure)
			}
			return false
		})
		if pdata == nil {
			return nil, majorityError(errs, crypto.ErrInsufficientNumberOfSecrets)
		}
		nodes = succ
	}
	var ss packet.SignaturePacket
	suff := false
	for _, data := range pdata {
		if sig, err := packet.ParseSignature(data); err == nil {
			suff = c.crypt.CollectiveSignature.Combine(&ss, sig, q)
			// go through all responses
		}
	}
	if !suff {
		return nil, crypto.ErrInsufficientNumberOfSignatures
	}
	return &ss, nil
}

func (c *Client) setupAuthenticationParameters(variable []byte, cred []byte, q quorum.Quorum) error {
	// self-sign over <x>
	tbs, err := packet.Serialize(variable, nil, uint64(0))
	if err != nil {
		return err
	}
	sig, err := c.crypt.Signature.Sign(tbs)
	if err != nil {
		return err
	}

	// send out auth params to each member of the quorum
	params, err := auth.GeneratePartialAuthenticationParams(cred, len(q.Nodes()), q.GetThreshold())
	if err != nil {
		return err
	}
	mpkt := make([][]byte, len(params))
	for i, param := range params {
		pkt, err := packet.Serialize(variable, nil, uint64(0), sig, nil, param)
		if err != nil {
			return err
		}
		mpkt[i] = pkt
	}
	var succ []node.Node
	c.tr.MulticastM(transport.SetAuth, q.Nodes(), mpkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			succ = append(succ, res.Peer)
		}
		return false // broadcast as many as possible
	})
	if !q.IsSufficient(succ) {
		return bftkv.ErrInsufficientNumberOfValidResponses
	}
	return nil
}

//
// distributed crypto
//

func (c *Client) Distribute(caname string, key interface{}) error {
	q := c.qs.ChooseQuorum(quorum.AUTH)
	k := q.GetThreshold()
	secrets, algo, err := c.threshold.Distribute(key, q.Nodes(), k)
	if err != nil {
		return err
	}
	mpkt := make([][]byte, len(secrets))
	for i, secret := range secrets {
		val := threshold.SerializeParams(algo, secret)
		pkt, err := packet.Serialize([]byte(caname), val) // do we need to sign?
		if err != nil {
			return err
		}
		mpkt[i] = pkt
	}
	succ := 0
	c.tr.MulticastM(transport.Distribute, q.Nodes(), mpkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			succ++
		}
		return false
	})
	if succ < k {
		return bftkv.ErrInsufficientNumberOfResponses
	}
	return nil
}

func (c *Client) DistSign(caname string, tbs []byte, algo crypto.ThresholdAlgo, hash gocrypto.Hash) (sig []byte, err error) {
	proc, err := c.threshold.NewProcess(tbs, algo, hash)
	if err != nil {
		return nil, err
	}
	for {
		nodes, req, err := proc.MakeRequest()
		if err != nil {
			return nil, err
		}
		if nodes == nil || len(nodes) == 0 {
			return nil, bftkv.ErrInsufficientNumberOfResponses
		}
		pkt, err := packet.Serialize([]byte(caname), req)
		if err != nil {
			return nil, err
		}
		var sig []byte
		succ := 0
		c.tr.Multicast(transport.DistSign, nodes, pkt, func(res *transport.MulticastResponse) bool {
			if res.Err == nil && res.Data != nil {
				succ++
				sig, err = proc.ProcessResponse(res.Data, res.Peer)
				return sig != nil || err != nil
			}
			return false
		})
		if err == crypto.ErrContinue {
			continue
		}
		if sig != nil || err != nil {
			return sig, err
		}
		if succ == 0 { // no more new responses
			return nil, bftkv.ErrInsufficientNumberOfResponses
		}
	}
}
