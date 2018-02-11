// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package transport

import (
	"io"
	"bytes"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/node"
)

const (
	Join = iota
	Leave
	Time
	Read
	Write
	Sign
	Auth
	SetAuth
	Distribute
	DistSign
	Register
	Revoke
	Notify
)

// notification
const (
	NetworkConfigChanged = 0
)

const Prefix = "/bftkv/v1/"

var (
	ErrTransportSecurity = bftkv.NewError("transport: transport security error")
	ErrTransportNonceMismatch = bftkv.NewError("transport: nonce mismatch")
	ErrServerError = bftkv.NewError("transport: server error")
	ErrNoAddress = bftkv.NewError("transport: no address")
)

type MulticastResponse struct {
	Peer node.Node
	Data []byte
	Err error
}

type TransportServer interface {
	Handler(cmd int, r io.Reader, w io.Writer) error
}

type Transport interface {
	Multicast(path int, peers []node.Node, data []byte, cb func(res *MulticastResponse) bool)
	Start(o TransportServer, addr string)
	Stop()

	// internal use
	Post(addr string, msg io.Reader) (res io.ReadCloser, err error)
	GenerateRandom() []byte
	Encrypt(peers []node.Node, plain []byte, nonce []byte) (cipher []byte, err error)
	Decrypt(r io.Reader) (plain []byte, nonce []byte, peer node.Node, err error)
}

func Multicast(tr Transport, path int, peers []node.Node, data []byte, cb func(res *MulticastResponse) bool) {
	cmd := ""
	switch path {
	case Join:
		cmd = "join"
	case Leave:
		cmd = "leave"
	case Time:
		cmd = "time"
	case Read:
		cmd = "read"
	case Write:
		cmd = "write"
	case Sign:
		cmd = "sign"
	case Auth:
		cmd = "auth"
	case SetAuth:
		cmd = "setauth"
	case Distribute:
		cmd = "distribute"
	case DistSign:
		cmd = "distsign"
	case Register:
		cmd = "register"
	case Revoke:
		cmd = "revoke"
	case Notify:
		cmd = "notify"
	}
	ch := make(chan(*MulticastResponse), len(peers))
	t1 := tr.GenerateRandom()
	cipher, err := tr.Encrypt(peers, data, t1)
	if err != nil {
		if cb == nil {
			return
		}
		for _, peer := range peers {
			if cb(&MulticastResponse{peer, nil, err}) {
				break
			}
		}
		return
	}
	for _, peer := range(peers) {
		go func(peer node.Node) {
			if peer.Address() == "" {
				ch <- &MulticastResponse{peer, nil, ErrNoAddress}
				return
			}
			var plain []byte
			r, err := tr.Post(peer.Address() + Prefix + cmd, bytes.NewReader(cipher))
			if err == nil {
				var t2 []byte
				plain, t2, _, err = tr.Decrypt(r)
				r.Close()
				if err == nil && !bytes.Equal(t1, t2) {
					err = ErrTransportNonceMismatch
					plain = nil
				}
			}
			ch <- &MulticastResponse{peer, plain, err}	// Node is always available
		}(peer)
	}
	for i := 0; i < len(peers); i++ {
		mr := <- ch
		if cb != nil {
			if cb(mr) {
				break	// should cancel the remaining Post requests?
			}
		}
	}
}
