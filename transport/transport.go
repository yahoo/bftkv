// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package transport

import (
	"bytes"
	"io"

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
	ErrTransportSecurity      = bftkv.NewError("transport: transport security error")
	ErrTransportNonceMismatch = bftkv.NewError("transport: nonce mismatch")
	ErrServerError            = bftkv.NewError("transport: server error")
	ErrNoAddress              = bftkv.NewError("transport: no address")
)

type MulticastResponse struct {
	Peer node.Node
	Data []byte
	Err  error
}

type TransportServer interface {
	Handler(cmd int, r io.Reader, w io.Writer) error
}

type Transport interface {
	Multicast(path int, peers []node.Node, data []byte, cb func(res *MulticastResponse) bool)
	MulticastM(path int, peers []node.Node, mdata [][]byte, cb func(res *MulticastResponse) bool)
	Start(o TransportServer, addr string)
	Stop()

	// internal use
	Post(addr string, msg io.Reader) (res io.ReadCloser, err error)
	GenerateRandom() []byte
	Encrypt(peers []node.Node, plain []byte, nonce []byte) (cipher []byte, err error)
	Decrypt(r io.Reader) (plain []byte, nonce []byte, peer node.Node, err error)
}

func Multicast(tr Transport, path int, peers []node.Node, mdata [][]byte, cb func(res *MulticastResponse) bool) {
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
	ch := make(chan (*MulticastResponse), len(peers))
	var cipher []byte
	var nonce []byte
	var err error
	for i, peer := range peers {
		if i < len(mdata) {
			nonce = tr.GenerateRandom()
			cipher, err = tr.Encrypt(peers[i:i+len(peers)-len(mdata)+1], mdata[i], nonce)
			if err != nil {
				ch <- &MulticastResponse{peer, nil, err}
				continue
			}
		}
		go func(peer node.Node, cipher []byte, nonce []byte) {
			if peer.Address() == "" {
				ch <- &MulticastResponse{peer, nil, ErrNoAddress}
				return
			}
			var plain []byte
			r, err := tr.Post(peer.Address()+Prefix+cmd, bytes.NewReader(cipher))
			if err == nil {
				var t []byte
				plain, t, _, err = tr.Decrypt(r)
				r.Close()
				if err == nil && !bytes.Equal(t, nonce) {
					err = ErrTransportNonceMismatch
					plain = nil
				}
			}
			ch <- &MulticastResponse{peer, plain, err} // Node is always available
		}(peer, cipher, nonce)
	}
	for i := 0; i < len(peers); i++ {
		mr := <-ch
		if cb != nil {
			if cb(mr) {
				break // should cancel the remaining Post requests?
			}
		}
	}
}
