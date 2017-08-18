// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/storage"
	"github.com/yahoo/bftkv/transport"
)

// need to duplicate malserver instance of revokesigners

type MalServer struct {
	Server
	malst MalStorage
}

func NewMalServer(self node.SelfNode, qs quorum.QuorumSystem, tr transport.Transport, crypt *crypto.Crypto, st MalStorage) *MalServer {
	return &MalServer{
		Server: Server{
			Protocol: Protocol{
				self:  self,
				qs:    qs,
				tr:    tr,
				crypt: crypt,
			},
			st: st,
		},
		malst: st,
	}
}

func (s *MalServer) Start() error {
	// start the server first
	if addr := s.self.Address(); addr != "" {
		if u, err := url.Parse(addr); err == nil {
			addr = ":" + u.Port()
		}
		s.tr.Start(s, addr)
		log.Printf("Server @ %s running\n", addr)
	}

	return s.Joining()
}

func (s *MalServer) signResult(req []byte, peer node.Node) ([]byte, error) {
	for _, url := range mal {
		if strings.Compare(s.self.Address(), url) == 0 {
			return s.malSign(req, peer)
		}
	}
	return s.sign(req, peer)
}

func (s *MalServer) malSign(req []byte, peer node.Node) ([]byte, error) {
	_, _, _, _, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}

	tbss, err := packet.TBSS(req)
	if err != nil {
		return nil, err
	}
	/*
		if err := s.crypt.Signature.Verify(tv, sig); err != nil {
			return nil, err
		}
	*/
	ss, err := s.crypt.CollectiveSignature.Sign(tbss)
	if err != nil {
		return nil, err
	}

	pkt, err := packet.SerializeSignature(ss)
	if err != nil {
		return nil, err
	}
	return pkt, nil
}

func (s *MalServer) writeResult(req []byte, peer node.Node) ([]byte, error) {
	for _, url := range mal {
		if strings.Compare(s.self.Address(), url) == 0 {
			return s.malWrite(req, peer)
		}
	}
	return s.write(req, peer)
}

func (s *MalServer) malWrite(req []byte, peer node.Node) ([]byte, error) {
	variable, _, _, t, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}

	_, err1 := packet.TBS(req)
	if err1 != nil {
		return nil, err1
	}

	if err := s.malst.MalWrite(variable, t, req); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *MalServer) readResult(req []byte, peer node.Node) ([]byte, error) {
	for _, url := range mal {
		if strings.Compare(s.self.Address(), url) == 0 {
			return s.malRead(req, peer)
		}
	}
	return s.read(req, peer)
}

func (s *MalServer) malRead(req []byte, peer node.Node) ([]byte, error) {
	variable := req
	tvs, err := s.malst.MalRead(variable, 0)
	if err != nil && err != storage.ErrNotFound {
		// honest read intended
		return s.read(req, peer)
	}

	if tvs != nil {
		_, _, _, _, ss, err := packet.Parse(tvs)
		if err != nil {
			return nil, err
		}
		if ss == nil || !ss.Completed {
			return nil, nil
		}
	}
	return tvs, nil
}

func (s *MalServer) Handler(cmd int, r io.Reader, w io.Writer) error {
	req, nonce, peer, err := s.crypt.Message.Decrypt(r)
	if err != nil {
		if cmd != transport.Join || req == nil {
			log.Printf("server [%s]: transport security error: %s\n", s.self.Name(), err)
			return err
		}
	}

	var res []byte
	switch cmd {
	case transport.Join:
		res, err = s.join(req, peer)
	case transport.Leave:
		res, err = s.leave(req, peer)
	case transport.Time:
		res, err = s.time(req, peer)
	case transport.Read:
		res, err = s.readResult(req, peer)
	case transport.Write:
		res, err = s.writeResult(req, peer)
	case transport.Sign:
		res, err = s.signResult(req, peer)
	case transport.Revoke:
		res, err = s.revoke(req, peer)
	default:
		err = bftkv.ErrUnknownCommand
	}
	if err != nil {
		log.Printf("server[%s]: error: %s\n", s.self.Name(), err)
		return err
		// should not call Close()
	}
	var peers []node.Node
	if peer == nil {
		peers = s.crypt.Keyring.GetKeyring()
		if peers == nil {
			return crypto.ErrCertificateNotFound
		}
	} else {
		peers = []node.Node{peer}
	}
	cipher, err := s.crypt.Message.Encrypt(peers, res, nonce)
	if err != nil {
		return err
	}
	_, err = w.Write(cipher)
	return err
}
