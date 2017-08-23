// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"io"
	"bytes"
	"encoding/binary"
	"net/url"
	"log"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
	"github.com/yahoo/bftkv/storage"
	"github.com/yahoo/bftkv/packet"
)

type Server struct {
	Protocol
	st storage.Storage
}

const maxTimestampDiff = 100	// to avoid to intentionally cause overflow

func NewServer(self node.SelfNode, qs quorum.QuorumSystem, tr transport.Transport, crypt *crypto.Crypto, st storage.Storage) *Server {
	return &Server{
		Protocol: Protocol{
			self: self,
			qs: qs,
			tr: tr,
			crypt: crypt,
		},
		st: st,
	}
}

func (s *Server) Start() error {
	// start the server first
	if addr := s.self.Address(); addr != "" {
		if u, err := url.Parse(addr); err == nil {
			addr = ":" + u.Port()	// @@ go.http accept ":" as a port when the host doesn't include the port number?
		}
		s.tr.Start(s, addr)
		log.Printf("Server @ %s running\n", addr)
	}
	return nil
}

func (s *Server) Stop() {
	s.Leaving()	// leave from the network
	s.tr.Stop()
}

func (s *Server) join(req []byte, peer node.Node) ([]byte, error) {
	if peer != nil && peer.Id() == s.self.Id() {	// avoid to overwrite the self node
		log.Printf("server [%s]: joining to itself?\n", peer.Name())
		return nil, nil	// nothing to return
	}
	nodes, err := s.crypt.Certificate.Parse(req)
	if err != nil {
		// reject
		return nil, err
	}

	// @@ accept any certificate unless it's been revoked
	nodes = s.self.AddPeers(nodes)
	if err := s.crypt.Keyring.Register(nodes, false, false); err != nil {
		s.self.RemovePeers(nodes)	// to be consistent
		return nil, err
	}
	
	// return the node regardless of the result
	// nodes can send both self cert and other certs signed by itself to tell the joining node that it trusts them
	var buf bytes.Buffer
	err = s.self.SerializeNodes(&buf)
	if err != nil {
		return nil, err		// keep it in the graph and keyring
	}
	return buf.Bytes(), nil
}

func (s *Server) leave(req []byte, peer node.Node) ([]byte, error) {
	nodes, err := s.crypt.Certificate.Parse(req)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if peer != nil && n.Id() == peer.Id() {
			s.self.RemovePeers([]node.Node{n})
			// do not remove the key from the key ring here
		}
	}
	// no response
	return nil, nil
}

func (s *Server) time(req []byte, peer node.Node) ([]byte, error) {
	variable := req
	t := uint64(0)
	tvs, err := s.st.Read(variable, 0)
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
	}
	if err == nil {
		_, _, _, t, _, err = packet.Parse(tvs)
		if err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, t)
	return buf.Bytes(), nil
}

func (s *Server) read(req []byte, peer node.Node) ([]byte, error) {
	variable := req
	tvs, err := s.st.Read(variable, 0)	// get the latest one
	if err != nil && err != storage.ErrNotFound {
		return nil, err
	}
	if tvs != nil {
		// check to see if tvs has ss, which means the write process has completed
		_, _, _, t, ss, err := packet.Parse(tvs)
		if err != nil {
			return nil, err
		}
		if ss == nil || !ss.Completed {	// got a sign request but haven't gotten a write request
			// find the latest one that has ss
			tvs = nil
			for t--; t > 0; t-- {
				ttvs, err := s.st.Read(variable, t)
				if err == nil && tvs != nil {
					_, _, _, _, ss, err := packet.Parse(tvs)
					if err == nil && ss != nil && ss.Completed {
						tvs = ttvs
						break
					}
				}
			}
		}
	}
	return tvs, nil
}

func (s *Server) sign(req []byte, peer node.Node) ([]byte, error) {
	variable, val, sig, t, ss, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if sig == nil || ss == nil {
		return nil, bftkv.ErrMalformedRequest
	}

	// verify the signature with the quorum certs
	issuer := s.crypt.Signature.Issuer(sig)
	if issuer == nil {
		return nil, crypto.ErrCertificateNotFound
	}
	tbs, err := packet.TBS(req)
	if err != nil {
		return nil, err
	}
	if err := s.crypt.Signature.VerifyWithCertificate(tbs, sig, issuer); err != nil {
		return nil, err
	}
	// check the certs part
	q := s.qs.ChooseQuorum(quorum.AUTH | quorum.CERT)
	if !q.IsThreshold(s.crypt.Certificate.Signers(issuer)) {
		return nil, bftkv.ErrInvalidQuorumCertificate
	}

	rdata, err := s.st.Read(variable, 0)	// read the latest one
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
		rdata = nil
	}

	if rdata != nil {
		// the variable already exists
		_, rval, _, rt, rss, err := packet.Parse(rdata)
		if err != nil {
			return nil, err
		}

		// make sure that it does not sign both <x, v, t> and <x, v', t>
		d := t - rt
		if d == 0 && !bytes.Equal(val, rval) {
			// revoke the issuers if they are the same
			if s.revokeSigners(s.crypt.CollectiveSignature.Signers(ss), s.crypt.CollectiveSignature.Signers(rss)) {
				// @@ should remove <x, v, t> from the storage as well?
				return nil, bftkv.ErrEquivocation
			} else {
				return nil, bftkv.ErrInvalidSignRequest	// someone beat me
			}
		} else if d < 0 || d >= maxTimestampDiff {
			return nil, bftkv.ErrInvalidSignRequest
		}
	}

	// now sign the request
	tbss, err := packet.TBSS(req)
	if err != nil {
		return nil, err
	}
	ss, err = s.crypt.CollectiveSignature.Sign(tbss)
	if err != nil {
		return nil, err
	}
	// save <x, v, sig, t> to the storage before returning the signature
	if err := s.st.Write(variable, t, req); err != nil {	// no ss. To avoid to sign on another <x, t, v'>
		return nil, err
	}
	pkt, err := packet.SerializeSignature(ss)
	if err != nil {
		return nil, err
	}
	return pkt, nil
}

func (s *Server) write(req []byte, peer node.Node) ([]byte, error) {
	variable, val, sig, t, ss, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if sig == nil || ss == nil {
		return nil, bftkv.ErrMalformedRequest
	}

	// check if sufficient number of quorum members have signed the same <x, v, t>
	tbss, err := packet.TBSS(req)
	if err != nil {
		return nil, err
	}
	if err := s.crypt.CollectiveSignature.Verify(tbss, ss, s.qs.ChooseQuorum(quorum.AUTH)); err != nil {
		return nil, err
	}

	rdata, err := s.st.Read(variable, 0)	// read the latest one, not with 't'
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
	}
	if rdata != nil {
		_, rval, rsig, rt, rss, err := packet.Parse(rdata)
		if err != nil {
			return nil, err
		}
		if t < rt || t - rt >= maxTimestampDiff {
			return nil, bftkv.ErrBadTimestamp
		} else if t == rt && !bytes.Equal(val, rval) {
			if rss != nil {
				s.revokeSigners(s.crypt.CollectiveSignature.Signers(ss), s.crypt.CollectiveSignature.Signers(rss))
			}
			// @@ should remove ss^rss from ss on the storage as well??
			return nil, bftkv.ErrEquivocation
		}

		// check the TOFU policy -- check if the signers are same
		// the signature and quorum cert have already been verified 
		newIssuer := s.crypt.Signature.Issuer(sig)
		prevIssuer := s.crypt.Signature.Issuer(rsig)
		if newIssuer == nil || prevIssuer == nil {
			return nil, crypto.ErrCertificateNotFound	// should not happen
		}
		if prevIssuer.Id() != newIssuer.Id() && prevIssuer.UId() != newIssuer.UId() {
			return nil, bftkv.ErrPermissionDenied
		}
	}

	if err := s.st.Write(variable, t, req); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Server) revokeSigners(signers1, signers2 []node.Node) bool {
	revoked := false
	m := make(map[uint64]bool)
	for _, issuer := range signers1 {
		m[issuer.Id()] = true
	}
	for _, issuer := range signers2 {
		if _, ok := m[issuer.Id()]; ok {
			s.self.Revoke(issuer)
			revoked = true
		}
	}
	if revoked {
		var buf bytes.Buffer
		if s.self.SerializeRevokedNodes(&buf) != nil {
			s.tr.Multicast(transport.Notify, s.self.GetPeers(), buf.Bytes(), nil)
		}
	}
	return revoked
}

func (s *Server) revoke(req []byte, peer node.Node) ([]byte, error) {
	nodes, err := s.crypt.Certificate.Parse(req)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if n.Id() == peer.Id() {
			s.self.Revoke(n)
		}
	}
	// no response
	return nil, nil
}

func (s *Server) notify(req []byte, peer node.Node) ([]byte, error) {
	// no-op
	return nil, nil
}

func (s *Server) Handler(cmd int, r io.Reader, w io.Writer) error {
	req, nonce, peer, err := s.crypt.Message.Decrypt(r)
	if err != nil {
		if cmd != transport.Join || req == nil {	// the requester's cert might not have been in the keyring. The cert will be verifie by quorums to join
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
		res, err = s.read(req, peer)
	case transport.Write:
		res, err = s.write(req, peer)
	case transport.Sign:
		res, err = s.sign(req, peer)
	case transport.Revoke:
		res, err = s.revoke(req, peer)
	case transport.Notify:
		res, err = s.notify(req, peer)
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
		peers = s.crypt.Keyring.GetKeyring()	// this should work only when cmd == Join and the peer's cert had not been registered
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
