// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package protocol

import (
	"io"
	"bytes"
	"encoding/binary"
	"net/url"
	"math"
	"time"
	"log"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/threshold"
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

type AuthHistory struct {
	t time.Time
	n int
}

const (
	AUTH_MIN_DURATION = (10 * time.Second)	// 10 sec
	AUTH_DELAY_RATE = (1 * time.Second)	// increase 1 sec per retry
	AUTH_RETRY_LIMIT = 10
	authHistoryPostfix = "......stayaway"
)

var hiddenPrefix = []byte("!!!secret!!!")
	
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

	var certs []node.Node
	if peer != nil {
		// accept only certificate from the peer
		for _, n := range nodes {
			if n.Id() == peer.Id() {
				certs = append(certs, n)
			}
		}
	} else if len(nodes) > 0 {
		// if it's the first time it sees the peer trust any cert
		if nodes[0].Id() == s.self.Id() {
			log.Printf("server [%s]: joining to itself?\n", nodes[0].Name())
			return nil, nil
		}
		certs = append(certs, nodes[0])
	}
	certs = s.self.AddPeers(certs)
	if err := s.crypt.Keyring.Register(certs, false, false); err != nil {
		s.self.RemovePeers(certs)	// to be consistent
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
	if bytes.HasPrefix(variable, hiddenPrefix) {
		return nil, bftkv.ErrPermissionDenied
	}
	tvs, err := s.st.Read(variable, 0)
	if err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
	}
	if err == nil {
		_, _, t, _, _, _, err = packet.Parse(tvs)
		if err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, t)
	return buf.Bytes(), nil
}

func (s *Server) read(req []byte, peer node.Node) ([]byte, error) {
	variable, _, _, _, proof, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(variable, hiddenPrefix) {
		return nil, bftkv.ErrPermissionDenied
	}
	tvs, err := s.st.Read(variable, 0)	// get the latest one
	if err != nil && err != storage.ErrNotFound {
		return nil, err
	}
	var auth []byte
	if tvs != nil {
		var ss *packet.SignaturePacket
		var t uint64
		// check to see if tvs has ss, which means the write process has completed
		_, _, t, _, ss, auth, err = packet.Parse(tvs)
		if err != nil {
			return nil, err
		}
		if ss == nil || !ss.Completed {	// got a sign request but haven't gotten a write request
			// find the latest one that has ss
			tvs = nil
			for t--; t > 0; t-- {
				ttvs, err := s.st.Read(variable, t)
				if err == nil && tvs != nil {
					_, _, _, _, ss, _, err = packet.Parse(tvs)
					if err == nil && ss != nil && ss.Completed {
						tvs = ttvs
						break
					}
				}
			}
		}
	}
	if auth != nil {
		if proof == nil || s.crypt.CollectiveSignature.Verify(variable, proof, s.qs.ChooseQuorum(quorum.AUTH)) != nil {
			return nil, bftkv.ErrAuthenticationFailure
		}
		// auth succeeded -- clear the history
		s.clearAuthHistory(variable)
	}
	return tvs, nil
}

func (s *Server) sign(req []byte, peer node.Node) ([]byte, error) {
	variable, val, t, sig, ss, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if sig == nil {
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

	var auth []byte
	if rdata != nil {
		// the variable already exists
		_, rval, rt, rsig, _, rauth, err := packet.Parse(rdata)
		if err != nil {
			return nil, err
		}

		// check the auth first
		if rauth != nil {
			if ss == nil {
				return nil, bftkv.ErrAuthenticationFailure
			}
			if s.crypt.CollectiveSignature.Verify(variable, ss, s.qs.ChooseQuorum(quorum.AUTH)) != nil {
				return nil, bftkv.ErrAuthenticationFailure
			}
			// auth succeeded -- clear the history
			s.clearAuthHistory(variable)
		}

		// make sure not to sign both <x, v, t> and <x, v', t>
		if rt == math.MaxUint64 {
			return nil, bftkv.ErrNoMoreWrite
		} else if t == rt && !bytes.Equal(val, rval) {
			// revoke the issuers if they are the same
			if s.revokeSigners(s.crypt.Signature.Signers(sig), s.crypt.Signature.Signers(rsig)) {
				// @@ should remove <x, v, t> from the storage as well?
				return nil, bftkv.ErrEquivocation
			} else {
				return nil, bftkv.ErrInvalidSignRequest	// someone beat me
			}
		} else if t < rt {
			return nil, bftkv.ErrBadTimestamp
		}
		auth = rauth	// inherit the auth params
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

	pkt, err := packet.SerializeSignature(ss)
	if err != nil {
		return nil, err
	}

	// save the request packet to the storage before returning the signature
	req, err = packet.Serialize(variable, val, t, sig, nil, auth)	// get rid of ss to tell it's not completed
	if err != nil {
		return nil, err
	}
	if err := s.st.Write(variable, t, req); err != nil {
		return nil, err
	}

	return pkt, nil
}

func (s *Server) write(req []byte, peer node.Node) ([]byte, error) {
	variable, val, t, sig, ss, _, err := packet.Parse(req)
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
		_, rval, rt, rsig, rss, rauth, err := packet.Parse(rdata)
		if err != nil {
			return nil, err
		}

		if rt == math.MaxUint64 {
			return nil, bftkv.ErrNoMoreWrite
		} else if t < rt {
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

		// inherit auth if exists
		if rauth != nil {
			req, err = packet.Serialize(variable, val, t, sig, ss, rauth)
			if err != nil {
				return nil, err
			}
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

func (s *Server) setAuth(req []byte, peer node.Node) ([]byte, error) {
	// receiving <varialble, nil, sig, 0, nil, auth>
	variable, _, t, sig, _, authdata, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if sig == nil || authdata == nil || t != 0 {
		return nil, bftkv.ErrMalformedRequest
	}

	// do not verify the signature here! just keep it with the auth data for the future use

	// can set the password to only virgin variables
	rdata, err := s.st.Read(variable, 0)
	if err == nil {
		_, _, rt, _, _, _, err := packet.Parse(rdata)
		if err == nil && rt != 0 {	// t == 0 temporary
			return nil, bftkv.ErrExist	// can't overwrite the password
		}
	} else if err != storage.ErrNotFound {
		return nil, bftkv.ErrAuthenticationFailure
	}

	// save the parameters temporarily -- it'll be settled when something is written with the correct password
	if err := s.st.Write(variable, 0, req); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Server) auth(req []byte, peer node.Node) ([]byte, error) {
	variable, authdata, err := packet.ParseAuthenticationRequest(req)
	if err != nil {
		return nil, err
	}
	rdata, err := s.st.Read(variable, 0)	// read the latest one
	if err != nil {
		return nil, crypto.ErrNoAuthenticationData
	}
	_, _, _, _, _, rauth, err := packet.Parse(rdata)
	if err != nil {
		return nil, err
	}
	if rauth == nil {
		return nil, crypto.ErrNoAuthenticationData
	}
	ss, err := s.crypt.CollectiveSignature.Sign(variable)	// @@ signing over only variables which means you can keep the proof for the later use
	if err != nil {
		return nil, err
	}
	sig, err := packet.SerializeSignature(ss)
	if err != nil {
		return nil, err
	}
	res, err := s.crypt.Authentication.MakeResponse(rauth, authdata, sig)
	if err != nil {
		return nil, err
	}

	// check and save the auth history
	hist, err := s.readAuthHistory(variable)
	if err == nil && time.Since(hist.t) < AUTH_MIN_DURATION {
		delay := time.Duration(hist.n) * AUTH_DELAY_RATE
		time.Sleep(delay)
		hist.n++
		if hist.n >= AUTH_RETRY_LIMIT {
			// at the moment just keep a log
			log.Printf("server[%s]: auth: too many retry from %s on %v\n", s.self.Name(), peer.Name(), variable)
		}
	} else {
		hist = &AuthHistory{time.Now(), 1}
	}
	s.writeAuthHistory(variable, hist)

	return res, nil
}

func (s *Server) register(req []byte, peer node.Node) ([]byte, error) {
	variable, value, t, sig, ss, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	if sig == nil || ss == nil {
		return nil, bftkv.ErrMalformedRequest
	}

	// check the self signed signature
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

	// check the proof
	if err := s.crypt.CollectiveSignature.Verify(variable, ss, s.qs.ChooseQuorum(quorum.AUTH)); err != nil {
		return nil, err
	}
	// auth succeeded -- clear the history
	s.clearAuthHistory(variable)

	var ret []byte
	certs, err := s.crypt.Certificate.Parse(value)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 {
		cert := certs[0]	// take the first one only
		if !bytes.Equal([]byte(cert.UId()), variable) {
			return nil, bftkv.ErrInvalidUserID
		}
		if err := s.crypt.Certificate.Sign(cert); err != nil {
			return nil, err
		}
		ret, err = cert.Serialize()
	}

	// save the request packet to settle the auth setup process
	var rauth []byte
	if rdata, err := s.st.Read(variable, 0); err != nil {
		if err != storage.ErrNotFound {
			return nil, err
		}
		rauth = nil
	} else {
		_, _, _, _, _, rauth, err = packet.Parse(rdata)
		if err != nil {
			return nil, err
		}
	}
	pkt, err := packet.Serialize(variable, value, t, sig, ss, rauth)
	if err != nil {
		return nil, err
	}
	if err := s.st.Write(variable, t, pkt); err != nil {
		return nil, err
	}
	return ret, err
}

func (s *Server) distribute(req []byte, peer node.Node) ([]byte, error) {
	variable, val, _, _, _, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	
	if err := s.st.Write(append(hiddenPrefix, variable...), 0, val); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Server) distSign(req []byte, peer node.Node) ([]byte, error) {
	variable, val, _, _, _, _, err := packet.Parse(req)
	if err != nil {
		return nil, err
	}
	params, err := s.st.Read(append(hiddenPrefix, variable...), 0)
	if err != nil {
		return nil, err
	}
	if params == nil {
		return nil, storage.ErrNotFound
	}
	return threshold.Sign(params, val)
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

func (s *Server) readAuthHistory(variable []byte) (*AuthHistory, error) {
	data, err := s.st.Read(append(variable, []byte(authHistoryPostfix)...), 0)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(data)
	var t int64
	if err := binary.Read(r, binary.BigEndian, &t); err != nil {
		return nil, err
	}
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	return &AuthHistory{time.Unix(t, 0), int(n)}, nil
}

func (s *Server) writeAuthHistory(variable []byte, hist *AuthHistory) error {
	var buf bytes.Buffer
	t := hist.t.Unix()
	if err := binary.Write(&buf, binary.BigEndian, t); err != nil {
		return err
	}
	n := uint32(hist.n)
	if err := binary.Write(&buf, binary.BigEndian, n); err != nil {
		return err
	}
	return s.st.Write(append(variable, []byte(authHistoryPostfix)...), 0, buf.Bytes())
}

func (s *Server) clearAuthHistory(variable []byte) error {
	return s.writeAuthHistory(variable, &AuthHistory{time.Now(), 0})
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
	case transport.Auth:
		res, err = s.auth(req, peer)
	case transport.SetAuth:
		res, err = s.setAuth(req, peer)
	case transport.Distribute:
		res, err = s.distribute(req, peer)
	case transport.DistSign:
		res, err = s.distSign(req, peer)
	case transport.Register:
		res, err = s.register(req, peer)
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
