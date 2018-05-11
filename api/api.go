// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package api

import (
	"os"
	gocrypto "crypto"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/protocol"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/quorum/wotqs"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/transport"
	transport_http "github.com/yahoo/bftkv/transport/http"
)

type API struct {
	path string
	client *protocol.Client
	g *graph.Graph
	crypt *crypto.Crypto
	qs quorum.QuorumSystem
	tr transport.Transport
}

func OpenClient(path string) (*API, error) {
	api := &API{
		path: path,
		client: nil,
		g: graph.New(),
		crypt: pgp.New(),
	}
	if _, err := api.readCerts(path + "/pubring.gpg", false, true); err != nil {
		return nil, err
	}
	if _, err := api.readCerts(path + "/secring.gpg", true, true); err != nil {
		return nil, err
	}

	// make a quorum system from the graph
	api.qs = wotqs.New(api.g)
	api.tr = transport_http.New(api.crypt)
	api.client = protocol.NewClient(node.SelfNode(api.g), api.qs, api.tr, api.crypt)
	if err := api.client.Joining(); err != nil {
		return nil, err
	}
	return api, nil
}

func (api *API) CloseClient() {
	api.client.Leaving()
}

func (api *API) signPeers(certs []string) error {
	for _, cert := range certs {
		if peers, err := api.readCerts(cert + "/pubring.gpg", false, false); err == nil {
			// make an edge: self -> cert
			if len(peers) > 0 {
				if err := api.crypt.Certificate.Sign(peers[0]); err == nil {
					api.g.AddNodes(peers[0:1])
				}
			}
		}
	}
	return nil
}

func (api *API) Register(certs []string, password string) error {
	// support PGP certs only
	if err := api.signPeers(certs); err != nil {
		return err
	}
	// read them into the graph
	if err := api.client.Joining(); err != nil {	// re-joining so the client can construct the full graph
		return err
	}
	// need to re-sign as Joining has overwritten some nodes
	if err := api.signPeers(certs); err != nil {
		return err
	}
	// now the quorum system should work even if it is not completed yet

	self := node.SelfNode(api.g)
	variable := []byte(self.UId())

	proof, _, err := api.client.Authenticate(variable, []byte(password))
	if err != nil {
		return err
	}

	// do "register" and get back signed certs
	t := uint64(1)	// make sure it's no longer temporary
	cert, err := self.SerializeSelf()
	if err != nil {
		return err
	}
	tbs, err := packet.Serialize(variable, cert, t)
	if err != nil {
		return err
	}
	sig, err := api.crypt.Signature.Sign(tbs)
	if err != nil {
		return err
	}
	pkt, err := packet.Serialize(variable, cert, t, sig, proof)	// use the value as the PGP cert
	if err != nil {
		return err
	}
	q := api.qs.ChooseQuorum(quorum.AUTH)
	var sigs []node.Node
	var succ []node.Node
	api.tr.Multicast(transport.Register, api.client.PeerNodes(q.Nodes()), pkt, func(res *transport.MulticastResponse) bool {
		if res.Err == nil {
			certs, err := api.crypt.Certificate.Parse(res.Data)
			if err == nil {
				sigs = append(sigs, certs...)
				succ = append(succ, res.Peer)
			}
		}
		return false	// collect signatures as many as possible
	})

	// accumulate all signatures into the self cert
	if !q.IsSufficient(succ) {
		return bftkv.ErrAuthenticationFailure
	}
	selfNode := api.crypt.Keyring.GetCertById(self.Id())
	for _, sig := range sigs {
		api.crypt.Certificate.Merge(selfNode, sig)
	}

	// re-set the self node
	nodes := []node.Node{selfNode}
	api.g.AddNodes(nodes)
	// renew the self cert
	api.crypt.Keyring.Remove(nodes)
	if err := api.crypt.Keyring.Register(nodes, false, true); err != nil {
		return err
	}
	return nil
}

func (api *API) Write(variable []byte, value []byte, password string) (err error) {
	var proof *packet.SignaturePacket
	if password != "" {
		var key []byte
		proof, key, err = api.client.Authenticate(variable, []byte(password))
		if err != nil {
			return err
		}
		value, err = api.crypt.DataEncryption.Encrypt(key, value)
		if err != nil {
			return err
		}
	}
	return api.client.Write(variable, value, proof)
}

func (api *API) Read(variable []byte, password string) (value []byte, err error) {
	var proof *packet.SignaturePacket
	var key []byte
	if password != "" {
		proof, key, err = api.client.Authenticate(variable, []byte(password))
		if err != nil {
			return nil, err
		}
	}
	value, err = api.client.Read(variable, proof)
	if err != nil {
		return nil, err
	}
	if key != nil {
		value, err = api.crypt.DataEncryption.Decrypt(key, value)
		if err != nil {
			return nil, err
		}
	}
	return value, nil
}

func (api *API) UpdateCert() error {
	path := api.path + "/pubring.gpg"
	err := os.Rename(path, path + "~")
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	err = api.g.SerializeNodes(f)
	f.Close()
	if err != nil {
		os.Rename(path + "~", path)
	}
	return err
}

func (api *API) readCerts(path string, sec bool, self bool) ([]node.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	certs, err := api.crypt.Certificate.ParseStream(f)
	if err != nil {
		return nil, err
	}
	if self {
		if sec {
			api.g.SetSelfNodes(certs)
		} else {
			api.g.AddNodes(certs)
		}
		if err := api.crypt.Keyring.Register(certs, sec, self); err != nil {
			return nil, err
		}
	}
	return certs, nil
}

func (api *API) Distribute(caname string, key interface{}) error {
	return api.client.Distribute(caname, key)
}

func (api *API) Sign(caname string, tbs []byte, algo crypto.ThresholdAlgo, dgst gocrypto.Hash) (sig []byte, err error) {
	return api.client.DistSign(caname, tbs, algo, dgst)
}

func (api *API) UId() string {
	self := node.SelfNode(api.g)
	return self.UId()
}
