// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package pgp

import (
	"io"
	"io/ioutil"
	"bytes"
	"bufio"
	"encoding/base64"
	"time"
	"regexp"
	"strings"
	"log"

	"golang.org/x/crypto/openpgp"
	pgp_packet "golang.org/x/crypto/openpgp/packet"

	"crypto/rand"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
	"github.com/yahoo/bftkv/quorum"
)


//
// Certificate Instance
//
type PGPCertificateInstance struct {
	entity *openpgp.Entity
	active bool
}

func newNode(e *openpgp.Entity) node.Node {
	return &PGPCertificateInstance{
		entity: e,
		active: true,
	}
}

func (c *PGPCertificateInstance) Id() uint64 {
	return c.entity.PrimaryKey.KeyId
}

func (c *PGPCertificateInstance) Name() string {
	re := regexp.MustCompile("([^<(]*)")
	for _, id := range c.entity.Identities {
		res := re.FindString(id.Name)
		if res != "" {
			return strings.TrimSpace(res)
		}
	}
	return ""
}

func (c *PGPCertificateInstance) Address() string {
	re := regexp.MustCompile("\\((.*://.*)\\)")
	for _, id := range c.entity.Identities {
		res := re.FindStringSubmatch(id.Name)
		if len(res) >= 2 {
			return res[1]
		}
	}
	return ""
}

func (c *PGPCertificateInstance) UId() string {
	re := regexp.MustCompile("<(.*)>")
	for _, id := range c.entity.Identities {
		res := re.FindStringSubmatch(id.Name)
		if len(res) >= 2 {
			return res[1]
		}
	}
	return c.Address()
}

func (c *PGPCertificateInstance) Signers() []uint64 {
	var signers []uint64
	for _, id := range c.entity.Identities {
		for _, s := range id.Signatures {
			signers = append(signers, *s.IssuerKeyId)
		}
	}
	return signers
}

func (c *PGPCertificateInstance) Serialize() ([]byte, error) {
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := c.entity.Serialize(w); err != nil {
		return nil, err
	}
	w.Flush()
	return b.Bytes(), nil
}

func (c *PGPCertificateInstance) Instance() interface{} {
	return c.entity
}

func (c *PGPCertificateInstance) SetActive(active bool) {
	c.active = active
}

func (c *PGPCertificateInstance) Active() bool {
	return c.active
}

//
// Keyring
//
type PGPKeyring struct {
	keyring openpgp.EntityList
	secring openpgp.EntityList
	self openpgp.EntityList
}

func NewKeyring() crypto.Keyring {
	return &PGPKeyring{}
}

func replace(ring openpgp.EntityList, nodes []node.Node) openpgp.EntityList {
	targets := make(map[uint64]*openpgp.Entity)
	for _, n := range nodes {
		targets[n.Id()] = n.Instance().(*openpgp.Entity)
	}
	for i, e := range ring {
		if n, exist := targets[e.PrimaryKey.KeyId]; exist {
			ring[i] = n
			delete(targets, e.PrimaryKey.KeyId)
		}
	}
	for _, e := range targets {
		ring = append(ring, e)
	}
	return ring
}

func (k *PGPKeyring) Register(nodes []node.Node, priv bool, self bool) error {
	if priv {
		k.secring = replace(k.secring, nodes)
	} else {
		k.keyring = replace(k.keyring, nodes)
		if self {
			k.self = replace(k.self, nodes[0:1])	// @@ the first one must be self
		}
	}
	return nil
}

func (k *PGPKeyring) Remove(nodes []node.Node) {
	targets := make(map[uint64]bool)
	for _, n := range nodes {
		targets[n.Id()] = true
	}
	var newKeyring openpgp.EntityList
	for _, e := range k.keyring {
		if _, ok := targets[e.PrimaryKey.KeyId]; !ok {
			newKeyring = append(newKeyring, e)
		}
	}
	k.keyring = newKeyring
	// remove from the self certs as well
	newKeyring = nil
	for _, e := range k.self {
		if _, ok := targets[e.PrimaryKey.KeyId]; !ok {
			newKeyring = append(newKeyring, e)
		}
	}
	k.self = newKeyring
}

func (k *PGPKeyring) GetCertById(id uint64) node.Node {
	e := k.getCertById(id)
	if e == nil {
		return nil
	}
	return newNode(e)
}

func (k *PGPKeyring) GetKeyring() []node.Node {
	var nodes []node.Node
	for _, e := range k.keyring {
		nodes = append(nodes, newNode(e))
	}
	return nodes
}

func (k *PGPKeyring) getKeyring() openpgp.EntityList {
	return append(k.secring, k.keyring...)
}

func (k *PGPKeyring) getPrivateKey() *openpgp.Entity {
	if len(k.secring) == 0 {
		return nil
	}
	return k.secring[0]
}

func (k *PGPKeyring) getCertById(id uint64) *openpgp.Entity {
	for _, e := range k.keyring {
		if e.PrimaryKey.KeyId == id {
			return e
		}
	}
	// in the case for self encrypting
	for _, e := range k.secring {
		if e.PrimaryKey.KeyId == id {
			return e
		}
	}
	return nil
}

func (k *PGPKeyring) getSelfCertificate() openpgp.EntityList {
	return k.self
}

//
// Certificate
// 
type PGPCertificate struct {
	keyring *PGPKeyring
}

func NewCertificate(keyring crypto.Keyring) crypto.Certificate {
	return &PGPCertificate{keyring.(*PGPKeyring)}
}

func (c *PGPCertificate) Parse(pkt []byte) ([]node.Node, error) {
	// openpgp.ReadKeyRing() might be used??
	r := bytes.NewReader(pkt)
	packets := pgp_packet.NewReader(r)
	var nodes []node.Node
	for {
		entity, err := openpgp.ReadEntity(packets);
		if err != nil {
			break
		}
		nodes = append(nodes, newNode(entity))
	}
	return nodes, nil
}

func (c *PGPCertificate) ParseStream(r io.Reader) ([]node.Node, error) {
	entities, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}
	var nodes []node.Node
	for _, e := range entities {
		nodes = append(nodes, newNode(e))
	}
	return nodes, nil
}

func (c *PGPCertificate) Signers(signee node.Node) []node.Node {
	var signers []node.Node
	for _, id := range signee.Signers() {
		n := c.keyring.GetCertById(id)
		if n != nil {
			signers = append(signers, n)
		}
	}
	return signers
}

func (c *PGPCertificate) Sign(signee node.Node) error {
	signer := c.keyring.getPrivateKey()
	if signer == nil {
		return crypto.ErrKeyNotFound
	}
	e := signee.(*PGPCertificateInstance).entity
	id := ""
	for i, _ := range e.Identities {
		id = i
		break	// use the first one
	}
	if id == "" {
		return crypto.ErrCertificateNotFound
	}
	if e.SignIdentity(id, signer, nil) != nil {
		return crypto.ErrSigningFailed
	}
	return nil
}

func (c *PGPCertificate) Merge(target node.Node, sub node.Node) error {
	et := target.(*PGPCertificateInstance).entity
	es := sub.(*PGPCertificateInstance).entity
	for i, tid := range et.Identities {
		sid, ok := es.Identities[i]
		if !ok {
			continue
		}
		tid.Signatures = append(tid.Signatures, sid.Signatures...)
	}
	return nil
}

//
// Signature
//
type PGPSignature struct {
	keyring *PGPKeyring
	cert *PGPCertificate
}

func NewSignature(keyring crypto.Keyring, cert crypto.Certificate) crypto.Signature {
	return &PGPSignature{keyring.(*PGPKeyring), cert.(*PGPCertificate)}
}

func (s *PGPSignature) Verify(tbs []byte, sig *packet.SignaturePacket) error {
	// go through all signatures
	r := bytes.NewReader(sig.Data)
	err := crypto.ErrInvalidSignature	// at least we need one valid signature
	for r.Len() > 0 {
		_, err = openpgp.CheckDetachedSignature(s.keyring.getKeyring(), bytes.NewReader(tbs), r)
		if err != nil {
			return crypto.ErrInvalidSignature
		}
	}
	return err
}

func (s *PGPSignature) VerifyWithCertificate(tbs []byte, sig *packet.SignaturePacket, cert node.Node) error {
	keyring := openpgp.EntityList{cert.(*PGPCertificateInstance).entity}
	// go through all signatures
	r := bytes.NewReader(sig.Data)
	err := crypto.ErrInvalidSignature	// at least we need one valid signature
	for r.Len() > 0 {
		_, err = openpgp.CheckDetachedSignature(keyring, bytes.NewReader(tbs), r)
		if err != nil {
			return crypto.ErrInvalidSignature
		}
	}
	return err
}

func (s *PGPSignature) Sign(tbs []byte) (*packet.SignaturePacket, error) {
	priv := s.keyring.getPrivateKey()
	if priv == nil {
		return nil, crypto.ErrCertificateNotFound
	}
	var w bytes.Buffer
	r := bytes.NewReader(tbs)
	if err := openpgp.DetachSign(&w, priv, r, nil); err != nil {
		return nil, crypto.ErrSigningFailed
	}
	sig := w.Bytes()
	var w2 bytes.Buffer
	for _, self := range s.keyring.getSelfCertificate() {
		if err := self.Serialize(&w2); err != nil {
			return nil, err
		}
	}
	cert := w2.Bytes()
	return &packet.SignaturePacket{
		Type: packet.SignatureTypePGP,
		Version: 0,
		Completed: false,
		Data: sig,
		Cert: cert,
	}, nil
}

func (s *PGPSignature) Signers(sig *packet.SignaturePacket) []node.Node {
	var nodes []node.Node
	r := pgp_packet.NewReader(bytes.NewReader(sig.Data))
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		switch p := p.(type) {
		case *pgp_packet.Signature:
			e := s.keyring.getCertById(*p.IssuerKeyId)	// @@ we need to explicitly specify to use the primary key to sign <x, t, v>
			if e != nil {
				nodes = append(nodes, newNode(e))
			}
		}
	}
	return nodes
}

func (s *PGPSignature) Certs(sig *packet.SignaturePacket) ([]node.Node, error) {
	return s.cert.Parse(sig.Cert)
}

func (s *PGPSignature) Issuer(sig *packet.SignaturePacket) node.Node {
	if sig.Cert == nil || len(sig.Cert) == 0 {
		return nil
	}
	nodes, err := s.Certs(sig)
	if err != nil || len(nodes) == 0 {
		return nil
	}
	return nodes[0]		// has to be the first one
}


//
// message stream
//
type PGPMessage struct {
	keyring *PGPKeyring
}

func NewMessage(keyring crypto.Keyring) crypto.Message {
	return &PGPMessage{keyring.(*PGPKeyring)}
}

func (msg *PGPMessage) Encrypt(peers []node.Node, plain []byte, nonce []byte) ([]byte, error) {
	priv := msg.keyring.getPrivateKey()
	if priv == nil {
		return nil, crypto.ErrCertificateNotFound
	}
	var to []*openpgp.Entity
	for _, peer := range peers {
		to = append(to, peer.Instance().(*openpgp.Entity))
	}
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	plainWriter, err := openpgp.Encrypt(w, to, priv, &openpgp.FileHints{true, base64.StdEncoding.EncodeToString(nonce), time.Unix(0, 0)}, nil)
	if err != nil {
		return nil, crypto.ErrEncryptionFailed
	}
	plainWriter.Write(plain)
	plainWriter.Close()
	w.Flush()
	return b.Bytes(), nil
}

func (msg *PGPMessage) EncryptStream(w io.Writer, peerId uint64, nonce []byte) (plainWriter io.WriteCloser, err error) {
	priv := msg.keyring.getPrivateKey()
	e := msg.keyring.getCertById(peerId)
	if priv == nil || e == nil {
		return nil, crypto.ErrCertificateNotFound
	}
	to := []*openpgp.Entity{e}
	plainWriter, err = openpgp.Encrypt(w, to, priv, &openpgp.FileHints{true, base64.StdEncoding.EncodeToString(nonce), time.Unix(0, 0)}, nil)
	if err != nil {
		return nil, crypto.ErrEncryptionFailed
	}
	return plainWriter, nil
}

func (msg *PGPMessage) Decrypt(body io.Reader) (plain []byte, nonce []byte, peer node.Node, err error) {
	m, err := openpgp.ReadMessage(body, msg.keyring.getKeyring(), nil, nil)
	if err != nil {
		return nil, nil, nil, crypto.ErrDecryptionFailed
	}
	if !(m.IsEncrypted && m.IsSigned) {	// m.IsSignedBy might be nil in the case we haven't had the signer's key in the keyring yet
		return nil, nil, nil, crypto.ErrInvalidTransportSecurityData
	}
	plain, err = ioutil.ReadAll(m.UnverifiedBody)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce, err = base64.StdEncoding.DecodeString(m.LiteralData.FileName)
	if err != nil {
		return nil, nil, nil, err
	}
	peer = msg.keyring.GetCertById(m.SignedByKeyId)	// peer might be nil
	return plain, nonce, peer, m.SignatureError	// @@ need to confirm SignedByKeyId is always the primary key ID regardless of what sub key is used
}


//
// simple collective signature
//

type PGPCollectiveSignature struct {
	signature *PGPSignature
}

func NewCollectiveSignature(signature crypto.Signature) crypto.CollectiveSignature {
	return &PGPCollectiveSignature{signature.(*PGPSignature)}
}

func (cs *PGPCollectiveSignature) Verify(tbs []byte, ss *packet.SignaturePacket, q quorum.Quorum) error {
	r := bytes.NewReader(ss.Data)
	keyring := cs.signature.keyring.getKeyring()
	var verified []node.Node
	for r.Len() > 0 {
		signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(tbs), r)
		if err == nil {
			verified = append(verified, newNode(signer))
			if q.IsSufficient(verified) {
				ss.Completed = true
				return nil
			}
		}
	}
	return crypto.ErrInsufficientNumberOfSignatures
}

func (cs *PGPCollectiveSignature) Sign(tbs []byte) (partialSignature *packet.SignaturePacket, err error) {
	return cs.signature.Sign(tbs)
}

func (cs *PGPCollectiveSignature) Combine(ss *packet.SignaturePacket, s *packet.SignaturePacket, q quorum.Quorum) bool {
	if ss.Type == packet.SignatureTypeNil {
		ss.Type = s.Type
	} else if ss.Type != s.Type {
		return false
	}
	ss.Data = append(ss.Data, s.Data...)
	signers := cs.signature.Signers(ss)
	return q.IsSufficient(signers)
}

func (cs *PGPCollectiveSignature) Signers(ss *packet.SignaturePacket) []node.Node {
	return cs.signature.Signers(ss)
}

//
// data encryption
//

type DataEncryption struct {
}

func NewDataEncryption() crypto.DataEncryption {
	return &DataEncryption{}
}

func (e *DataEncryption) Encrypt(key []byte, plain []byte) ([]byte, error) {
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	pw, err := openpgp.SymmetricallyEncrypt(w, key, nil, nil)
	if err != nil {
		return nil, err
	}
	pw.Write(plain)
	pw.Close()
	w.Flush()
	return b.Bytes(), nil
}

func (e *DataEncryption) Decrypt(key []byte, cipher []byte) ([]byte, error) {
	m, err := openpgp.ReadMessage(bytes.NewReader(cipher), nil, func(keys []openpgp.Key, Symmetric bool) ([]byte, error) {
		return key, nil
	}, nil)
	plain, err := ioutil.ReadAll(m.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return plain, m.SignatureError
}

//
// rng
//
type PGPRng struct {
}

func NewRNG() crypto.RNG {
	return &PGPRng{}
}

func (r *PGPRng) Initialize(seed []byte) {
	// do nothing
}

func (r *PGPRng) Generate(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic(err)
	}
	return b
}

//
// PGP crypto
//

func New() *crypto.Crypto {
	instance := &crypto.Crypto{}
	instance.Keyring = NewKeyring()
	instance.Certificate = NewCertificate(instance.Keyring)
	instance.Signature = NewSignature(instance.Keyring, instance.Certificate)
	instance.Message = NewMessage(instance.Keyring)
	instance.CollectiveSignature = NewCollectiveSignature(instance.Signature)
	instance.DataEncryption = NewDataEncryption()
	instance.RNG = NewRNG()
	return instance
}
