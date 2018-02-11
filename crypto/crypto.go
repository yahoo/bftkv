// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package crypto

import (
	"io"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/packet"
)

var (
	ErrCertificateNotFound = bftkv.NewError("crypto: certifiate not found")
	ErrKeyNotFound = bftkv.NewError("crypto: key not found")
	ErrInvalidTransportSecurityData = bftkv.NewError("crypto: invalid transport security data")
	ErrInsufficientNumberOfSignatures = bftkv.NewError("crypto: insufficient number of signatures")
	ErrInvalidSignature = bftkv.NewError("crypto: invalid signature")
	ErrSigningFailed = bftkv.NewError("crypto: failed to sign")
	ErrEncryptionFailed = bftkv.NewError("crypto: failed to encrypt")
	ErrDecryptionFailed = bftkv.NewError("crypto: failed to decrypt")
	ErrInsufficientNumberOfSecrets = bftkv.NewError("crypto: insufficient number of secrets")
	ErrInvalidInput = bftkv.NewError("crypto: invalid input")
	ErrNoAuthenticationData = bftkv.NewError("crypto: no authentication data")
	ErrUnsupported = bftkv.NewError("crypto: unsupported algorithm")
	ErrInsufficientNumberOfThresholdSignatures = bftkv.NewError("crypto: insufficient number of threshold signatures")
)

type Keyring interface {
	Register(nodes []node.Node, priv bool, self bool) error
	Remove(node []node.Node)
	GetCertById(id uint64) node.Node
	GetKeyring() []node.Node
}

type Certificate interface {
	Parse(pkt []byte) ([]node.Node, error)
	ParseStream(r io.Reader) ([]node.Node, error)
	Signers(signee node.Node) []node.Node
	Sign(signee node.Node) error
	Merge(cert node.Node, sub node.Node) error
}

type Signature interface {
	// signature includes the signers (IDs or certificates)
	Verify(tbs []byte, sig *packet.SignaturePacket) error
	VerifyWithCertificate(tbs []byte, sig *packet.SignaturePacket, cert node.Node) error
	Sign(tbs []byte) (*packet.SignaturePacket, error)
	Signers(sig *packet.SignaturePacket) []node.Node		// return only nodes that have been verified
	Issuer(sig *packet.SignaturePacket) node.Node
	Certs(sig *packet.SignaturePacket) ([]node.Node, error)
}

type Message interface {
	Encrypt(peers []node.Node, plain []byte, nonce []byte) (cipher []byte, err error)
	EncryptStream(out io.Writer, peerId uint64, nonce []byte) (in io.WriteCloser, err error)
	Decrypt(body io.Reader) (plain []byte, nonce []byte, peer node.Node, err error)
}

type CollectiveSignature interface {
	Verify(tbs []byte, ss *packet.SignaturePacket, q quorum.Quorum) error
	Sign(tbs []byte) (partialSignature *packet.SignaturePacket, err error)
	Combine(ss *packet.SignaturePacket, s *packet.SignaturePacket, q quorum.Quorum) bool
	Signers(ss *packet.SignaturePacket) []node.Node
}

type AuthenticationClient interface {
	GenerateAuthenticationData() ([]byte, error)
	ProcessAuthResponse(res []byte, id uint64) (bool, error)
	GetAuxData(id uint64) ([]byte, error)
	GetCipherKey() ([]byte, error)
}

type Authentication interface {
	GeneratePartialAuthenticationParams(cred []byte, n, k int) ([][]byte, error)
	MakeResponse(ss []byte, challenge []byte, plain []byte) (res []byte, err error)
	NewClient(cred []byte, n, k int) AuthenticationClient
}

type DataEncryption interface {
	Encrypt(key []byte, plain []byte) ([]byte, error)
	Decrypt(key []byte, cipher []byte) ([]byte, error)
}

type RNG interface {
	Initialize(seed []byte)
	Generate(n int) []byte
}

type ThresholdProcess interface {
	MakeRequest() ([]node.Node, []byte, error)
	ProcessResponse(res []byte, id uint64) ([]byte, error)
}

type Crypto struct {
	Keyring Keyring
	Certificate Certificate
	Signature Signature
	Message Message
	CollectiveSignature CollectiveSignature
	DataEncryption DataEncryption
	RNG RNG
	Authentication Authentication
}
