// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package node

import (
	"io"

	"github.com/yahoo/bftkv/crypto/cert"
)

type Node interface {
	cert.CertificateInstance
}

type SelfNode interface {
	Node

	SerializeSelf() ([]byte, error)
	AddPeers(nodes []Node) []Node
	GetPeers() []Node
	RemovePeers(nodes []Node)
	Revoke(node Node)

	SerializeNodes(w io.Writer) error
	SerializeRevokedNodes(w io.Writer) error
}
