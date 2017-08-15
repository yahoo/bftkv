// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package quorum

import (
	"github.com/yahoo/bftkv/node"
)

const (
	READ = 0x01
	WRITE = 0x02
	AUTH = 0x04
)

type Quorum interface {
	Nodes() []node.Node
	IsQuorum(nodes []node.Node) bool
	IsThreshold(nodes []node.Node) bool
	IsSufficient(nodes []node.Node) bool
	Reject(nodes []node.Node) bool
}

type QuorumSystem interface {
	ChooseQuorum(rw int) Quorum
	GetQuorum(rw int, s node.Node) Quorum
}
