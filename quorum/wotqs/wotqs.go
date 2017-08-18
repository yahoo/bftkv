// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package wotqs

import (
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
)

const (
	maxCliqueDistance = 2
)

type wot struct {
	g *graph.Graph
}

type qc struct {	// quarum clique
	nodes []node.Node
	f int
	min int
	threshold int
	suff int
}

type wotq struct {
	qcs []qc
	cert bool
}

func howmany(a, b int) int {
	return (a + b - 1) / b
}

func New(g *graph.Graph) quorum.QuorumSystem {
	return &wot{g: g}
}

func newQC(nodes []node.Node, rw int) *qc {
	n := len(nodes)
	if n == 0 {
		return nil
	}
	if rw == 0 {
		return &qc{nodes, 0, 0, 0, 0}
	}
	f := (n - 1) / 3
	if f >= 1 {
		min := 3 * f + 1
		threshold := 2 * f + 1
		suff := f + (n - f) / 2 + 1
		if (rw & quorum.CERT) != 0 {
			threshold = f + 1
		}
		return &qc{nodes, f, min, threshold, suff}
	} else {
		return nil
	}
}

func complement(u []node.Node, c []qc, e []qc, extra bool) []qc {
	var nodes []node.Node
	for _, n1 := range u {
		found := false
	next:
		for _, qc := range c {
			for _, n2 := range qc.nodes {
				if n1.Id() == n2.Id() {
					found = true
					break next
				}
			}
		}
		if !found {
			nodes = append(nodes, n1)
		}
	}
	if q := newQC(nodes, 0); q != nil {
		e = append(e, *q)
	}
	return e
}

func (qs *wot) getQuorumFrom(rw int, s uint64) *wotq {
	q := &wotq{}
	cliques := qs.g.GetCliques(s, maxCliqueDistance)
	for _, c := range cliques {
		if qc := newQC(c, rw); qc != nil {
			q.qcs = append(q.qcs, *qc)
		}
	}
	if (rw & quorum.AUTH) != 0 {
		// fall through
	}
	if (rw & (quorum.READ | quorum.WRITE)) != 0 {
		qcs := q.qcs
		if (rw & quorum.AUTH) == 0 {
			qcs = nil
		}
		qcs = complement(qs.g.GetReachableNodes(s, maxCliqueDistance + 1), q.qcs, qcs, false)	// R = {Vi} - {Ci}
		if (rw & quorum.WRITE) != 0 {
			qcs = complement(qs.g.GetPeers(), q.qcs, qcs, true)	// W = U - {Ci} + R
		}
		q.qcs = qcs
	}
	q.cert = (rw & quorum.CERT) != 0
	return q
}

func (qs *wot) ChooseQuorum(rw int) quorum.Quorum {
	return qs.getQuorumFrom(rw, qs.g.GetSelfId())
}

//
// quorum
// 
func (q *wotq) Nodes() []node.Node {
	var r []node.Node
	for _, qc := range q.qcs {
		for _, n := range qc.nodes {
			if n.Active() && n.Address() != "" {
				r = append(r, n)
			}
		}
	}
	return r
}

func (q *wotq) IsQuorum(nodes []node.Node) bool {
	// |nodes| >= 3f+1
	if len(q.qcs) == 0 {
		return false
	}
	for _, qc := range q.qcs {
		if qc.f > 0 && len(intersection(nodes, qc.nodes)) < qc.min {
			return false
		}
	}
	return true
}

func (q *wotq) IsThreshold(nodes []node.Node) bool {
	// |nodes| >= 2f+1
	if len(q.qcs) == 0 {
		return false
	}
	if q.cert {
		for _, qc := range q.qcs {
			if qc.f > 0 && len(intersection(nodes, qc.nodes)) >= qc.threshold {
				return true
			}
		}
		return false
	} else {
		for _, qc := range q.qcs {
			if qc.f > 0 && len(intersection(nodes, qc.nodes)) < qc.threshold {
				return false
			}
		}
		return true
	}
}

func (q *wotq) IsSufficient(nodes []node.Node) bool {
	if len(q.qcs) == 0 {
		return false
	}
	for _, qc := range q.qcs {
		if qc.f > 0 && len(intersection(nodes, qc.nodes)) < qc.suff {
			return false
		}
	}
	return true
}

func (q *wotq) Reject(nodes []node.Node) bool {
	for _, qc := range q.qcs {
		if qc.f > 0 && len(intersection(nodes, qc.nodes)) > qc.f {
			return true
		}
	}
	return false
}

func intersection(s1, s2 []node.Node) []node.Node {
	var ret []node.Node
	for _, n1 := range s1 {
		for _, n2 := range s2 {
			if n1.Id() == n2.Id() {
				ret = append(ret, n1)
				break
			}
		}
	}
	return ret
}
