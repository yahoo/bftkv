// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package graph

import (
	"io"
	"bytes"
	"sync"
	"log"

	"github.com/yahoo/bftkv/node"
)

type Vertex struct {
	Edges map[uint64]*Vertex	// @@ redudant... should be []uint64?
	Instance node.Node
}

type Graph struct {
	Vertices map[uint64]*Vertex
	Revoked map[uint64]node.Node
	Self []*Vertex
	mutex sync.Mutex
}

func NewVertex(instance node.Node) *Vertex {
	return &Vertex{
		Instance: instance,
		Edges: make(map[uint64]*Vertex),
	}
}

func New() *Graph {
	return &Graph{
		Vertices: make(map[uint64]*Vertex),
		Revoked: make(map[uint64]node.Node),
	}
}

func (g *Graph) AddNodes(nodes []node.Node) []node.Node {
	var res []node.Node
	for _, n := range nodes {
		skid := n.Id()
		if _, ok := g.Revoked[skid]; ok {
			continue
		}
		self, ok := g.Vertices[skid]
		if !ok {
			self = NewVertex(n)
			g.Vertices[skid] = self
		} else if self.Instance == nil {
			self.Instance = n
		}
		// add the signers unless they have been revoked
		for _, signer := range n.Signers() {
			if _, ok := g.Revoked[signer]; ok {
				continue
			}
			v, ok := g.Vertices[signer]
			if !ok {
				v = NewVertex(nil)	// keep the instance nil
				g.Vertices[signer] = v
			}
			v.Edges[skid] = self
		}
		res = append(res, n)
	}
	return res
}

func (g *Graph) SetSelfNodes(nodes []node.Node) {
	// assume the graph has been already built
	for _, n := range nodes {
		v, ok := g.Vertices[n.Id()]
		if !ok || v.Instance == nil {
			// @@ should we allow this? i.e., the case where the key ring has only seckey..
			g.AddNodes([]node.Node{n})
			v = g.Vertices[n.Id()]
		}
		g.Self = append(g.Self, v)
	}
}

func (g *Graph) RemoveNodes(nodes []node.Node) {
	// we might get multiple leave requests; regulate access with a mutex
	g.mutex.Lock()
	for _, n := range nodes {
		id := n.Id()
		for _, v := range g.Vertices {
			delete(v.Edges, id)
		}
		delete(g.Vertices, id)
	}
	g.mutex.Unlock()
}

func (g *Graph) AddPeers(peers []node.Node) []node.Node {
	peers = g.AddNodes(peers)
	for _, n := range peers {
		n.SetActive(true)
	}
	return peers
}

func (g *Graph) GetPeers() []node.Node {
	var nodes []node.Node
	for _, v := range g.Vertices {
		if v.Instance != nil && v.Instance.Id() != g.GetSelfId() {
			nodes = append(nodes, v.Instance)
		}
	}
	return nodes
}

func (g *Graph) RemovePeers(peers []node.Node) {
	g.RemoveNodes(peers)
}

func (g *Graph) Revoke(n node.Node) {
	id := n.Id()
	v, ok := g.Vertices[id]
	var instance node.Node
	if ok {
		instance = v.Instance
		g.RemoveNodes([]node.Node{instance})
	}
	g.Revoked[id] = instance
}

func (g *Graph) RevokeNodes(nodes []node.Node) {
	for _, n := range nodes {
		g.Revoked[n.Id()] = n
	}
}

func (g *Graph) SerializeSelf() ([]byte, error) {
	var buf bytes.Buffer
	for _, n := range g.Self {
		if n.Instance != nil {
			pkt, err := n.Instance.Serialize()
			if err != nil {
				return nil, err
			}
			if _, err := buf.Write(pkt); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func (g *Graph) SerializeNodes(w io.Writer) error {
	for _, v := range g.Vertices {
		if v.Instance == nil {
			continue
		}
		pkt, err := v.Instance.Serialize()
		if err != nil {
			return err
		}
		if _, err := w.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (g *Graph) SerializeRevokedNodes(w io.Writer) error {
	for _, n := range g.Revoked {
		pkt, err := n.Serialize()
		if err != nil {
			return err
		}
		if _, err := w.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (g *Graph) InGraph(n node.Node) bool {
	_, ok := g.Vertices[n.Id()]
	return ok
}

//
// node.Node (CertificateInstance) implementation
// @@ assume the first element represents 'self'
//
func (g *Graph) Id() uint64 {
	return g.Self[0].Instance.Id()
}

func (g *Graph) Name() string {
	return g.Self[0].Instance.Name()
}

func (g *Graph) Address() string {
	return g.Self[0].Instance.Address()
}

func (g *Graph) UId() string {
	return g.Self[0].Instance.UId()
}

func (g *Graph) Signers() []uint64 {
	return g.Self[0].Instance.Signers()
}

func (g *Graph) Serialize() ([]byte, error) {
	return g.Self[0].Instance.Serialize()
}

func (g *Graph) Instance() interface{} {
	return g.Self[0].Instance.Instance()
}

func (g *Graph) SetActive(active bool) {
}

func (g *Graph) Active() bool {
	return true
}


//
// internal APIs
//

func (g *Graph) GetSelfId() uint64 {
	if len(g.Self) == 0 || g.Self[0].Instance == nil {
		return 0
	}
	return g.Self[0].Instance.Id()
}

func (g *Graph) GetGraphSize() int {
	return len(g.Vertices)
}

type vertexDistance struct {
	v *Vertex
	d int
}

func (g *Graph) GetReachableNodes(sid uint64, distance int) []node.Node {
	var nodes []node.Node
	v, ok := g.Vertices[sid]
	if !ok {
		return nodes
	}
	bfs(v, func(vd vertexDistance) bool {
		if distance >= 0 && vd.d > distance {
			return true
		}
		if vd.v.Instance != nil {
			nodes = append(nodes, vd.v.Instance)
		}
		return false
	})
	return nodes
}

func (g *Graph) GetCliques(sid uint64, distance int) [][]node.Node {
	var cliques [][]node.Node
	v, ok := g.Vertices[sid]
	if !ok || v.Instance == nil {
		return cliques
	}
	bfs(v, func(vd vertexDistance) bool {
		if distance >= 0 && vd.d > distance {
			return true
		}
		if vd.v.Instance != nil {
			if !inClique(vd.v.Instance, cliques) {
				clique := g.findMaximalClique(vd.v)
				if clique != nil {
					cliques = append(cliques, clique)
				}
			}
		}
		return false
	})
	return cliques
}

func inClique(e node.Node, cliques [][]node.Node) bool {
	for _, c := range cliques {
		for _, n := range c {
			if e.Id() == n.Id() {
				return true
			}
		}
	}
	return false
}

// find a single maximal clique, assuming there exists only one maximal clique that includes 's' therefore maximal = maximum
func (g * Graph) findMaximalClique(s *Vertex) []node.Node {
	clique := []*Vertex{s}
	// walk thru all nodes
	for _, v := range g.Vertices {
		if v.Instance == nil {
			continue
		}
		if v == s {
			continue
		}
		if bidirect(v, clique) {
			clique = append(clique, v)
		}
	}

	// check if the clique is unique
	for _, v := range g.Vertices {
		if v.Instance != nil && v != s && !inVertices(v, clique) && bidirect(v, []*Vertex{s}) {
			log.Printf("graph: found more than one maximal cliques for %s", s.Instance.Name())
			return nil
		}
	}

	// return nodes
	var res []node.Node
	for _, c := range clique {
		res = append(res, c.Instance)
	}
	return res
}

func bidirect(v *Vertex, clique []*Vertex) bool {
	for _, c := range clique {
		if _, ok := c.Edges[v.Instance.Id()]; !ok {
			return false
		}
		if _, ok := v.Edges[c.Instance.Id()]; !ok {
			return false
		}
	}
	return true
}

func inVertices(e *Vertex, s []*Vertex) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func bfs(v *Vertex, proc func(vd vertexDistance) bool) {
	m := make(map[uint64]bool)
	q := make([]vertexDistance, 0)
	q = append(q, vertexDistance{v, 0})
	m[v.Instance.Id()] = true
	for len(q) > 0 {
		vd := q[0]
		q = q[1:]
		if proc(vd) {
			return
		}
		for id, e := range vd.v.Edges {
			if _, ok := m[id]; !ok {
				q = append(q, vertexDistance{e, vd.d + 1})
				m[id] = true
			}
		}
	}
}
