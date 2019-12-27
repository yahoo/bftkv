// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package graph

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
)

const (
	maxDistance = -1
	keyPath     = "../../scripts/run/keys"
)

type Keyring struct {
	pubrngs [][]byte
	secrng  []byte
}

type VertexDistance struct {
	v *Vertex
	d int
}

func distance(v1, v2 *Vertex) int {
	m := make(map[uint64]bool)
	q := make([]VertexDistance, 0)
	q = append(q, VertexDistance{v1, 0})
	m[v1.Instance.Id()] = true
	for len(q) > 0 {
		vd := q[0]
		q = q[1:]
		if vd.v == v2 {
			return vd.d
		}
		for id, e := range vd.v.Edges {
			if _, ok := m[id]; !ok {
				q = append(q, VertexDistance{e, vd.d + 1})
			}
		}
	}
	return -1
}

func constructGraph() (*Graph, error) {
	g := New()
	crypt := pgp.New()

	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".") {
			continue
		}
		path := keyPath + "/" + f.Name()
		readCerts(g, crypt, path+"/pubring.gpg", false)
		readCerts(g, crypt, path+"/secring.gpg", true)
	}
	return g, nil
}

func checkDistance(t *testing.T, g *Graph, nodes []node.Node, start uint64) {
	sv := g.Vertices[start]
	if sv.Instance == nil {
		t.Fatalf("%X: null instance!", start)
	}
	di := make([]int, len(nodes))
	for i, n := range nodes {
		id := n.Id()
		v := g.Vertices[id]
		if v.Instance == nil {
			t.Fatalf("%X: null instance!", id)
		}
		di[i] = distance(sv, v)
		if di[i] < 0 {
			t.Errorf("not connected: %X, %X\n", sv.Instance.Id(), v.Instance.Id())
		}
	}
	if !sort.SliceIsSorted(di, func(i, j int) bool {
		return di[i] < di[j]
	}) {
		t.Errorf("[%X] not sorted: %v", start, di)
	}
}

func checkUniqueness(t *testing.T, nodes []node.Node) {
	for i, n1 := range nodes {
		for _, n2 := range nodes[i+1:] {
			if n1 == n2 {
				t.Errorf("duplicated: %s[%X]", n1.Name(), n1.Id())
			}
		}
	}
}

func TestBFS(t *testing.T) {
	t.Skip("skip failing test - FIXME")
	g, err := constructGraph()
	if err != nil {
		t.Fatal(err)
	}

	for start, v := range g.Vertices {
		if v.Instance == nil {
			continue
		}
		for n := 1; n < maxDistance; n++ {
			nodes := g.GetReachableNodes(start, n)
			// vvv print the result vvv
			var ids []string
			for _, nn := range nodes {
				ids = append(ids, nn.Name())
			}
			t.Log(ids)
			// ^^^
			checkDistance(t, g, nodes, start)
			checkUniqueness(t, nodes)
		}
	}
}

func checkEdges(v1, v2 *Vertex) bool {
	if _, ok := v1.Edges[v2.Instance.Id()]; !ok {
		return false
	}
	if _, ok := v2.Edges[v1.Instance.Id()]; !ok {
		return false
	}
	return true
}

func checkClique(g *Graph, clique []node.Node) bool {
	for i, c := range clique {
		v := g.Vertices[c.Id()]
		for _, cc := range clique[i+1:] {
			vv := g.Vertices[cc.Id()]
			if !checkEdges(v, vv) {
				return false
			}
		}
	}
	return true
}

func isMember(v *Vertex, clique []node.Node) bool {
	for _, n := range clique {
		if n == v.Instance {
			return true
		}
	}
	return false
}

func checkMaximal(g *Graph, clique []node.Node) bool {
	for _, v := range g.Vertices {
		if isMember(v, clique) {
			continue
		}
		if v.Instance == nil {
			continue
		}
		if checkClique(g, append(clique, v.Instance)) {
			return false
		}
	}
	return true
}

func TestClieque(t *testing.T) {
	t.Skip("skip failing test - FIXME)")
	g, err := constructGraph()
	if err != nil {
		t.Fatal(err)
	}

	for start, v := range g.Vertices {
		if v.Instance == nil {
			continue
		}
		for n := 1; n < maxDistance; n++ {
			cliques := g.GetCliques(start, n)
			for _, clique := range cliques {
				// vvv print the resut vvv
				var ids []string
				for _, nn := range clique.Nodes {
					ids = append(ids, nn.Name())
				}
				t.Log(ids)
				// ^^^
				if !checkClique(g, clique.Nodes) {
					t.Errorf("not a clique: %s", v.Instance.Name())
				}
				if !checkMaximal(g, clique.Nodes) {
					t.Errorf("not maximal: %s", v.Instance.Name())
				}
				checkUniqueness(t, clique.Nodes)
			}
		}
	}
}

func readCerts(g *Graph, crypt *crypto.Crypto, path string, sec bool) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return
	}
	certs, err := crypt.Certificate.ParseStream(f)
	if err != nil {
		f.Close()
		log.Fatal(err)
	}
	if sec {
		g.SetSelfNodes(certs)
	} else {
		g.AddNodes(certs)
	}
	crypt.Keyring.Register(certs, sec, true)
	f.Close()
}

func dump(g *Graph, prompt string) {
	fmt.Printf(">>> %s <<<\n", prompt)
	for _, v := range g.Vertices {
		n := v.Instance
		if n == nil {
			continue
		}
		instance := ""
		if n.Instance() == nil {
			instance = "nil"
		}
		fmt.Printf("  %s [%x] %s\n", n.Name(), n.Id(), instance)
		for _, e := range v.Edges {
			if e.Instance != nil {
				fmt.Printf("    %s\n", e.Instance.Name())
			} else {
				fmt.Printf("    ---\n")
			}
		}
	}
}
