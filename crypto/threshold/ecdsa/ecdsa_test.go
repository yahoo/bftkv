// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package ecdsa

import (
	"testing"
	"math/rand"
	"math/big"
	"time"
	gocrypto "crypto"
	goecdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/crypto/threshold/dsa"
	"github.com/yahoo/bftkv/crypto/threshold/dsa/test_utils"
	"github.com/yahoo/bftkv/node"
)

const (
	k = 4
	n = 10
)

const (
	scriptPath = "../../../scripts"
	keyPath = scriptPath + "/run/keys"
	clientKey = keyPath + "/u01"
	testTBS = "tbs..."
)

func TestMul(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	priv, err := goecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	group, _ := (&ecdsaGroup{}).ParseKey(priv)
	q := group.SubGroupOrder()
	f0 := new(big.Int).Rand(r, q)
	f, err := sss.Distribute(f0, n, k, q)
	if err != nil {
		t.Fatal(err)
	}
	var rs []*dsa.PartialR
	for _, i := range r.Perm(n) {
		ri := group.CalculatePartialR(f[i].Y)
		rs = append(rs, &dsa.PartialR{
			X: f[i].X,
			Ri: ri,
			Vi: f[i].Y,
		})
		if len(rs) >= k {
			break
		}
	}

	var xs []int
	for _, ri := range rs {
		xs = append(xs, ri.X)
	}
	g := group.(*ecdsaGroupOperations)
	var x, y *big.Int
	v := big.NewInt(0)
	for _, ri := range rs {
		l := sss.Lagrange(ri.X, xs, g.params.N)
		x1, y1 := elliptic.Unmarshal(g.curve, ri.Ri)
		x1, y1 = g.curve.ScalarMult(x1, y1, l.Bytes())
		if x == nil {
			x, y = x1, y1
		} else {
			x, y = g.curve.Add(x, y, x1, y1)	// P += li*ai*P
		}

		t := new(big.Int).Mul(ri.Vi, l)
		t.Mod(t, g.params.N)
		v.Mod(v.Add(v, t), g.params.N)
	}

	if v.Cmp(f0) != 0 {
		t.Fatalf("mismatch: %x, %x", v, f0)
	}

	x0, y0 := g.curve.ScalarBaseMult(f0.Bytes())
	if x.Cmp(x0) != 0 || y.Cmp(y0) != 0 {
		t.Fatalf("mismatch: (%x, %x) != (%x, %x)", x, y, x0, y0)
	}
}

type server struct {
	self node.SelfNode
	crypt *crypto.Crypto
	th crypto.Threshold
}

func TestThreshold(t *testing.T) {
	// construct ECDSA parameters
	priv, err := goecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	orderSize := (priv.Curve.Params().N.BitLen() + 7) / 8

	servers, err := test_utils.NewServers(New, "a")
	if err != nil {
		t.Fatal(err)
	}

	crypt := pgp.New()
	client := New(nil)
	self, err := test_utils.NewClient(crypt, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	var peers []node.Node
	for _, server := range servers {
		peers = append(peers, server.Self)
	}
	params, algo, err := client.Distribute(priv, peers, k)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[uint64][]byte)
	for i, peer := range peers {
		shares[peer.Id()] = params[i]
	}

	proc, err := client.NewProcess([]byte(testTBS), algo, gocrypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	for retry := 3; retry > 0; retry-- {
		nodes, req, err := proc.MakeRequest()
		if err != nil {
			t.Fatal(err)
		}
		if nodes == nil || len(nodes) == 0 {
			t.Fatal(crypto.ErrInsufficientNumberOfThresholdSignatures)
		}
		for _, nd := range nodes {
			serverId := nd.Id()
			psig, err := servers[serverId].Th.Sign(shares[serverId], req, self.Id(), serverId)	// don't be confused with self/peer IDs: peer=client(self)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := proc.ProcessResponse(psig, nd)
			if err == crypto.ErrContinue {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if sig != nil {
				n := len(sig) / 2
				if n != orderSize {
					t.Fatalf("unmatch order size: %d, %d", n, orderSize)
				}
				r := new(big.Int).SetBytes(sig[:n])
				s := new(big.Int).SetBytes(sig[n:])
				h := gocrypto.SHA256.New()
				h.Write([]byte(testTBS))
				dgst := h.Sum(nil)[:orderSize]
				if !goecdsa.Verify(&priv.PublicKey, dgst, r, s) {
					t.Fatal("verifiation failed")
				}
				return
			}
		}
	}
	t.Fatal(crypto.ErrInsufficientNumberOfThresholdSignatures)
}
