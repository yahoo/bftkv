// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package dsa

import (
	"testing"
	"math/rand"
	"math/big"
	"time"
	gocrypto "crypto"
	godsa "crypto/dsa"
	crand "crypto/rand"
        "os"
	"io/ioutil"
        "strings"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/crypto/pgp"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/node/graph"
)

const (
	n = 10
	k = 4

	Pstr = "87AAE74090CF0C1F99C70A6B5003E02751D3D2784CA05D34392328B8E34A5EDCF8CC4F2210A556409C27110D2F627E1665B81FB3AE507CFC33FEF82C5F5A41170D124A9118FA72FBD301BAB93D7EE759392FD8E0F1212A91A5689481462D6AC4A9F33E9EB7F6BADD61B9AB6641CC8061FA26BD8560504D6BA661710B1EA5381D"
	Qstr = "8F51039F8929797506DC8CBACB642D0B614FC413"
	Gstr = "1867CB0DA8A98D662983225162ADE2BA39A6C8776A94C979756DC0CC7C75D475457B30AA85BCC5C405F4C24B9E71A73546F7148CE4FF62684D6F174C2E2DA87AEF035574EB0DDEDA8AA934246A055163A24DD662D735AB8E2F5E22905F2BA9D91CFA15A90AA1E97C01B439355709D43DCAAA16944D52AE30044CC8D447F8E057"
)

var (
	p, _ = new(big.Int).SetString(Pstr, 16)
	q, _ = new(big.Int).SetString(Qstr, 16)
	g, _ = new(big.Int).SetString(Gstr, 16)
)

const (
	scriptPath = "../../../scripts"
	keyPath = scriptPath + "/run/keys"
	clientKey = keyPath + "/u01"
	testTBS = "tbs..."
)

//
// f(0) + g(0) = \Sum (f(i) + g(i))l(i)
//
func TestSum(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	f0 := new(big.Int).Rand(r, p)
	g0 := new(big.Int).Rand(r, p)
	f, err := sss.Distribute(f0, n, k, p)
	if err != nil {
		t.Fatal(err)
	}
	g, err := sss.Distribute(g0, n, k, p)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := sss.NewProcess(nil, n, k, p)
	if err != nil {
		t.Fatal(err)
	}

	for _, i := range r.Perm(n) {
		coord := &sss.Coordinate{
			X: f[i].X,	// g[i].X should be the same
			Y: new(big.Int).Mod(new(big.Int).Add(f[i].Y, g[i].Y), p),
		}
		s, err := proc.ProcessResponse(coord)
		if err != nil {
			t.Fatal(err)
		}
		if s != nil {
			ss := new(big.Int).SetBytes(s)
			h0 := new(big.Int).Mod(new(big.Int).Add(f0, g0), p)
			if ss.Cmp(h0) != 0 {
				t.Fatalf("not match: %x, %x\n", ss, h0)
			}
			break
		}
	}
}

//
// f(0)*g(0) = \Sum f(i)*g(i)*l(i)
//
func TestMul(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	f0 := new(big.Int).Rand(r, p)
	g0 := new(big.Int).Rand(r, p)
	f, err := sss.Distribute(f0, n, k, p)
	if err != nil {
		t.Fatal(err)
	}
	g, err := sss.Distribute(g0, n, k, p)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := sss.NewProcess(nil, n, k*2, p)
	if err != nil {
		t.Fatal(err)
	}

	for _, i := range r.Perm(n) {
		coord := &sss.Coordinate{
			X: f[i].X,	// g[i].X should be the same
			Y: new(big.Int).Mod(new(big.Int).Mul(f[i].Y, g[i].Y), p),
		}
		s, err := proc.ProcessResponse(coord)
		if err != nil {
			t.Fatal(err)
		}
		if s != nil {
			ss := new(big.Int).SetBytes(s)
			h0 := new(big.Int).Mod(new(big.Int).Mul(f0, g0), p)
			if ss.Cmp(h0) != 0 {
				t.Fatalf("not match: %x, %x\n", ss, h0)
			}
			break
		}
	}
}

//
// a + b*x_i
//
func muladd(a, b, x *big.Int) *big.Int {
	r := new(big.Int)
	r.Mod(r.Mul(b, x), p)
	r.Mod(r.Add(r, a), p)
	return r
}

func TestMulAdd(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	a := new(big.Int).Rand(r, p)
	b := new(big.Int).Rand(r, p)
	x := new(big.Int).Rand(r, p)
	f, err := sss.Distribute(x, n, k, p)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := sss.NewProcess(nil, n, k, p)
	if err != nil {
		t.Fatal(err)
	}

	for _, i := range r.Perm(n) {
		coord := &sss.Coordinate{
			X: f[i].X,	// g[i].X should be the same
			Y: muladd(a, b, f[i].Y),
		}
		s, err := proc.ProcessResponse(coord)
		if err != nil {
			t.Fatal(err)
		}
		if s != nil {
			ss := new(big.Int).SetBytes(s)
			if ss.Cmp(muladd(a, b, x)) != 0 {
				t.Fatalf("not match: %x, %x\n", ss, muladd(a, b, x))
			}
			break
		}
	}
}

func jointShare(r *rand.Rand) (sigma []*sss.Coordinate, jointSecret *big.Int, err error) {
	secrets := make([]*big.Int, n)
	jointShare := make([][]*sss.Coordinate, n)
	for i := 0; i < n; i++ {
		secrets[i] = new(big.Int).Rand(r, q)
		jointShare[i], err = sss.Distribute(secrets[i], n, k, q)	// f_i(1), f_i(2), ..., f_i(n)
		if err != nil {
			return
		}
	}
	// calculate sigma for each node
	jointSecret = big.NewInt(0)
	sigma = make([]*sss.Coordinate, n)
	for i := 0; i < n; i++ {
		y := big.NewInt(0)
		for j := 0; j < n; j++ {
			coord := jointShare[j][i]
			y.Mod(y.Add(y, coord.Y), q)
		}
		sigma[i] = &sss.Coordinate{jointShare[0][i].X, y}
		jointSecret.Mod(jointSecret.Add(jointSecret, secrets[i]), q)
	}
	return
}

func TestJointShare(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	sigma, jointSecret, err := jointShare(r)
	if err != nil {
		t.Fatal(err)
	}

	proc, err := sss.NewProcess(nil, n, k, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range r.Perm(n) {
		s, err := proc.ProcessResponse(sigma[i])
		if err != nil {
			t.Fatal(err)
		}
		if s != nil {
			ss := new(big.Int).SetBytes(s)
			if ss.Cmp(jointSecret) != 0 {
				t.Fatalf("not match: %x, %x\n", ss, jointSecret)
			}
			break
		}
	}
}

type jointShareParams struct {
	k_share, a_share, b_share, c_share []*sss.Coordinate
}

func TestDSA(t *testing.T) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	orderSize := (q.BitLen() + 7) / 8
	// generate a random message
	msg := make([]byte, orderSize)
	rand.Read(msg)
	m := new(big.Int).SetBytes(msg)

	// generate a random private key x and its share
	x, err := crand.Int(crand.Reader, q)
	if err != nil {
		t.Fatal(err)
	}
	xs, err := sss.Distribute(x, n, k, q)
	if err != nil {
		t.Fatal(err)
	}

	// phase 1
	var js []*jointShareParams
	kk := big.NewInt(0)
	for i := 0; i < n; i++ {
		k_share, a_share, b_share, c_share, ki, err := firstPhase()
		if err != nil {
			t.Fatal(err)
		}
		js = append(js, &jointShareParams{k_share, a_share, b_share, c_share})
		kk.Mod(kk.Add(kk, ki), q)
	}

	// phase 2
	var nodes []int
	var r *big.Int
	var rs, vs []*sss.Coordinate
	var ks, cs []*big.Int
	for _, i := range rnd.Perm(n) {
		xi, ri, vi, ki, ci, err := secondPhase(i, js)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, &sss.Coordinate{xi, ri})
		vs = append(vs, &sss.Coordinate{xi, vi})
		ks = append(ks, ki)
		cs = append(cs, ci)
		nodes = append(nodes, i)
		if len(rs) >= 2*k {
			r = calculateR(rs, vs, p, q)
			break
		}
	}
	if r == nil {
		t.Fatal("r == nil!")
	}
	// check if r ?= g^k^-1
	kinv := new(big.Int).ModInverse(kk, q)
	rr := new(big.Int).Exp(g, kinv, p)
	rr.Mod(rr, q)
	if r.Cmp(rr) != 0 {
		t.Fatal("r mismatch")
	}

	// phase 3
	var s *big.Int
	var ss []*sss.Coordinate
	for i, j := range nodes {	// must be the same nodes in the second phase
		x_, si := thirdPhase(m, r, xs[j], ks[i], cs[i])
		ss = append(ss, &sss.Coordinate{x_, si})
		if len(ss) >= 2*k {
			s = calculateS(ss, q)
			break
		}
	}
	if s == nil {
		t.Fatal("s == nil!")
	}
	// check if s ?= k(m + xr)
	sr := new(big.Int).Mul(x, r)
	sr.Mod(sr, q)
	sr.Mod(sr.Add(sr, m), q)
	sr.Mod(sr.Mul(sr, kk), q)
	if s.Cmp(sr) != 0 {
		t.Fatal("s mismatch")
	}

	// double-check (s, r) with Verify()
	var pub godsa.PublicKey
	pub.P = p
	pub.Q = q
	pub.G = g
	pub.Y = new(big.Int)
	pub.Y.Exp(g, x, p)
	if !Verify(&pub, msg, r, s) {
		t.Fatal("verification failed")
	}
}

func firstPhase() (k_share, a_share, b_share, c_share []*sss.Coordinate, ki *big.Int, err error) {
	ki, err = crand.Int(crand.Reader, q)
	if err != nil {
		return
	}
	k_share, err = sss.Distribute(ki, n, k, q)
	if err != nil {
		return
	}
	a_share, err = generateJointRandom(k, n, q)
	if err != nil {
		return
	}
	b_share, err = generateJointZero(k*2, n, q)
	if err != nil {
		return
	}
	c_share, err = generateJointZero(k*2, n, q)
	if err != nil {
		return
	}
	return
}

// ri = g^ai mod p
// vi = ai*ki + bi mod q
func secondPhase(i int, js []*jointShareParams) (x int, ri, vi, ki, ci *big.Int, err error) {
	x = -1
	ki = big.NewInt(0)
	ai := big.NewInt(0)
	bi := big.NewInt(0)
	ci = big.NewInt(0)
	for _, share := range js {
		kj := share.k_share[i]
		aj := share.a_share[i]
		bj := share.b_share[i]
		cj := share.c_share[i]
		if x < 0 {
			x = kj.X
		}
		if !(kj.X == x && aj.X == x && bj.X == x && cj.X == x) {
			err = crypto.ErrInvalidInput
			return
		}
		ki.Mod(ki.Add(ki, kj.Y), q)
		ai.Mod(ai.Add(ai, aj.Y), q)
		bi.Mod(bi.Add(bi, bj.Y), q)
		ci.Mod(ci.Add(ci, cj.Y), q)
	}
	ri = new(big.Int).Exp(g, ai, p)
	vi = new(big.Int).Mul(ki, ai)
	vi.Mod(vi, q)
	vi.Add(vi, bi)
	vi.Mod(vi, q)
	return
}

func thirdPhase(m, r *big.Int, xi *sss.Coordinate, ki, c *big.Int) (int, *big.Int) {
	// si = ki(m + xi*r) + c mod q
	si := new(big.Int).Mul(xi.Y, r)
	si.Mod(si, q)
	si.Mod(si.Add(si, m), q)
	si.Mod(si.Mul(si, ki), q)
	si.Mod(si.Add(si, c), q)
	return xi.X, si
}

func TestThreshold(t *testing.T) {
	var priv godsa.PrivateKey
	if err := godsa.GenerateParameters(&priv.Parameters, crand.Reader, godsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := godsa.GenerateKey(&priv, crand.Reader); err != nil {
		t.Fatal(err)
	}
	orderSize := (priv.Q.BitLen() + 7) / 8

	crypt := pgp.New()
	ctx := New(crypt)
	peers, err := newServers(crypt, "a")
	if err != nil {
		t.Fatal(err)
	}
	self, err := newClient(crypt, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	params, algo, err := ctx.Distribute(&priv, peers, k)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[uint64][]byte)
	for i, peer := range peers {
		shares[peer.Id()] = params[i]
	}

	proc, err := ctx.NewProcess([]byte(testTBS), algo, gocrypto.SHA256)
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
			psig, err := ctx.Sign(shares[nd.Id()], req, self.Id(), nd.Id())	// don't be confused with self/peer IDs: peer=client(self)
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
				if !Verify(&priv.PublicKey, dgst, r, s) {
					t.Fatal("verifiation failed")
				}
				return
			}
		}
	}
	t.Fatal(crypto.ErrInsufficientNumberOfThresholdSignatures)
}

func newServers(crypt *crypto.Crypto, prefixes ...string) ([]node.Node, error) {
	g := graph.New()
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		for _, prefix := range prefixes {
			if strings.HasPrefix(f.Name(), prefix) {
				path := keyPath + "/" + f.Name()
				if err := readCerts(g, crypt, path + "/pubring.gpg", false); err != nil {
					return nil, err
				}
				if err := readCerts(g, crypt, path + "/secring.gpg", true); err != nil {
					return nil, err
				}
			}
		}
	}
	return g.GetPeers(), nil
}

func newClient(crypt *crypto.Crypto, path string) (node.Node, error) {
	g := graph.New()
	if err := readCerts(g, crypt, path + "/pubring.gpg", false); err != nil {
		return nil, err
	}
	if err := readCerts(g, crypt, path + "/secring.gpg", true); err != nil {
		return nil, err
	}
	return node.Node(g), nil
}

func readCerts(g *graph.Graph, crypt *crypto.Crypto, path string, sec bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	certs, err := crypt.Certificate.ParseStream(f)
	if err != nil {
		return err
	}
	if sec {
		g.SetSelfNodes(certs)
	} else {
		g.AddNodes(certs)
	}
	crypt.Keyring.Register(certs, sec, true)
	return nil
}

// copied from https://golang.org/src/crypto/dsa/dsa.go
func Verify(pub *godsa.PublicKey, hash []byte, r, s *big.Int) bool {
  	// FIPS 186-3, section 4.7
	
  	if pub.P.Sign() == 0 {
  		return false
  	}
	
  	if r.Sign() < 1 || r.Cmp(pub.Q) >= 0 {
  		return false
  	}
  	if s.Sign() < 1 || s.Cmp(pub.Q) >= 0 {
  		return false
  	}
	
  	w := new(big.Int).ModInverse(s, pub.Q)
	
  	n := pub.Q.BitLen()
  	if n&7 != 0 {
  		return false
  	}
  	z := new(big.Int).SetBytes(hash)
	
  	u1 := new(big.Int).Mul(z, w)
  	u1.Mod(u1, pub.Q)
  	u2 := w.Mul(r, w)
  	u2.Mod(u2, pub.Q)
  	v := u1.Exp(pub.G, u1, pub.P)
  	u2.Exp(pub.Y, u2, pub.P)
  	v.Mul(v, u2)
  	v.Mod(v, pub.P)
  	v.Mod(v, pub.Q)
	
  	return v.Cmp(r) == 0
}
