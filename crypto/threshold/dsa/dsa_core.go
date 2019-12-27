// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package dsa

import (
	"bytes"
	gocrypto "crypto"
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
)

type PartialR struct {
	X  int
	Ri []byte
	Vi *big.Int
}

type GroupOperations interface {
	CalculatePartialR(ai *big.Int) []byte
	CalculateR(rs []*PartialR) *big.Int
	SubGroupOrder() *big.Int
	Serialize(bp *bytes.Buffer) error
	OS2I(os []byte) *big.Int
}

type Group interface {
	ParseKey(key interface{}) (GroupOperations, *big.Int)
	ParseParams(r *bytes.Reader) (GroupOperations, error)
}

type kc struct {
	k, c *big.Int
}

type dsaContext struct {
	g      Group
	crypt  *crypto.Crypto
	n, t   int
	nodes  []node.Node
	kmap   map[uint64]*kc
	nonces map[uint64][]byte
	algo   crypto.ThresholdAlgo
}

type encryptedShare struct {
	coords []byte // E_id({k,a,b,c})
	id     uint64
}

func NewWithGroup(crypt *crypto.Crypto, g Group, algo crypto.ThresholdAlgo) crypto.Threshold {
	return &dsaContext{
		g:      g,
		crypt:  crypt,
		kmap:   make(map[uint64]*kc),
		nonces: make(map[uint64][]byte),
		algo:   algo,
	}
}

func (ctx *dsaContext) Distribute(key interface{}, nodes []node.Node, t int) (shares [][]byte, algo crypto.ThresholdAlgo, err error) {
	if t*2 > len(nodes) {
		// return shares, algo, crypto.ErrInvalidInput
		t = len(nodes) / 2 // @@ take the closest threshold for now
	}
	ctx.nodes = nodes
	ctx.n = len(nodes)
	ctx.t = t
	group, x := ctx.g.ParseKey(key)
	q := group.SubGroupOrder()
	coords, err := sss.Distribute(x, ctx.n, ctx.t, q)
	if err != nil {
		return nil, algo, err
	}
	for _, coord := range coords {
		secret, err := serializePartialParam(group, coord, ctx.t, ctx.nodes)
		if err != nil {
			return nil, algo, err
		}
		shares = append(shares, secret)
	}
	return shares, ctx.algo, nil
}

func (ctx *dsaContext) Sign(sec []byte, req []byte, peerId, selfId uint64) ([]byte, error) {
	group, share, t, nodes, err := parsePartialParam(ctx, sec)
	q := group.SubGroupOrder()
	if err != nil {
		return nil, err
	}
	if req == nil { // the first phase, generate joint share for k, a, b, c
		n := len(nodes)
		k, err := generateJointRandom(t, n, q)
		if err != nil {
			return nil, err
		}
		a, err := generateJointRandom(t, n, q)
		if err != nil {
			return nil, err
		}
		b, err := generateJointZero(t*2, n, q)
		if err != nil {
			return nil, err
		}
		c, err := generateJointZero(t*2, n, q)
		if err != nil {
			return nil, err
		}
		shares, err := ctx.encrypt(k, a, b, c, nodes, peerId) // js.k[i] corresponds to nodes[i] for all i
		if err != nil {
			return nil, err
		}
		return serializeJointShare(shares)
	} else {
		var psig []byte
		m, r, k_share, err := parseSignRequest(req, selfId)
		if err != nil {
			return nil, err
		}
		if k_share != nil { // the second phase
			// ki = \Sum f_j(i)
			x, ki, ai, bi, ci, err := ctx.decrypt(k_share, q, selfId, peerId)
			if err != nil {
				return nil, err
			}
			ri := group.CalculatePartialR(ai)
			// vi = ki*ai + bi mod q
			vi := new(big.Int).Mul(ki, ai)
			vi.Mod(vi.Add(vi.Mod(vi, q), bi), q)
			psig, err = serializePartialSignature(group, x, ri, vi)
			if err != nil {
				return nil, err
			}
			// keep ki
			ctx.kmap[peerId] = &kc{ki, ci}
		} else { // the final phase
			if m == nil || r == nil {
				return nil, crypto.ErrInvalidInput
			}
			kc, ok := ctx.kmap[peerId]
			if !ok {
				return nil, crypto.ErrKeyNotFound
			}
			// si = ki(m + xi*r) mod q
			si := new(big.Int).Mul(r, share.Y)
			si.Mod(si, q)
			si.Mod(si.Add(si, m), q)
			si.Mod(si.Mul(si, kc.k), q)
			si.Mod(si.Add(si, kc.c), q)
			psig, err = serializePartialSignature(group, share.X, si.Bytes(), nil)
			if err != nil {
				return nil, err
			}
		}
		return psig, nil
	}
}

func generateJointRandom(t, n int, m *big.Int) ([]*sss.Coordinate, error) {
	s, err := rand.Int(rand.Reader, m)
	if err != nil {
		return nil, err
	}
	return sss.Distribute(s, n, t, m)
}

func generateJointZero(t, n int, m *big.Int) ([]*sss.Coordinate, error) {
	return sss.Distribute(big.NewInt(0), n, t, m)
}

func (ctx *dsaContext) encrypt(k, a, b, c []*sss.Coordinate, nodes []node.Node, peerId uint64) ([]*encryptedShare, error) {
	// generate a nonce for the peer
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	var res []*encryptedShare
	for i, peer := range nodes {
		data, err := serializeShare(k[i], a[i], b[i], c[i])
		if err != nil {
			return nil, err
		}
		cipher, err := ctx.crypt.Message.Encrypt([]node.Node{peer}, data, nonce[:])
		if err != nil {
			return nil, err
		}
		res = append(res, &encryptedShare{
			coords: cipher,
			id:     peer.Id(),
		})
	}
	ctx.nonces[peerId] = nonce[:]
	return res, nil
}

func (ctx *dsaContext) decrypt(shares [][]byte, q *big.Int, selfId, peerId uint64) (x int, ki, ai, bi, ci *big.Int, err error) {
	x = -1
	ki = big.NewInt(0)
	ai = big.NewInt(0)
	bi = big.NewInt(0)
	ci = big.NewInt(0)
	err = crypto.ErrShareNotFound
	for _, share := range shares {
		plain, nonce, signer, err1 := ctx.crypt.Message.Decrypt(bytes.NewReader(share))
		if err1 != nil {
			err = err1
			return
		}
		if signer.Id() == selfId { // check if the nonce is fresh so at least this share is secure
			if selfNonce, ok := ctx.nonces[peerId]; !ok || !bytes.Equal(nonce, selfNonce) {
				err = crypto.ErrShareNotFound
				return
			}
			err = nil // clear the error -- to avoid to eliminate the self share
		}
		k, a, b, c, err1 := parseShare(plain)
		if err1 != nil {
			err = err1
			return
		}
		// double-check if all coordinates have the same x
		if x < 0 {
			x = k.X
		}
		if !(k.X == x && a.X == x && b.X == x && c.X == x) {
			err = crypto.ErrInvalidInput
			return
		}
		ki.Mod(ki.Add(ki, k.Y), q)
		ai.Mod(ai.Add(ai, a.Y), q)
		bi.Mod(bi.Add(bi, b.Y), q)
		ci.Mod(ci.Add(ci, c.Y), q)
	}
	return
}

func serializeShare(k, a, b, c *sss.Coordinate) (chunk []byte, err error) {
	var buf bytes.Buffer
	if err = serializeCoord(&buf, k); err == nil {
		if err = serializeCoord(&buf, a); err == nil {
			if err = serializeCoord(&buf, b); err == nil {
				if err = serializeCoord(&buf, c); err == nil {
					chunk = buf.Bytes()
				}
			}
		}
	}
	return
}

func parseShare(data []byte) (k, a, b, c *sss.Coordinate, err error) {
	r := bytes.NewReader(data)
	if k, err = parseCoord(r); err == nil {
		if a, err = parseCoord(r); err == nil {
			if b, err = parseCoord(r); err == nil {
				c, err = parseCoord(r)
			}
		}
	}
	return
}

type dsaProc struct {
	nodes  []node.Node
	t, n   int
	dgst   []byte
	m      *big.Int // calculate when the group parameters get available from a server
	r      *big.Int
	s      *big.Int
	kmap   map[uint64][][]byte
	ri     []*PartialR
	si     []*sss.Coordinate
	phase  int
	result []byte
	g      Group
}

func (ctx *dsaContext) NewProcess(tbs []byte, algo crypto.ThresholdAlgo, hash gocrypto.Hash) (crypto.ThresholdProcess, error) {
	h := hash.New()
	h.Write(tbs)
	dgst := h.Sum(nil)
	return &dsaProc{
		nodes: ctx.nodes,
		t:     ctx.t,
		n:     len(ctx.nodes),
		dgst:  dgst,
		r:     nil,
		s:     nil,
		kmap:  make(map[uint64][][]byte),
		phase: 0,
		g:     ctx.g,
	}, nil
}

func (proc *dsaProc) MakeRequest() (nodes []node.Node, req []byte, err error) {
	switch proc.phase {
	case 0:
		req = nil // nothing to send
	case 1:
		req, err = serializeSignRequest(nil, nil, proc.kmap) // ineffective to put all shares into one packet and broadcast but for simplicity for now...
	case 2:
		req, err = serializeSignRequest(proc.m, proc.r, nil)
	}
	if err != nil {
		return
	}
	nodes = proc.nodes
	proc.nodes = nil
	return
}

func (proc *dsaProc) ProcessResponse(data []byte, peer node.Node) ([]byte, error) {
	proc.nodes = append(proc.nodes, peer)
	switch proc.phase {
	case 0: // expecting joint share for k, a, b, c
		shares, err := parseJointShare(data)
		if err != nil {
			return nil, err
		}
		th := 0
		for _, share := range shares {
			proc.kmap[share.id] = append(proc.kmap[share.id], share.coords)
			th = len(proc.kmap[share.id]) // should be the same for all items
		}
		if th >= 2*proc.t {
			proc.phase++
			return nil, crypto.ErrContinue
		} else {
			return nil, nil
		}
	case 1:
		group, x, ri, vi, err := parsePartialSignature(proc.g, data)
		if err != nil {
			return nil, err
		}
		proc.ri = append(proc.ri, &PartialR{x, ri, vi})
		if len(proc.ri) >= 2*proc.t {
			proc.r = group.CalculateR(proc.ri)
			proc.m = group.OS2I(proc.dgst)
			proc.phase++
			return nil, crypto.ErrContinue
		} else {
			return nil, nil
		}
	case 2:
		group, x, si, _, err := parsePartialSignature(proc.g, data)
		if err != nil {
			return nil, err
		}
		proc.si = append(proc.si, &sss.Coordinate{x, new(big.Int).SetBytes(si)})
		if len(proc.si) >= 2*proc.t {
			q := group.SubGroupOrder()
			proc.s = calculateS(proc.si, q)
			proc.result = formatDSA(proc.r, proc.s, q)
			proc.phase++
			return proc.result, nil
		} else {
			return nil, nil
		}
	default:
		if proc.result != nil {
			return proc.result, nil
		} else {
			return nil, crypto.ErrSigningFailed
		}
	}
}

func formatDSA(r, s *big.Int, q *big.Int) []byte {
	// returns the result in the raw format, not in DER
	n := (q.BitLen() + 7) / 8
	res := make([]byte, n*2) // should be initialized with 0
	rs := r.Bytes()
	ss := s.Bytes()
	if len(rs) > n || len(ss) > n {
		panic("DSA: the size of the order > 160")
	}
	copy(res[n-len(rs):], rs)
	copy(res[2*n-len(ss):], ss)
	return res
}

func calculateS(res []*sss.Coordinate, q *big.Int) *big.Int {
	// s = \Sum si*li mod q
	s := big.NewInt(0)
	var xs []int
	for _, si := range res {
		xs = append(xs, si.X)
	}
	for _, si := range res {
		l := sss.Lagrange(si.X, xs, q)
		t := new(big.Int).Mul(si.Y, l)
		t.Mod(t, q)
		s.Mod(s.Add(s, t), q)
	}
	return s
}

func serializePartialParam(group GroupOperations, share *sss.Coordinate, t int, nodes []node.Node) ([]byte, error) {
	var buf bytes.Buffer
	if err := group.Serialize(&buf); err != nil {
		return nil, err
	}
	if err := serializeCoord(&buf, share); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(t)); err != nil {
		return nil, err
	}
	// write nodes as a stream
	for _, n := range nodes {
		s, err := n.Serialize()
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(s); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func parsePartialParam(ctx *dsaContext, data []byte) (group GroupOperations, share *sss.Coordinate, t int, nodes []node.Node, err error) {
	r := bytes.NewReader(data)
	if group, err = ctx.g.ParseParams(r); err != nil {
		return
	}
	share, err = parseCoord(r)
	if err != nil {
		return
	}
	var tt uint16
	if err = binary.Read(r, binary.BigEndian, &tt); err != nil {
		return
	}
	t = int(tt)
	nodes, err = ctx.crypt.Certificate.ParseStream(r) // read nodes from a stream
	return
}

func serializeJointShare(shares []*encryptedShare) ([]byte, error) {
	var buf bytes.Buffer
	n := uint16(len(shares))
	if err := binary.Write(&buf, binary.BigEndian, n); err != nil {
		return nil, err
	}
	for _, share := range shares {
		if err := packet.WriteChunk(&buf, share.coords); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, binary.BigEndian, share.id); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func parseJointShare(data []byte) ([]*encryptedShare, error) {
	r := bytes.NewReader(data)
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	shares := make([]*encryptedShare, n)
	for i := uint16(0); i < n; i++ {
		c, err := packet.ReadChunk(r)
		if err != nil {
			return nil, err
		}
		var id uint64
		if err := binary.Read(r, binary.BigEndian, &id); err != nil {
			return nil, err
		}
		shares[i] = &encryptedShare{c, id}
	}
	return shares, nil
}

func serializeSignRequest(m, r *big.Int, kmap map[uint64][][]byte) ([]byte, error) {
	var buf bytes.Buffer
	if kmap != nil {
		if _, err := buf.Write([]byte{0}); err != nil {
			return nil, err
		}
		return serializeJointShareAll(&buf, kmap)
	} else {
		if _, err := buf.Write([]byte{1}); err != nil {
			return nil, err
		}
		return serializeDSAParameters(&buf, m, r)
	}
}

func parseSignRequest(data []byte, id uint64) (m, r *big.Int, share [][]byte, err error) {
	rdr := bytes.NewReader(data)
	phase, err := rdr.ReadByte()
	if err != nil {
		return
	}
	if phase == 0 {
		share, err = parseJointShareById(rdr, id)
	} else {
		m, r, err = parseDSAParameters(rdr)
	}
	return
}

func serializeDSAParameters(buf *bytes.Buffer, m, r *big.Int) ([]byte, error) {
	if err := packet.WriteBigInt(buf, m); err != nil {
		return nil, err
	}
	if err := packet.WriteBigInt(buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseDSAParameters(rdr *bytes.Reader) (m, r *big.Int, err error) {
	m, err = packet.ReadBigInt(rdr)
	if err == nil {
		r, err = packet.ReadBigInt(rdr)
	}
	return
}

func serializeJointShareAll(buf *bytes.Buffer, kmap map[uint64][][]byte) ([]byte, error) {
	n := uint16(len(kmap))
	if err := binary.Write(buf, binary.BigEndian, n); err != nil {
		return nil, err
	}
	for id, shares := range kmap {
		if err := binary.Write(buf, binary.BigEndian, id); err != nil {
			return nil, err
		}
		n := uint16(len(shares))
		if err := binary.Write(buf, binary.BigEndian, n); err != nil {
			return nil, err
		}
		for _, share := range shares {
			if err := packet.WriteChunk(buf, share); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func parseJointShareById(r *bytes.Reader, selfId uint64) ([][]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	for ; n > 0; n-- {
		var id uint64
		if err := binary.Read(r, binary.BigEndian, &id); err != nil {
			return nil, err
		}
		var nshares uint16
		if err := binary.Read(r, binary.BigEndian, &nshares); err != nil {
			return nil, err
		}
		var shares [][]byte
		for ; nshares > 0; nshares-- {
			share, err := packet.ReadChunk(r)
			if err != nil {
				return nil, err
			}
			shares = append(shares, share)
		}
		if selfId == id {
			return shares, nil
		}
	}
	return nil, crypto.ErrShareNotFound
}

func serializeCoord(buf *bytes.Buffer, coord *sss.Coordinate) error {
	if err := binary.Write(buf, binary.BigEndian, uint64(coord.X)); err != nil {
		return err
	}
	if err := packet.WriteBigInt(buf, coord.Y); err != nil {
		return err
	}
	return nil
}

func parseCoord(r *bytes.Reader) (*sss.Coordinate, error) {
	var x uint64
	if err := binary.Read(r, binary.BigEndian, &x); err != nil {
		return nil, err
	}
	y, err := packet.ReadBigInt(r)
	if err != nil {
		return nil, err
	}
	return &sss.Coordinate{
		X: int(x),
		Y: y,
	}, nil
}

func serializePartialSignature(group GroupOperations, x int, s []byte, v *big.Int) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint64(x)); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(&buf, s); err != nil {
		return nil, err
	}
	if err := packet.WriteBigInt(&buf, v); err != nil {
		return nil, err
	}
	if err := group.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parsePartialSignature(g Group, data []byte) (group GroupOperations, x int, s []byte, v *big.Int, err error) {
	r := bytes.NewReader(data)
	var xx uint64
	if err = binary.Read(r, binary.BigEndian, &xx); err == nil {
		x = int(xx)
		if s, err = packet.ReadChunk(r); err == nil {
			if v, err = packet.ReadBigInt(r); err == nil {
				group, err = g.ParseParams(r)
			}
		}
	}
	return
}
