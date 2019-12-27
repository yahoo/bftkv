// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package rsa

import (
	"bytes"
	gocrypto "crypto"
	"crypto/rand"
	gorsa "crypto/rsa"
	"encoding/binary"
	"math/big"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
	//	"fmt"
)

type partialParam struct {
	keys map[uint32]*big.Int
	N    *big.Int
	id   uint32
	n    int
}

//
// client API
//
type rsaContext struct {
	crypt *crypto.Crypto
	n, k  int
	nodes []node.Node
}

type paramTree struct {
	idx      uint32
	di       *big.Int
	children map[uint32]*paramTree
}

func New(crypt *crypto.Crypto) crypto.Threshold {
	return &rsaContext{
		crypt: crypt,
	}
}

func (ctx *rsaContext) Distribute(key interface{}, nodes []node.Node, k int) (shares [][]byte, algo crypto.ThresholdAlgo, err error) {
	ctx.nodes = nodes
	ctx.n = len(ctx.nodes)
	ctx.k = k
	priv := key.(*gorsa.PrivateKey)
	kt, err := makeKeyTree(priv.D, 0, ctx.n, ctx.k)
	if err != nil {
		return nil, algo, err
	}
	for i := 0; i < ctx.n; i++ {
		keys := make(map[uint32]*big.Int)
		collectKeys(kt, uint32(i), keys)
		params := &partialParam{
			keys: keys,
			N:    priv.N,
			id:   uint32(i),
			n:    ctx.n,
		}
		secret, err := serializePartialParam(params)
		if err != nil {
			return nil, algo, err
		}
		shares = append(shares, secret)
	}
	return shares, crypto.TH_RSA, nil
}

func makeKeyTree(key *big.Int, idx uint32, n, k int) (*paramTree, error) {
	d := depth(idx, n)
	if d > n-k {
		return &paramTree{idx, key, nil}, nil
	}
	di, err := splitKey(key, n-d)
	if err != nil {
		return nil, err
	}
	tr := &paramTree{idx, key, make(map[uint32]*paramTree)}
	for i, j := 0, 0; i < n; i++ {
		if !inPath(uint32(i), idx, n) {
			c, err := makeKeyTree(di[j], idx*uint32(n)+uint32(i)+1, n, k)
			if err != nil {
				return nil, err
			}
			tr.children[uint32(i)] = c
			j++
		}
	}
	return tr, nil
}

func splitKey(d *big.Int, n int) ([]*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(d.BitLen()*2))
	di := make([]*big.Int, n)
	sum := new(big.Int)
	for i := 0; i < n-1; i++ {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		sign := x.Bit(0)
		x.Rsh(x, 1)
		if sign != 0 {
			x.Neg(x)
		}
		di[i] = x
		sum.Add(sum, x)
	}
	di[n-1] = new(big.Int).Sub(d, sum)
	return di, nil
}

func collectKeys(tr *paramTree, i uint32, keys map[uint32]*big.Int) {
	for j, c := range tr.children {
		if j == i {
			keys[tr.idx] = c.di
		} else {
			collectKeys(c, i, keys)
		}
	}
}

func depth(idx uint32, n int) int {
	d := 0
	for ; idx != 0; idx = (idx - 1) / uint32(n) {
		d++
	}
	return d
}

//
// server API
//
func (ctx *rsaContext) Sign(sec []byte, req []byte, peerId, selfId uint64) ([]byte, error) {
	// parse the request
	keys, hinfo, err := parseSignRequest(req)
	if err != nil {
		return nil, err
	}

	// parse the saved parameter
	params, err := parsePartialParam(sec)
	if err != nil {
		return nil, err
	}

	// support only pkcs1.5 EMSA encode
	m, err := emsaEncode(hinfo, params.N)
	if err != nil {
		return nil, err
	}

	// sign with each fragmented key that constructs the spcified keys
	sigs := make(map[uint32]*big.Int)
	for _, kid := range keys {
		if di, ok := params.keys[kid]; ok {
			ci := new(big.Int)
			if di.Sign() < 0 {
				ci.Exp(m, di.Neg(di), params.N)
				ci.ModInverse(ci, params.N)
			} else {
				ci.Exp(m, di, params.N)
			}
			sigs[kid*uint32(params.n)+params.id+1] = ci
		}
	}
	if len(sigs) == 0 {
		return nil, nil
	} else {
		return serializePartialSignature(sigs, params.N)
	}
}

//
// client process
//
type sigTree struct {
	idx       uint32
	psig      *big.Int
	completed bool
	children  map[uint32]*sigTree
}

type rsaProc struct {
	nodes []node.Node
	n, k  int
	tree  *sigTree
	sig   []byte
	hinfo []byte
}

type hashInfo struct {
	prefix []byte
	dgst   []byte
}

func (ctx *rsaContext) NewProcess(tbs []byte, algo crypto.ThresholdAlgo, hash gocrypto.Hash) (crypto.ThresholdProcess, error) {
	// we do not know the original RSA parameters so we can't even encode TBS with PKCS1.5 at the client side
	hinfo, err := serializeHashInfo(hash, tbs)
	if err != nil {
		return nil, err
	}
	return &rsaProc{
		nodes: ctx.nodes,
		n:     ctx.n,
		k:     ctx.k,
		tree:  &sigTree{0, nil, false, nil},
		hinfo: hinfo,
	}, nil
}

/*
 * MakeRequest decides the strategy to collect partial signatures
 * - the current logic minimizes the amount of transaction data by strictly excluding fault nodes with zero tolerance
 * ProcessResponse should be able to handle any subset depending on the strategy without changing the logic
 */
func (p *rsaProc) MakeRequest() ([]node.Node, []byte, error) {
	keys := missingKeys(p.tree, []uint32{}, p.n, p.k)
	if keys == nil || len(keys) == 0 {
		return nil, nil, nil
	}
	encoded, err := serializeSignRequest(keys, p.hinfo)
	if err != nil {
		return nil, nil, err
	}
	return p.nodes, encoded, nil // always try to broadcast to all nodes in case some inactive nodes might have been back online
}

func (p *rsaProc) ProcessResponse(data []byte, peer node.Node) ([]byte, error) {
	sigs, N, err := parsePartialSignature(data)
	if err != nil {
		return nil, err
	}
	if p.sig != nil {
		return p.sig, nil
	}

	for idx, s := range sigs {
		registerPartialSignature(p.tree, idx, s, depth(idx, p.n), p.n)
	}
	if p.tree.completed { // we got all keys!
		s := big.NewInt(1)
		calculateSignature(p.tree, s, N)
		p.sig = I2OS(s, (N.BitLen()+7)/8)
	}
	return p.sig, nil
}

func inPath(i uint32, path uint32, n int) bool {
	for ; path != 0; path = (path - 1) / uint32(n) {
		if i == (path-1)%uint32(n) {
			return true
		}
	}
	return false
}

func missingKeys(st *sigTree, keys []uint32, n, k int) []uint32 {
	if st == nil || st.completed {
		return keys
	}
	if st.children == nil || len(st.children) == 0 {
		keys = append(keys, st.idx)
	} else {
		if depth(st.idx, n) >= n-k {
			// too deep...
			return keys
		}
		for i := 0; i < n; i++ {
			if inPath(uint32(i), st.idx, n) {
				continue
			}
			c, ok := st.children[uint32(i)]
			if !ok {
				keys = append(keys, st.idx*uint32(n)+uint32(i)+1)
			} else if !c.completed {
				keys = missingKeys(c, keys, n, k)
			}
		}
	}
	return keys
}

func registerPartialSignature(st *sigTree, idx uint32, psig *big.Int, d int, n int) {
	self := idx // idx never be 0
	for j := 0; j < d-1; j++ {
		self = (self - 1) / uint32(n)
	}
	i := (self - 1) % uint32(n)
	if st.children == nil {
		st.children = make(map[uint32]*sigTree)
	}
	c, ok := st.children[i]
	if !ok {
		if d <= 1 {
			c = &sigTree{self, psig, true, nil}
		} else {
			c = &sigTree{self, nil, false, nil}
		}
		st.children[i] = c
	}
	if d > 1 {
		registerPartialSignature(c, idx, psig, d-1, n)
	}

	// check if we got partial sigs from all children
	if len(st.children) >= n-depth(st.idx, n) {
		st.completed = completed(st)
	}
}

func calculateSignature(st *sigTree, s *big.Int, N *big.Int) {
	if !st.completed {
		return
	}
	if st.psig != nil {
		s.Mod(s.Mul(s, st.psig), N)
		return
	}
	for _, c := range st.children {
		calculateSignature(c, s, N)
	}
}

func completed(st *sigTree) bool {
	for _, c := range st.children {
		if !c.completed {
			return false
		}
	}
	return true
}

//
// marshaling
//

// copied from https://golang.org/src/crypto/rsa/pkcs1v15.go
var hashPrefixes = map[gocrypto.Hash][]byte{
	gocrypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	gocrypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	gocrypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	gocrypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	gocrypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	gocrypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	gocrypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	gocrypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

func emsaEncode(hinfo *hashInfo, N *big.Int) (*big.Int, error) {
	emlen := (N.BitLen() + 7) / 8
	mlen := len(hinfo.prefix) + len(hinfo.dgst)
	padlen := emlen - mlen
	if padlen < 3 {
		return nil, crypto.ErrInvalidInput
	}
	em := make([]byte, emlen)
	i := 0
	em[i] = 0x00
	i++ // make the em size the same as modulus size
	em[i] = 0x01
	i++
	for ; i < padlen-1; i++ {
		em[i] = 0xff
	}
	em[i] = 0x00
	i++
	copy(em[i:], hinfo.prefix)
	i += len(hinfo.prefix)
	copy(em[i:], hinfo.dgst)
	return OS2I(em), nil
}

func I2OS(b *big.Int, sz int) []byte {
	c := b.Bytes()
	if len(c) >= sz {
		return c
	}
	// prepend 0
	ret := make([]byte, sz)
	i := 0
	for ; i < sz-len(c); i++ {
		ret[i] = 0
	}
	copy(ret[i:], c)
	return ret
}

func OS2I(os []byte) *big.Int {
	return new(big.Int).SetBytes(os)
}

func serialize(keys [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for i := 0; i < len(keys); i++ {
		if err := packet.WriteChunk(&buf, keys[i]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func serializePartialParam(params *partialParam) ([]byte, error) {
	var buf bytes.Buffer
	l := len(params.keys)
	if err := binary.Write(&buf, binary.BigEndian, uint16(l)); err != nil {
		return nil, err
	}
	for idx, k := range params.keys {
		if err := binary.Write(&buf, binary.BigEndian, idx); err != nil {
			return nil, err
		}
		sign := k.Sign()
		if sign < 0 {
			sign = 1
		} else {
			sign = 0
		}
		if err := buf.WriteByte(byte(sign)); err != nil {
			return nil, err
		}
		if err := packet.WriteChunk(&buf, k.Bytes()); err != nil {
			return nil, err
		}
	}
	if err := packet.WriteChunk(&buf, params.N.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, params.id); err != nil {
		return nil, err
	}
	if err := buf.WriteByte(byte(params.n)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parsePartialParam(pkt []byte) (*partialParam, error) {
	params := &partialParam{}
	r := bytes.NewReader(pkt)
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	params.keys = make(map[uint32]*big.Int)
	for ; l != 0; l-- {
		var idx uint32
		if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
			return nil, err
		}
		sign, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		k, err := packet.ReadChunk(r)
		if err != nil {
			return nil, err
		}
		b := new(big.Int).SetBytes(k)
		if sign != 0 {
			b.Neg(b)
		}
		params.keys[idx] = b
	}
	N, err := packet.ReadChunk(r)
	if err != nil {
		return nil, err
	}
	params.N = new(big.Int).SetBytes(N)
	if err := binary.Read(r, binary.BigEndian, &params.id); err != nil {
		return nil, err
	}
	n, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	params.n = int(n)
	return params, nil
}

func serializeSignRequest(keys []uint32, hinfo []byte) ([]byte, error) {
	var buf bytes.Buffer
	l := len(keys)
	if err := binary.Write(&buf, binary.BigEndian, uint16(l)); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if err := binary.Write(&buf, binary.BigEndian, k); err != nil {
			return nil, err
		}
	}
	if err := packet.WriteChunk(&buf, hinfo); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseSignRequest(req []byte) ([]uint32, *hashInfo, error) {
	r := bytes.NewReader(req)
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, nil, err
	}
	keys := make([]uint32, l)
	for i := 0; i < int(l); i++ {
		if err := binary.Read(r, binary.BigEndian, &keys[i]); err != nil {
			return nil, nil, err
		}
	}
	h, err := packet.ReadChunk(r)
	if err != nil {
		return nil, nil, err
	}
	hinfo, err := parseHashInfo(h)
	if err != nil {
		return nil, nil, err
	}
	return keys, hinfo, nil
}

func serializeHashInfo(hash gocrypto.Hash, tbs []byte) ([]byte, error) {
	var buf bytes.Buffer
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return nil, crypto.ErrUnsupported
	}
	h := hash.New()
	h.Write(tbs)
	dgst := h.Sum(nil)
	if err := packet.WriteChunk(&buf, prefix); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(&buf, dgst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseHashInfo(data []byte) (*hashInfo, error) {
	r := bytes.NewReader(data)
	prefix, err := packet.ReadChunk(r)
	if err != nil {
		return nil, err
	}
	h, err := packet.ReadChunk(r)
	if err != nil {
		return nil, err
	}
	return &hashInfo{
		prefix: prefix,
		dgst:   h,
	}, nil
}

func serializePartialSignature(sigs map[uint32]*big.Int, N *big.Int) ([]byte, error) {
	var buf bytes.Buffer
	l := len(sigs)
	if err := binary.Write(&buf, binary.BigEndian, uint16(l)); err != nil {
		return nil, err
	}
	for idx, s := range sigs {
		if err := binary.Write(&buf, binary.BigEndian, idx); err != nil {
			return nil, err
		}
		if err := packet.WriteChunk(&buf, s.Bytes()); err != nil {
			return nil, err
		}
	}
	if err := packet.WriteChunk(&buf, N.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parsePartialSignature(data []byte) (sigs map[uint32]*big.Int, N *big.Int, err error) {
	r := bytes.NewReader(data)
	sigs = make(map[uint32]*big.Int)
	var l uint16
	if err = binary.Read(r, binary.BigEndian, &l); err != nil {
		return
	}
	for ; l > 0; l-- {
		var idx uint32
		if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
			return nil, nil, err
		}
		c, err := packet.ReadChunk(r)
		if err != nil {
			return nil, nil, err
		}
		sigs[idx] = new(big.Int).SetBytes(c)
	}
	c, err := packet.ReadChunk(r)
	if err != nil {
		return
	}
	N = new(big.Int).SetBytes(c)
	return
}
