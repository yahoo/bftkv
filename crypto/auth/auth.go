// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"math/big"
	"encoding/binary"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/packet"
)

type Auth struct {
}

type AuthPartialSecret struct {
	x int
	y *big.Int
	B *big.Int
}

type AuthClient struct {
	password []byte
	pi *big.Int
	a *big.Int	// random exp
	a2 *big.Int	// a - g^pi
	ss *big.Int
	X *big.Int
	results map[uint64]*AuthPartialSecret
}

type AuthParams struct {
	x int
	y *big.Int
	v *big.Int
	salt []byte
	k, n int
}

const SALT_SIZE = 16

var (
	// has to be a safe prime, i.e., p = 2q + 1
	pb = []byte{
		0xb0, 0xa6, 0x7d, 0x9f, 0x5c, 0xeb, 0xc0, 0xff, 0xe8,
		0x16, 0x90, 0xe7, 0xb2, 0x67, 0x0a, 0xb0, 0x5f, 0x9f,
		0xa4, 0xc2, 0xe7, 0x36, 0x39, 0xf6, 0x60, 0xc0, 0x40,
		0x8a, 0x2d, 0x9a, 0x4a, 0x8b, 0x45, 0x4a, 0x98, 0x93,
		0xfd, 0x7d, 0x4e, 0x8f, 0xa3, 0x99, 0xcf, 0xc9, 0xc9,
		0xba, 0x05, 0xb0, 0x80, 0xf9, 0x03, 0xe3, 0x3b, 0xcd,
		0xcb, 0xef, 0xae, 0xd4, 0x09, 0x15, 0xe5, 0x1d, 0x46,
		0xf5, 0x8d, 0x1a, 0x5b, 0xd2, 0x04, 0xdb, 0x20, 0xfa,
		0x3f, 0xe9, 0xdb, 0x71, 0xf0, 0xb8, 0xe0, 0xaa, 0x87,
		0xb5, 0x77, 0x14, 0x06, 0xf2, 0x5f, 0xad, 0x59, 0xe7,
		0xf1, 0x0f, 0xe5, 0x25, 0x56, 0x44, 0x75, 0x88, 0x72,
		0xea, 0x2d, 0xec, 0x1f, 0x6d, 0xcd, 0x11, 0xbe, 0x90,
		0x5d, 0xe5, 0x9a, 0x04, 0x4f, 0x6c, 0x2e, 0xa3, 0x98,
		0x2b, 0x22, 0x35, 0xac, 0xc9, 0x02, 0x1a, 0x19, 0x6f,
		0xc4, 0xce, 0x0b, 0x19, 0xf6, 0xb3, 0x12, 0xee, 0x9c,
		0xfc, 0x59, 0x97, 0xdc, 0x5f, 0x7c, 0xe2, 0xf3, 0x86,
		0x13, 0x12, 0x94, 0xa5, 0x6b, 0xa9, 0x3a, 0x41, 0xa3,
		0xb6, 0x0e, 0x27, 0xe0, 0x39, 0x56, 0x03, 0x9f, 0x51,
		0xae, 0x73, 0xb8, 0x9c, 0x79, 0x5c, 0x5a, 0xe7, 0xd8,
		0x41, 0xe9, 0xb4, 0x55, 0xc3, 0x73, 0x41, 0xc0, 0x52,
		0x40, 0x4e, 0x8f, 0xe9, 0xfe, 0x4f, 0x0d, 0x52, 0xbc,
		0x16, 0x2a, 0x41, 0xf1, 0xee, 0xb9, 0xef, 0x29, 0x2c,
		0x66, 0xa9, 0xd6, 0xa6, 0x19, 0xaa, 0x54, 0x88, 0x07,
		0xeb, 0x11, 0x87, 0xee, 0x22, 0xbd, 0x62, 0xe2, 0x0e,
		0x26, 0xc3, 0xc0, 0x8c, 0x22, 0xec, 0xef, 0x12, 0xd3,
		0xb2, 0x30, 0x4a, 0x01, 0x0e, 0xd1, 0xf5, 0x0a, 0x68,
		0xe0, 0x26, 0x1a, 0xfe, 0x1a, 0x0b, 0xdd, 0xdf, 0x7a,
		0xb8, 0xa6, 0x17, 0x74, 0xd3, 0xaf, 0x3f, 0x1c, 0xce,
		0x2b, 0x95, 0xda, 0xd3,
	}
	gb = []byte{3}
	p *big.Int
	phi *big.Int
	q *big.Int
	g *big.Int
	k *big.Int
	nonce = []byte{0x94, 0x33, 0xa0, 0x1b, 0xcc, 0x09, 0x20, 0x6f}
)

func NewAuth() crypto.Authentication {
	if p == nil {
		// p = 2q + 1
		p = new(big.Int).SetBytes(pb)
		phi = new(big.Int).Sub(p, big.NewInt(1))
		q = new(big.Int).Div(phi, big.NewInt(2))
	}
	if g == nil {
		g = new(big.Int).SetBytes(gb)
	}
	if k == nil {
		k = new(big.Int).SetBytes(hash(pb, gb))
	}
	return &Auth{}
}

func (a *Auth) GeneratePartialAuthenticationData(cred []byte, n, k int) ([][]byte, error) {
	// generate a (k-1)-degree polynomial (on q)
	poly := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		coeff, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		poly[i] = coeff
	}

	// pi = h(cred, salt), g^pi
	salt := make([]byte, SALT_SIZE)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	pi := PI(cred, salt)

	// x = pi * g^s, v = g^x
	x := new(big.Int)
	s := poly[0]
	x.Mod(x.Mul(pi, x.Exp(g, s, p)), p)
	v := new(big.Int).Exp(g, x, p)

	var res [][]byte
	t := new(big.Int)
	gpi := new(big.Int).Exp(g, PI(cred, nil), q)	// salt = nil
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		f := new(big.Int).Set(poly[0])
		for j := 1; j < k; j++ {
			f.Add(f, t.Mul(poly[j], x))
			f.Mod(f, q)
			x.Mul(x, x)
		}
		var params AuthParams
		params.x = i
		params.y = new(big.Int).Mod(t.Add(f, gpi), q)	// f(i) + g^pi
		params.v = v
		params.salt = salt
		params.n = n
		params.k = k
		ss, err := serializeParams(&params)
		if err != nil {
			return nil, err
		}
		res = append(res, ss)
	}
	return res, nil
}

func (a *Auth) MakeResponse(ss []byte, challenge []byte, plain []byte) (res []byte, cipherData []byte, err error) {
	params, err := parseParams(ss)
	if err != nil {
		return nil, nil, err
	}
	b, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, nil, err
	}

	// Bi = kv + g^b
	t1 := new(big.Int)
	t2 := new(big.Int)
	kv := t1.Mod(t1.Mul(k, params.v), p)
	Bi := t2.Mod(t2.Add(kv, t2.Exp(g, b, p)), p)

	// KS = (X * v^u)^b
	t := new(big.Int)
	X := new(big.Int).SetBytes(challenge)
	u := new(big.Int).SetBytes(hash(challenge, Bi.Bytes()))
	t.Exp(t.Mod(t.Mul(X, t.Exp(params.v, u, p)), p), b, p)
	ks := t.Bytes()

	// Yi = X*g^y
	Yi := new(big.Int).Mod(new(big.Int).Mul(X, new(big.Int).Exp(g, params.y, p)), p)	// g^(a+fi)

	// encrypt the data with ks
	block, err := aes.NewCipher(hash(ks))
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	cipherData = aead.Seal(nil, genNonce(aead.NonceSize()), plain, append(X.Bytes(), Bi.Bytes()...))
	res, err = serializeResponse(Yi, params.x, Bi, params.salt, params.k)
	return
}

func (a *Auth) NewClient(cred []byte) crypto.AuthenticationClient {
	return &AuthClient{
		password: cred,
		results: make(map[uint64]*AuthPartialSecret),
	}
}

func (c *AuthClient) GenerateAuthenticationData() ([]byte, error) {
	a, err := rand.Int(rand.Reader, q)
	if err != nil {
		return nil, err
	}
	gpi := new(big.Int).Exp(g, PI(c.password, nil), q)	// salt = nil
	c.a = a
	t := new(big.Int).Sub(a, gpi)
	t.Mod(t, q)
	c.a2 = t
	c.X = new(big.Int).Exp(g, t, p)		// g^(a - g^pi)
	return c.X.Bytes(), nil
}

func (c *AuthClient) ProcessAuthResponse(res []byte, id uint64) (bool, error) {
	Yi, x, Bi, salt, k, err := parseResponse(res)
	if err != nil {
		return false, nil
	}

	c.pi = PI(c.password, salt)
	inv := new(big.Int).Sub(q, c.a)		// t = -a mod q
	gy := new(big.Int).Mul(Yi, new(big.Int).Exp(g, inv, p))		// Yi*t = g^(a+f(i))*g^-a = g^f(i)
	gy.Mod(gy, p)

	c.results[id] = &AuthPartialSecret{x, gy, Bi}
	if len(c.results) == k {	// k: take the lastest one
		c.ss = c.calculateSharedSecret()
		return true, nil
	}
	return false, nil
}

func (c *AuthClient) calculateSharedSecret() *big.Int {
	// g^s = (g^(y0))^l0 * (g^(y1))^l1 * ... 
	gs := big.NewInt(1)
	for _, res := range c.results {
		l := c.lagrange(res.x)
		t := new(big.Int).Exp(res.y, l, p)
		gs.Mod(gs.Mul(gs, t), p)
	}
	return gs
}

func (c *AuthClient) getSessionKey(id uint64) ([]byte, error) {
	if c.ss == nil {
		return nil, crypto.ErrInsufficientNumberOfSecrets
	}
	result, ok := c.results[id]
	if !ok {
		return nil, crypto.ErrKeyNotFound
	}

	// x = pi * g^s
	x := new(big.Int)
	x.Mul(c.pi, c.ss)
	x.Mod(x, p)

	// u = H(X, Bi)
	Bi := result.B
	u := new(big.Int).SetBytes(hash(c.X.Bytes(), Bi.Bytes()))
	// (Bi - kg^x)^(a+ux)
	t := new(big.Int)
	e := new(big.Int)
	t.Mod(t.Sub(Bi, t.Mod(t.Mul(k, t.Exp(g, x, p)), p)), p)	// Bi - kg^x
	e.Mod(e.Add(c.a2, e.Mod(e.Mul(u, x), phi)), phi)	// e=a+ux
	return new(big.Int).Exp(t, e, p).Bytes(), nil		// ks = (Bi - kg^x)^e
}

func (c *AuthClient) Decrypt(id uint64, cipherData []byte) ([]byte, error) {
	ks, err := c.getSessionKey(id)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(hash(ks))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	Bi := c.results[id].B
	plain, err := aead.Open(nil, genNonce(aead.NonceSize()), cipherData, append(c.X.Bytes(), Bi.Bytes()...))
	if err != nil {
		return nil, crypto.ErrDecryptionFailed
	}
	return plain, err
}

func (c *AuthClient) GetCipherKey() []byte {
	t := new(big.Int)
	return hash(t.Mod(t.Mul(c.pi, c.ss), p).Bytes())
}

func (c *AuthClient) lagrange(x int) *big.Int {
	a := big.NewInt(1)
	b := big.NewInt(1)
	xj := big.NewInt(int64(x))
	for _, res := range c.results {
		if res.x == x {
			continue
		}
		xm := big.NewInt(int64(res.x))
		a.Mul(a, xm)
		b.Mul(b, new(big.Int).Sub(xm, xj))
	}
	a.Mod(a.Mul(a, b.ModInverse(b, q)), q)
	return a
}

func PI(password, salt []byte) *big.Int {
	t := new(big.Int)
	t.SetBytes(hash(password, salt))
	return t.Mod(t, q)
}

func hash(args ...[]byte) []byte {
	sha := sha256.New()
	for _, arg := range args {
		sha.Write(arg)
	}
	return sha.Sum(nil)
}

func genNonce(sz int) []byte {
	var res []byte
	for len(res) < sz {
		res = append(res, nonce...)
	}
	return res[0:sz]
}

func writeBigInt(w *bytes.Buffer, b *big.Int) error {
	return packet.WriteChunk(w, b.Bytes())
}

func readBigInt(r *bytes.Reader) (*big.Int, error) {
	c, err := packet.ReadChunk(r)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(c), nil
}

func serializeParams(params *AuthParams) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(params.x)); err != nil {
		return nil, err
	}
	if err := writeBigInt(buf, params.y); err != nil {
		return nil, err
	}
	if err := writeBigInt(buf, params.v); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(buf, params.salt); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(params.k)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(params.n)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseParams(ss []byte) (*AuthParams, error) {
	params := &AuthParams{}
	r := bytes.NewReader(ss)
	var t int32
	var err error
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return nil, err
	}
	params.x = int(t);
	if params.y, err = readBigInt(r); err != nil {
		return nil, err
	}
	if params.v, err = readBigInt(r); err != nil {
		return nil, err
	}
	if params.salt, err = packet.ReadChunk(r); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return nil, err
	}
	params.k = int(t)
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return nil, err
	}
	params.n = int(t)
	return params, nil
}

func serializeResponse(Y *big.Int, x int, B *big.Int, salt []byte, k int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := writeBigInt(buf, Y); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(x)); err != nil {
		return nil, err
	}
	if err := writeBigInt(buf, B); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(buf, salt); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(k)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseResponse(res []byte) (Y *big.Int, x int, B *big.Int, salt []byte, k int, err error) {
	r := bytes.NewReader(res)
	var t int32
	if Y, err = readBigInt(r); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return
	}
	x = int(t)
	if B, err = readBigInt(r); err != nil {
		return
	}
	if salt, err = packet.ReadChunk(r); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return
	}
	k = int(t)
	return
}
