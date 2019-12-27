// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/crypto/sss"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/packet"
)

type AuthPartialSecret struct {
	sss.Coordinate
	salt []byte
	a2   *big.Int // a': the second random exp
	Xi   []byte
	Ni   []byte
	Pi   []byte
	keys AuthKey
}

type AuthClient struct {
	password   []byte
	a          *big.Int // a: the primary random exp
	gs         *big.Int // shared secret g_pi^(a*S)
	X          *big.Int
	secrets    map[uint64]*AuthPartialSecret
	k, n       int
	nresponses int
}

type AuthServer struct {
	params   *AuthParams
	proof    []byte
	attempts int
	keys     AuthKey
	mac      []byte
}

type AuthParams struct {
	x    int
	y    *big.Int
	v    *big.Int
	salt []byte
}

const (
	MAC_KEY_SIZE = 16
	ENC_KEY_SIZE = 16
)

type AuthKey struct {
	km [MAC_KEY_SIZE]byte // mac key
	ke [ENC_KEY_SIZE]byte // enc key
}

const (
	AUTH_MIN_DURATION = (10 * time.Second) // 10 sec
	AUTH_DELAY_RATE   = (1 * time.Second)  // increase 1 sec per retry
	AUTH_RETRY_LIMIT  = 10
)

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
	p   *big.Int = new(big.Int).SetBytes(pb)
	phi *big.Int = new(big.Int).Sub(p, big.NewInt(1))
	q   *big.Int = new(big.Int).Div(phi, big.NewInt(2))
)

func GeneratePartialAuthenticationParams(cred []byte, n, k int) ([][]byte, error) {
	// calculate sss coordinates
	s, err := rand.Int(rand.Reader, q) // the secret
	if err != nil {
		return nil, err
	}
	coordinates, err := sss.Distribute(s, n, k, q)
	if err != nil {
		return nil, err
	}

	// g_pi = pi^2 mod p
	pi := PI(cred)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var res [][]byte
	for i := 0; i < n; i++ {
		c := coordinates[i]
		var params AuthParams
		params.x = c.X
		params.y = c.Y
		params.salt = hash(salt, []byte{byte(i)})
		si := new(big.Int).SetBytes(hash(cred, params.salt)) // si = hash(pass, hash(salt, i))
		si.Mod(si.Mul(si, s), q)
		params.v = new(big.Int).Exp(pi, si, p) // vi = g_pi^(S*si)

		ss, err := serializeParams(&params)
		if err != nil {
			return nil, err
		}
		res = append(res, ss)
	}
	return res, nil
}

func NewServer(ss []byte, proof []byte) (*AuthServer, error) {
	params, err := parseParams(ss)
	if err != nil {
		return nil, err
	}
	return &AuthServer{
		params:   params,
		proof:    proof,
		attempts: 0,
	}, nil
}

func (s *AuthServer) MakeResponse(phase int, req []byte) (res []byte, done bool, err error) {
	switch phase {
	case 0:
		res, err = s.makeYi(req)
		if err != nil {
			return
		}
		// check if this is a retry
		delay := time.Duration(s.attempts) * AUTH_DELAY_RATE
		if delay > 0 {
			time.Sleep(delay)
		}
		s.attempts++
		if s.attempts >= AUTH_RETRY_LIMIT {
			err = crypto.ErrAuthTooManyAttempts
			return
		}
		done = false
	case 1:
		res, err = s.makeBi(req)
		done = false
	case 2:
		res, err = s.makeZi(req)
		done = true
	}
	return
}

func (s *AuthServer) makeYi(X []byte) (res []byte, err error) {
	Yi := new(big.Int).SetBytes(X)
	Yi.Exp(Yi, s.params.y, p)
	return serializeYi(s.params.x, Yi, s.params.salt)
}

func (s *AuthServer) makeBi(Xi []byte) (res []byte, err error) {
	b, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}

	// Bi = v_i^b
	Bi := new(big.Int)
	Bi.Exp(s.params.v, b, p)

	// Ki = Xi^b
	Ki := new(big.Int).SetBytes(Xi)
	Ki.Exp(Ki, b, p)
	if err := keySched(&s.keys, Ki.Bytes(), s.params.salt); err != nil {
		return nil, err
	}

	// Ni = MAC(Xi || Bi)
	s.mac = calculateMac(s.keys.km, Xi, Bi.Bytes())

	return serializeBi(Bi)
}

func (s *AuthServer) makeZi(Ni []byte) (res []byte, err error) {
	// check the MAC
	if subtle.ConstantTimeCompare(Ni, s.mac) != 1 {
		return nil, bftkv.ErrAuthenticationFailure
	}

	// encrypt the data with ks
	Zi, nonce, err := encrypt(s.keys.ke, s.proof, s.mac)
	if err != nil {
		return nil, err
	}
	return serializeZi(Zi, nonce)
}

func NewClient(cred []byte, n, k int) *AuthClient {
	return &AuthClient{
		password: cred,
		secrets:  make(map[uint64]*AuthPartialSecret),
		k:        k,
		n:        n,
	}
}

func (c *AuthClient) Initiate(nodes []node.Node) (map[uint64][]byte, error) {
	X, err := c.generateX()
	if err != nil {
		return nil, err
	}
	res := make(map[uint64][]byte)
	for _, peer := range nodes {
		res[peer.Id()] = X
	}
	return res, nil
}

func (c *AuthClient) ProcessResponse(phase int, data []byte, peer node.Node) (res map[uint64][]byte, err error) {
	switch phase {
	case 0:
		res, err = c.processYi(data, peer.Id())
		if err != nil {
			return
		}
	case 1:
		res, err = c.processBi(data, peer.Id())
		if err != nil {
			return
		}
	case 2:
		res, err = c.processZi(data, peer.Id())
		if err != nil {
			return
		}
	}
	return
}

func (c *AuthClient) Done(phase int) bool {
	return phase > 2
}

func (c *AuthClient) GetCipherKey() ([]byte, error) {
	if c.gs == nil {
		return nil, crypto.ErrInsufficientNumberOfSecrets
	}
	ainv := new(big.Int).ModInverse(c.a, q)
	gs := new(big.Int).Exp(c.gs, ainv, p)
	return hash(gs.Bytes(), c.password), nil
}

func (c *AuthClient) generateX() ([]byte, error) {
	a, err := rand.Int(rand.Reader, q)
	if err != nil {
		return nil, err
	}
	X := new(big.Int).Exp(PI(c.password), a, p)
	c.a = a
	return X.Bytes(), nil
}

func (c *AuthClient) processYi(res []byte, id uint64) (map[uint64][]byte, error) {
	x, Yi, salt, err := parseYi(res)
	if err != nil {
		return nil, err
	}
	c.secrets[id] = &AuthPartialSecret{sss.Coordinate{X: x, Y: Yi}, salt, nil, nil, nil, nil, AuthKey{}}
	if len(c.secrets) >= c.k {
		c.gs = c.calculateSharedSecret()
		Xis := make(map[uint64][]byte)
		for i, secret := range c.secrets {
			a2, err := rand.Int(rand.Reader, q)
			if err != nil {
				return nil, nil
			}
			secret.a2 = a2
			si := new(big.Int).SetBytes(hash(c.password, secret.salt))
			e := new(big.Int).Mod(new(big.Int).Mul(a2, si), q)
			Xi := new(big.Int).Exp(c.gs, e, p)
			secret.Xi = Xi.Bytes()
			Xis[i] = secret.Xi
		}
		c.nresponses = 0
		return Xis, nil
	}
	return nil, nil
}

func (c *AuthClient) processBi(res []byte, id uint64) (map[uint64][]byte, error) {
	Bi, err := parseBi(res)
	if err != nil {
		return nil, err
	}
	secret, ok := c.secrets[id]
	if !ok {
		return nil, crypto.ErrNoAuthenticationData
	}

	// Ki = Bi^{aa'}
	e := new(big.Int).Mul(c.a, secret.a2)
	e.Mod(e, q)
	Ki := new(big.Int).Exp(Bi, e, p)
	keySched(&secret.keys, Ki.Bytes(), secret.salt)
	secret.Ni = calculateMac(secret.keys.km, secret.Xi, Bi.Bytes())

	c.nresponses++
	if c.nresponses >= len(c.secrets) {
		N := make(map[uint64][]byte)
		for i, secret := range c.secrets {
			N[i] = secret.Ni
		}
		c.nresponses = 0
		return N, nil
	}
	return nil, nil
}

func (c *AuthClient) processZi(res []byte, id uint64) (map[uint64][]byte, error) {
	Zi, nonce, err := parseZi(res)
	if err != nil {
		return nil, err
	}
	secret, ok := c.secrets[id]
	if !ok {
		return nil, crypto.ErrNoAuthenticationData
	}

	secret.Pi, err = decrypt(secret.keys.ke, Zi, secret.Ni, nonce)
	if err != nil {
		return nil, crypto.ErrDecryptionFailed
	}

	c.nresponses++
	if c.nresponses >= len(c.secrets) {
		P := make(map[uint64][]byte)
		for i, secret := range c.secrets {
			P[i] = secret.Pi
		}
		return P, nil
	}
	return nil, nil
}

func (c *AuthClient) calculateSharedSecret() *big.Int {
	// g^s = (g^(y0))^l0 * (g^(y1))^l1 * ...
	gs := big.NewInt(1)
	var xs []int
	for _, s := range c.secrets {
		xs = append(xs, s.X)
	}
	for _, s := range c.secrets {
		l := sss.Lagrange(s.X, xs, q)
		t := new(big.Int).Exp(s.Y, l, p)
		gs.Mod(gs.Mul(gs, t), p)
	}
	return gs
}

func PI(password []byte) *big.Int {
	t := new(big.Int)
	t.SetBytes(hash(password))
	return t.Mod(t.Mul(t, t), q)
}

func hash(args ...[]byte) []byte {
	sha := sha256.New()
	for _, arg := range args {
		sha.Write(arg)
	}
	return sha.Sum(nil)
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
	params.x = int(t)
	if params.y, err = readBigInt(r); err != nil {
		return nil, err
	}
	if params.v, err = readBigInt(r); err != nil {
		return nil, err
	}
	if params.salt, err = packet.ReadChunk(r); err != nil {
		return nil, err
	}
	return params, nil
}

func serializeYi(x int, Y *big.Int, salt []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(x)); err != nil {
		return nil, err
	}
	if err := writeBigInt(buf, Y); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(buf, salt); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseYi(res []byte) (x int, Y *big.Int, salt []byte, err error) {
	r := bytes.NewReader(res)
	var t int32
	if err = binary.Read(r, binary.BigEndian, &t); err != nil {
		return
	}
	x = int(t)
	if Y, err = readBigInt(r); err != nil {
		return
	}
	if salt, err = packet.ReadChunk(r); err != nil {
		return
	}
	return
}

func serializeBi(Bi *big.Int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := writeBigInt(buf, Bi); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseBi(res []byte) (Bi *big.Int, err error) {
	r := bytes.NewReader(res)
	if Bi, err = readBigInt(r); err != nil {
		return
	}
	return
}

func serializeZi(Zi []byte, nonce []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := packet.WriteChunk(buf, Zi); err != nil {
		return nil, err
	}
	if err := packet.WriteChunk(buf, nonce); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseZi(res []byte) (Zi []byte, nonce []byte, err error) {
	r := bytes.NewReader(res)
	if Zi, err = packet.ReadChunk(r); err != nil {
		return
	}
	if nonce, err = packet.ReadChunk(r); err != nil {
		return
	}
	return
}

func keySched(keys *AuthKey, ks []byte, salt []byte) error {
	hkdf := hkdf.New(sha256.New, ks, salt, nil)
	if _, err := io.ReadFull(hkdf, keys.km[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(hkdf, keys.ke[:]); err != nil {
		return err
	}
	return nil
}

func calculateMac(km [MAC_KEY_SIZE]byte, Xi []byte, Bi []byte) []byte {
	hmac := hmac.New(sha256.New, km[:])
	hmac.Write(Xi)
	hmac.Write(Bi)
	return hmac.Sum(nil)
}

func encrypt(ke [ENC_KEY_SIZE]byte, plain []byte, adata []byte) (res []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(ke[:])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize()) // random nonce is ok as the key is never reused
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	res = aead.Seal(nil, nonce, plain, adata)
	return res, nonce, nil
}

func decrypt(ke [ENC_KEY_SIZE]byte, ciphertext []byte, adata []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(ke[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, adata)
}
