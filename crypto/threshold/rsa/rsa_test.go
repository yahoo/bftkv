// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package rsa

import (
	"bytes"
	gocrypto "crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"testing"
	"time"

	//	"encoding/hex"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node"
)

const (
	testTBS = "tbs"
)

func TestSplitKey(t *testing.T) {
	key := readPKCS8("test.pkcs8")
	if key == nil {
		t.Fatal("couldn't read the key")
	}
	priv := key.(*rsa.PrivateKey)
	max := new(big.Int).Lsh(big.NewInt(1), uint(priv.D.BitLen()*2))
	d, err := crand.Int(crand.Reader, max)
	if err != nil {
		t.Fatal(err)
	}
	di, err := splitKey(d, 10)
	if err != nil {
		t.Fatal(err)
	}
	a := big.NewInt(0)
	for _, i := range di {
		a.Add(a, i)
	}
	if a.Cmp(d) != 0 {
		t.Fatal("mismatch")
	}
}

func TestDistribution(t *testing.T) {
	n, k := 10, 7
	key := readPKCS8("test.pkcs8")
	if key == nil {
		t.Fatal("couldn't read the key")
	}
	d := key.(*rsa.PrivateKey).D

	// make the param tree and dump it
	//	kt, err := makeKeyTree(d, 0, n, k)
	//	if err != nil {
	//		t.Fatal(err)
	//	}
	//	printTree(kt, 0)
	//	di := make(map[int]*big.Int)
	//	collectKeys(kt, 0, di)
	//	fmt.Printf("0:\n")
	//	for i, _ := range di {
	//		fmt.Printf("%d, ", i)
	//	}
	//	fmt.Printf("\n")

	ctx := New(nil)                                                // the argument won't be used
	params, _, err := ctx.Distribute(key, make([]node.Node, n), k) // nodes won't be used
	if err != nil {
		t.Fatal(err)
	}

	keys := make([]map[uint32]*big.Int, len(params))
	//	fmt.Printf("=== distributed keys ===\n")
	for i, p := range params {
		param, err := parsePartialParam(p)
		if err != nil {
			t.Fatal(err)
		}

		//		fmt.Printf("%d: [", i)
		//		for idx, _ := range param.keys {
		//			fmt.Printf("%d, ", idx)
		//		}
		//		fmt.Printf("]\n")

		keys[i] = param.keys
	}
	if !checkSum(keys, 0, d, n) {
		t.Fatal("distribution failed")
	}
}

func printTree(tr *paramTree, level int) {
	for i := 0; i < level; i++ {
		fmt.Printf(" ")
	}
	fmt.Printf("%d\n", tr.idx)
	for _, c := range tr.children {
		printTree(c, level+1)
	}
}

func checkSum(kmap []map[uint32]*big.Int, idx uint32, d *big.Int, n int) bool {
	s := big.NewInt(0)
	for i, m := range kmap {
		if a, ok := m[idx]; ok {
			if !checkSum(kmap, idx*uint32(n)+uint32(i)+1, a, n) {
				return false
			}
			s.Add(s, a)
		}
	}
	if s.BitLen() == 0 { // must be s == 0
		// no more sub keys
		return true
	}
	return s.Cmp(d) == 0
}

func TestEMSA(t *testing.T) {
	hash := gocrypto.SHA256
	key := readPKCS8("test.pkcs8")
	if key == nil {
		t.Fatal("couldn't read the key")
	}
	priv := key.(*rsa.PrivateKey)

	c, err := serializeHashInfo(hash, []byte(testTBS))
	if err != nil {
		t.Fatal(err)
	}
	hinfo, err := parseHashInfo(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := emsaEncode(hinfo, priv.N)
	if err != nil {
		t.Fatal(err)
	}

	h := hash.New()
	h.Write([]byte(testTBS))
	hashed := h.Sum(nil)
	want, err := goEMSA(hash, hashed, priv)
	if err != nil {
		t.Fatal(err)
	}

	if got.Cmp(want) != 0 {
		t.Fatal("mismatch")
	}
}

func TestCombine(t *testing.T) {
	key := readPKCS8("test.pkcs8")
	if key == nil {
		t.Fatal("couldn't read the key")
	}
	priv := key.(*rsa.PrivateKey)
	di, err := splitKey(priv.D, 10)
	if err != nil {
		t.Fatal(err)
	}

	// emsa
	hash := gocrypto.SHA256
	chunk, _ := serializeHashInfo(hash, []byte(testTBS))
	hinfo, _ := parseHashInfo(chunk)
	m, _ := emsaEncode(hinfo, priv.N)

	c := big.NewInt(1)
	for _, d := range di {
		ci := new(big.Int)
		if d.Sign() < 0 {
			ci.Exp(m, d.Neg(d), priv.N)
			ci.ModInverse(ci, priv.N)
		} else {
			ci.Exp(m, d, priv.N)
		}
		c.Mod(c.Mul(c, ci), priv.N)
	}
	got := I2OS(c, (priv.N.BitLen()+7)/8)

	h := gocrypto.SHA256.New()
	h.Write([]byte(testTBS))
	hashed := h.Sum(nil)
	want, err := rsa.SignPKCS1v15(nil, priv, hash, hashed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatal("couldn't reconstruct the signature")
	}
}

func TestThreshold(t *testing.T) {
	t.Skip("skip failing test - FIXME")
	key := readPKCS8("test.pkcs8")
	if key == nil {
		t.Fatal("couldn't read the key")
	}
	rand.Seed(time.Now().Unix())
	doTest(t, 10, 7, key)
	doTest(t, 10, 6, key)
	doTest(t, 9, 7, key)
	doTest(t, 9, 6, key)
	doTest(t, 8, 8, key)
	doTest(t, 4, 1, key)
}

func doTest(t *testing.T, n, k int, key interface{}) {
	// calculate the standard sig
	h := gocrypto.SHA256.New()
	h.Write([]byte(testTBS))
	hashed := h.Sum(nil)
	want, err := rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), gocrypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}

	ctx := New(nil)
	params, _, err := ctx.Distribute(key, make([]node.Node, n), k)
	if err != nil {
		t.Fatal(err)
	}

	// fixed faulty nodes
	for nfaults := 0; nfaults <= n-k; nfaults++ {
		faults := rand.Perm(n)[0:nfaults]
		fmt.Printf("testing fixed faulty nodes (%d, %d)\n", n, n-nfaults)
		sig, err := doProcess(ctx, n, k, params, nfaults+1, func(i, j int) bool { // nfaults + 1 must be sufficient to retry
			for _, f := range faults {
				if f == i {
					return true
				}
			}
			return false
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig, want) {
			t.Fatalf("sig mismatch: %d, %d", n, n-nfaults)
			fmt.Println("sig mismatch")
		} else {
			t.Logf("success: fixed faulty nodes (%d, %d)", n, n-nfaults)
			fmt.Println("success")
		}
	}
	// random faulty nodes
	for ntests := 5; ntests > 0; ntests-- {
		fmt.Printf("testing random faulty nodes[%d]\n", 10-ntests)
		lastIterate := -1
		var faults []int
		fmap := make(map[int]bool)
		sig, err := doProcess(ctx, n, k, params, 100, func(i, j int) bool { // 100 should be more than enough..
			if j > lastIterate {
				nfaults := rand.Intn(n - k + 1)
				faults = rand.Perm(n)[0:nfaults]
				lastIterate = j
			}
			for _, f := range faults {
				if f == i {
					fmap[f] = true
					return true
				}
			}
			return false
		})
		if err == crypto.ErrInsufficientNumberOfThresholdSignatures {
			if len(fmap) <= n-k {
				t.Fatal(err)
			}
			t.Logf("insufficient number of signatures with %d faulty nodes: (%d, %d)", len(fmap), n, k)
			fmt.Printf("insufficient number of signatures with %d faulty nodes\n", len(fmap))
		} else if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(sig, want) {
			t.Fatalf("sig mismatch: (%d, %d)", n, k)
			fmt.Println("sig mismatch")
		} else {
			t.Logf("success: random faulty nodes with %d faulty nodes (%d, %d)", len(fmap), n, k)
			fmt.Println("success")
		}
	}
}

func doProcess(ctx crypto.Threshold, n, k int, params [][]byte, retry int, isFault func(i, n int) bool) ([]byte, error) {
	proc, err := ctx.NewProcess([]byte(testTBS), crypto.TH_RSA, gocrypto.SHA256)
	if err != nil {
		return nil, err
	}
	for i := 0; i <= retry; i++ {
		nodes, req, err := proc.MakeRequest()
		if err != nil {
			return nil, err
		}
		if nodes == nil {
			return nil, crypto.ErrInsufficientNumberOfThresholdSignatures
		}
		{
			keys, _, err := parseSignRequest(req)
			if err != nil {
				return nil, err
			}
			fmt.Printf("looking for: ")
			for _, k := range keys {
				fmt.Printf("%d, ", k)
			}
			fmt.Printf("\n")
		}
		for _, j := range rand.Perm(n) {
			if isFault(j, i) {
				continue
			}
			res, err := ctx.Sign(params[j], req, 0, 0)
			if err != nil {
				return nil, err
			}
			if res == nil { // no partial signatures from this node
				fmt.Printf("[%d] key not found\n", j)
				continue
			}
			{
				sig, _, _ := parsePartialSignature(res)
				fmt.Printf("partial sig[%d]: {", j)
				for i, _ := range sig {
					fmt.Printf("%d, ", i)
				}
				fmt.Printf("}\n")
			}
			sig, err := proc.ProcessResponse(res, nodes[j])
			if err != nil {
				return nil, err
			}
			if sig != nil {
				return sig, nil
			}
		}
		{
			type cell struct {
				tr    *sigTree
				level int
			}
			// print the tree
			var stack []*cell
			stack = append(stack, &cell{proc.(*rsaProc).tree, 0})
			for len(stack) > 0 {
				sp := len(stack) - 1
				tr := stack[sp].tr
				level := stack[sp].level
				stack = stack[0:sp]
				for i := 0; i < level; i++ {
					fmt.Printf(" ")
				}
				fmt.Printf("%d [%v]\n", tr.idx, tr.completed)
				for _, c := range tr.children {
					stack = append(stack, &cell{c, level + 1})
				}
			}
		}
	}
	return nil, errors.New("too many retries...")
}

func readPKCS8(path string) interface{} {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil {
		if block.Type != "PRIVATE KEY" {
			return nil
		}
		der = block.Bytes
	} else { // not PEM, assume the data is DER
		der = data
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil
	}
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return key
	default:
		return nil
	}
}

//
// copied from rsa/pkcs1v15.go
//
func goEMSA(hash gocrypto.Hash, hashed []byte, priv *rsa.PrivateKey) (*big.Int, error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, errors.New("too long")
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	m := new(big.Int).SetBytes(em)
	return m, nil
}

func pkcs1v15HashInfo(hash gocrypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}
