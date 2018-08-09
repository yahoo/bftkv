// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package packet

import (
	"bytes"
	"io"
	"math/big"

	"encoding/binary"
)

const (
	SignatureTypeNil = 0
	SignatureTypePGP = 1
	// add threshold signature, etc...

	SignatureTypePasswordAuthProof = 256
)

//
// signature format
//

type SignaturePacket struct {
	Type byte
	Version uint32
	Completed bool
	Data []byte
	Cert []byte	// optional
}

// packetizer <x, v, t, sig, ss, auth>

func Serialize(args ...interface{}) ([]byte, error) {
	var buf bytes.Buffer
	for i, arg := range args {
		var err error
		switch i {
		case 0, 1, 5:	// variable and value in []byte, and auth (optional)
			if arg == nil {
				err = WriteChunk(&buf, []byte{})	// empty slice
			} else {
				err = WriteChunk(&buf, arg.([]byte))
			}
		case 2:		// timestamp
			err = binary.Write(&buf, binary.BigEndian, arg.(uint64))
		case 3, 4:	// *signature
			if arg == nil {
				err = writeSignature(&buf, nil)
			} else {
				err = writeSignature(&buf, arg.(*SignaturePacket))
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func Parse(pkt []byte) (variable []byte, value []byte, t uint64, sig *SignaturePacket, ss *SignaturePacket, auth []byte, err error) {
	r := bytes.NewReader(pkt)
	// variable
	variable, err = ReadChunk(r)
	if err != nil {
		return
	}
	// value
	value, err = ReadChunk(r)
	if err != nil {
		if err == io.EOF {
			err = nil
			value = nil
		}
		return
	}
	// timestamp
	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		if err == io.EOF {
			err = nil
			t = 0
		}
		return
	}
	// signature
	sig, err = readSignature(r)
	if err != nil {
		if err == io.EOF {
			err = nil
			sig = nil
		}
		return
	}
	// collective signature
	ss, err = readSignature(r)
	if err != nil {
		if err == io.EOF {
			err = nil
			ss = nil
		}
		return
	}
	// auth
	auth, err = ReadChunk(r)
	if err != nil {
		if err == io.EOF {
			err = nil
			auth = nil
		}
		return
	}
	return
}

func WriteChunk(buf *bytes.Buffer, chunk []byte) error {
	l := len(chunk)
	if err := binary.Write(buf, binary.BigEndian, uint64(l)); err != nil {
		return err
	}
	_, err := buf.Write(chunk)
	return err
}

func ReadChunk(r *bytes.Reader) ([]byte, error) {
	var l uint64
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	if l == 0 {
		return nil, nil
	}
	chunk := make([]byte, l)
	_, err := io.ReadFull(r, chunk)
	if err != nil {
		return nil, err
	}
	return chunk, nil
}

func seek2tbs(r *bytes.Reader) (int64, error) {
	// skip the variable
	var l int64
	binary.Read(r, binary.BigEndian, &l)
	r.Seek(l, io.SeekCurrent)
	// skip value
	binary.Read(r, binary.BigEndian, &l)
	r.Seek(l, io.SeekCurrent)
	// skip timestamp
	var t uint64
	binary.Read(r, binary.BigEndian, &t)
	return r.Seek(0, io.SeekCurrent)
}

func TBS(pkt []byte) ([]byte, error) {
	r := bytes.NewReader(pkt)
	offset, err := seek2tbs(r)
	if err != nil {
		return nil, err
	}
	chunk := make([]byte, offset)
	r.Seek(0, io.SeekStart)
	if _, err := io.ReadFull(r, chunk); err != nil {
		return nil, err
	}
	return chunk, nil
}

func TBSS(pkt []byte) ([]byte, error) {
	r := bytes.NewReader(pkt)
	if _, err := seek2tbs(r); err != nil {
		return nil, err
	}
	// skip signature
	if _, err := readSignature(r); err != nil {
		return nil, err
	}
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	chunk := make([]byte, offset)
	r.Seek(0, io.SeekStart)
	_, err = io.ReadFull(r, chunk)
	if err != nil {
		return nil, err
	}
	return chunk, nil
}

func writeSignature(buf *bytes.Buffer, sig *SignaturePacket) error {
	if sig == nil {
		sig = &SignaturePacket{}
	}
	if _, err := buf.Write([]byte{sig.Type}); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, sig.Version); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, sig.Completed); err != nil {
		return err
	}
	if err := WriteChunk(buf, sig.Data); err != nil {
		return err
	}
	if err := WriteChunk(buf, sig.Cert); err != nil {
		return err
	}
	return nil
}

func readSignature(r *bytes.Reader) (sig *SignaturePacket, err error) {
	sig = &SignaturePacket{}
	if sig.Type, err = r.ReadByte(); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &sig.Version); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &sig.Completed); err != nil {
		return nil, err
	}
	if sig.Data, err = ReadChunk(r); err != nil {
		return nil, err
	}
	if sig.Cert, err = ReadChunk(r); err != nil {
		return nil, err
	}
	if sig.Type == SignatureTypeNil {
		sig = nil
	}
	return sig, nil
}

func ParseSignature(pkt []byte) (*SignaturePacket, error) {
	r := bytes.NewReader(pkt)
	return readSignature(r)
}

func SerializeSignature(sig *SignaturePacket) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeSignature(&buf, sig); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ParseAuthenticationRequest(pkt []byte) (phase int, variable []byte, adata []byte, err error) {
	r := bytes.NewReader(pkt)
	b, err := r.ReadByte()
	if err != nil {
		return
	}
	phase = int(b)
	if variable, err = ReadChunk(r); err != nil {
		return
	}
	if adata, err = ReadChunk(r); err != nil {
		return
	}
	return
}

func SerializeAuthenticationRequest(phase int, variable []byte, adata []byte) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write([]byte{byte(phase)}); err != nil {
		return nil, err
	}
	if err := WriteChunk(&buf, variable); err != nil {
		return nil, err
	}
	if err := WriteChunk(&buf, adata); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}


func ReadBigInt(r *bytes.Reader) (*big.Int, error) {
	c, err := ReadChunk(r)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(c), nil
}

func WriteBigInt(buf *bytes.Buffer, b *big.Int) error {
	var c []byte
	if b != nil {
		c = b.Bytes()
	}
	return WriteChunk(buf, c)
}
