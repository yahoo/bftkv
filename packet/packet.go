// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package packet

import (
	"bytes"
	"io"

	"encoding/binary"
)

const (
	SignatureTypePGP = 0
	// add threshold signature, etc...
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

func Serialize(args ...interface{}) ([]byte, error) {
	var buf bytes.Buffer
	for i, arg := range args {
		var err error
		switch i {
		case 0, 1:	// variable and value in []byte
			err = writeChunk(&buf, arg.([]byte))
		case 3:		// timestamp
			err = binary.Write(&buf, binary.BigEndian, arg.(uint64))
		case 2, 4:	// *signature
			err = writeSignature(&buf, arg.(*SignaturePacket))
		}
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func Parse(pkt []byte) (variable []byte, value []byte, sig *SignaturePacket, t uint64, ss *SignaturePacket, err error) {
	r := bytes.NewReader(pkt)
	// variable
	variable, err = readChunk(r)
	if err != nil {
		return
	}
	// value
	value, err = readChunk(r)
	if err != nil {
		if err == io.EOF {
			err = nil
			value = nil
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
	// timestamp
	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		if err == io.EOF {
			err = nil
			t = 0
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
	return
}

func seek2tbs(r *bytes.Reader) (int64, error) {
	// skip the variable
	var l int64
	binary.Read(r, binary.BigEndian, &l)
	r.Seek(l, io.SeekCurrent)
	// skip value
	binary.Read(r, binary.BigEndian, &l)
	return r.Seek(l, io.SeekCurrent)
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
	// skip timestamp
	var t uint64
	if err := binary.Read(r, binary.BigEndian, &t); err != nil {
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

func writeChunk(buf *bytes.Buffer, chunk []byte) error {
	l := len(chunk)
	if err := binary.Write(buf, binary.BigEndian, uint64(l)); err != nil {
		return err
	}
	_, err := buf.Write(chunk)
	return err
}

func readChunk(r *bytes.Reader) ([]byte, error) {
	var l uint64
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	chunk := make([]byte, l)
	_, err := io.ReadFull(r, chunk)
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
	if err := writeChunk(buf, sig.Data); err != nil {
		return err
	}
	if err := writeChunk(buf, sig.Cert); err != nil {
		return err
	}
	return nil
}

func readSignature(r *bytes.Reader) (*SignaturePacket, error) {
	sig := &SignaturePacket{}
	var err error
	if sig.Type, err = r.ReadByte(); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &sig.Version); err != nil {
		return nil, err
	}
	if err = binary.Read(r, binary.BigEndian, &sig.Completed); err != nil {
		return nil, err
	}
	if sig.Data, err = readChunk(r); err != nil {
		return nil, err
	}
	if sig.Cert, err = readChunk(r); err != nil {
		return nil, err
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
