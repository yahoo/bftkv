// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package cert

type CertificateInstance interface {
	Id() uint64
	Name() string
	Address() string
	UId() string
	Signers() []uint64
	Serialize() ([]byte, error)
	Instance() interface{}
	SetActive(active bool)
	Active() bool
}
