// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package bftkv

import (
	"errors"
	"sync"
)

var (
	ErrInsufficientNumberOfQuorum = NewError("insufficient number of quorum")
	ErrInsufficientNumberOfResponses = NewError("insufficient number of responses")
	ErrInsufficientNumberOfValidResponses = NewError("insufficient number of valid responses")
	ErrInvalidQuorumCertificate = NewError("invalid quorum certficate")
	ErrInvalidTimestamp = NewError("invalid timestamp")
	ErrInvalidSignRequest = NewError("invalid signature request")
	ErrPermissionDenied = NewError("permission denied")
	ErrBadTimestamp = NewError("bad timestamp")
	ErrEquivocation = NewError("equivocation error")
	ErrInvalidVariable = NewError("invalid variable")
	ErrUnknownCommand = NewError("unknown command")
	ErrMalformedRequest = NewError("malformed request")
	ErrNoMoreWrite = NewError("no more write")
	ErrAuthenticationFailure = NewError("authentication failure")
	ErrExist = NewError("already exist")
	ErrInvalidUserID = NewError("invalid user ID")
	ErrInvalidResponse = NewError("invalid response")
)

var errMap = make(map[string]error)
var mutex sync.Mutex

func NewError(s string) error {
	err := errors.New(s)
	errMap[s] = err
	return err
}

func ErrorFromString(s string) error {
	mutex.Lock()
	err, ok := errMap[s]
	if !ok {
		err = NewError(s)
	}
	mutex.Unlock()
	return err
}
