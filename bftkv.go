// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package bftkv

import (
	"errors"
)

var (
	ErrInsufficientNumberOfQuorum = errors.New("insufficient number of quorum")
	ErrInsufficientNumberOfResponses = errors.New("insufficient number of responses")
	ErrInsufficientNumberOfValidResponses = errors.New("insufficient number of valid responses")
	ErrInvalidQuorumCertificate = errors.New("invalid quorum certficate")
	ErrInvalidTimestamp = errors.New("invalid timestamp")
	ErrInvalidSignRequest = errors.New("invalid signature request")
	ErrPermissionDenied = errors.New("permission denied")
	ErrBadTimestamp = errors.New("bad timestamp")
	ErrEquivocation = errors.New("equivocation error")
	ErrInvalidVariable = errors.New("invalid variable")
	ErrUnknownCommand = errors.New("unknown command")
	ErrMalformedRequest = errors.New("malformed request")
	ErrNoMoreWrite = errors.New("no more write")
)
