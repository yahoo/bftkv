// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package http

import (
	"net"
	"net/http"
	"time"

	_ "github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/transport"
)

type MalTrHTTP struct {
	TrHTTP
	O transport.MalTransportServer
}

func MalNew(security *crypto.Crypto) transport.Transport {
	h := &MalTrHTTP{
	             TrHTTP: TrHTTP{
                             security: security,
		     },
             }

	// client
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, time.Duration(DIAL_TIMEOUT)*time.Second)
		},
		MaxIdleConns:          5, // for testing -- running multiple servers in one process process may exceeds the limit of #sockets
		IdleConnTimeout:       time.Duration(IDLE_TIMEOUT) * time.Second,
		ResponseHeaderTimeout: time.Duration(RESPONSE_TIMEOUT) * time.Second,
	}
	h.client = &http.Client{
		Transport: tr,
	}
	return h
}
