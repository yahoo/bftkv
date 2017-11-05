// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package http

import (
	"io"
	"net"
	"net/http"
	"time"
	"context"
	"strings"
	"log"

	"github.com/yahoo/bftkv"
	"github.com/yahoo/bftkv/transport"
	"github.com/yahoo/bftkv/node"
	"github.com/yahoo/bftkv/crypto"
)

type TrHTTP struct {
	client *http.Client
	Server *http.Server
	O transport.TransportServer
	security *crypto.Crypto
}

const (
	NonceSize = 8
	DIAL_TIMEOUT = 5
	IDLE_TIMEOUT = 10
	RESPONSE_TIMEOUT = 10
)

func New(security *crypto.Crypto) transport.Transport {
	h := &TrHTTP{security: security}

	// client
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, time.Duration(DIAL_TIMEOUT) * time.Second)
		},
		MaxIdleConns: 1,	// for testing -- running multiple servers in one process process may exceeds the limit of #sockets
		IdleConnTimeout: time.Duration(IDLE_TIMEOUT) * time.Second,
		ResponseHeaderTimeout: time.Duration(RESPONSE_TIMEOUT) * time.Second,
	}
	h.client = &http.Client{
		Transport: tr,
	}
	return h
}


func (h *TrHTTP) Post(addr string, msg io.Reader) (io.ReadCloser, error) {
	res, err := h.client.Post(addr, "application/octet-stream", msg)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		err := transport.ErrServerError
		if res.StatusCode == http.StatusInternalServerError {
			errs := res.Header.Get("X-error")
			if errs != "" {
				err = bftkv.ErrorFromString(errs)
			}
		}
		return nil, err
	}
	return res.Body, nil
}

func (h *TrHTTP) Multicast(path int, peers []node.Node, data []byte, cb func(res *transport.MulticastResponse) bool) {
	transport.Multicast(h, path, peers, data, cb)
}

func (h *TrHTTP) Start(o transport.TransportServer, addr string) {
	h.Server = &http.Server{
		Addr: addr,
		Handler: h,
	}
	h.O = o
	go h.Server.ListenAndServe()
}

func (h *TrHTTP) Stop() {
	if h.Server == nil {
		return
	}
	ctx, _ := context.WithTimeout(context.Background(), 10 * time.Second)
	h.Server.Shutdown(ctx)
	h.Server.Close()
}

func (h *TrHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	path := strings.ToLower(r.URL.Path)
	if !strings.HasPrefix(path, transport.Prefix) {
		log.Printf("http: %s not found\n", path)
		http.NotFound(w, r)
		return
	}
	var cmd int
	switch path[len(transport.Prefix):] {
	case "join":
		cmd = transport.Join
	case "leave":
		cmd = transport.Leave
	case "time":
		cmd = transport.Time
	case "read":
		cmd = transport.Read
	case "write":
		cmd = transport.Write
	case "sign":
		cmd = transport.Sign
	case "auth":
		cmd = transport.Auth
	case "setauth":
		cmd = transport.SetAuth
	case "register":
		cmd = transport.Register
	case "revoke":
		cmd = transport.Revoke
	case "notify":
		cmd = transport.Notify
	default:
		http.NotFound(w, r)
		log.Printf("http: %s not found\n", path)
		return
	}
	err := h.O.Handler(cmd, r.Body, w)
	if err != nil {
		w.Header().Add("X-error", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (h *TrHTTP) GenerateRandom() []byte {
	return h.security.RNG.Generate(NonceSize)
}

func (h *TrHTTP) Encrypt(peers []node.Node, plain []byte, nonce []byte) (cipher []byte, err error) {
	return h.security.Message.Encrypt(peers, plain, nonce)
}

func (h *TrHTTP) Decrypt(r io.Reader) (plain []byte, nonce []byte, peer node.Node, err error) {
	return h.security.Message.Decrypt(r)
}
