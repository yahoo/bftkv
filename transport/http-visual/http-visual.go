// Copyright 2017, Yahoo Holdings Inc.
// Licensed under the terms of the Apache license. See LICENSE file in project root for terms.

package http_visual

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/yahoo/bftkv/crypto"
	"github.com/yahoo/bftkv/node/graph"
	"github.com/yahoo/bftkv/quorum"
	"github.com/yahoo/bftkv/transport"
	transport_http "github.com/yahoo/bftkv/transport/http"
	"golang.org/x/net/websocket"
)

type TrHTTPVisual struct {
	transport_http.TrHTTP
	graph *graph.Graph
	qs    quorum.QuorumSystem
	wss   []*websocket.Conn
}

type Edge struct {
	Source      string
	Destination string
}

type VisualGraph struct {
	Names   map[uint64]string
	Edges   []Edge
	Revoked []string
}

type message struct {
	Message string `json:"message"`
}

func New(security *crypto.Crypto, graph *graph.Graph, qs quorum.QuorumSystem, wsAddress string) transport.Transport {
	h := transport_http.New(security)
	hv := &TrHTTPVisual{*(h.(*transport_http.TrHTTP)), graph, qs, nil}
	// create listener to send and receive data from js
	http.Handle("/"+wsAddress, websocket.Handler(hv.HandleConnection))
	go func() {
		err := http.ListenAndServe(":"+wsAddress, nil)
		if err != nil {
			log.Println("Websocket already open and serving.")
		}
	}()
	return hv
}

func (hVisual *TrHTTPVisual) HandleConnection(ws *websocket.Conn) {
	log.Printf("Socket open: %s, %s ", ws.LocalAddr(), ws.RemoteAddr())
	// send the node id of the server
	websocket.Message.Send(ws, fmt.Sprintf("{\"actionType\": \"id\", \"id\": \"%v\"}", hVisual.graph.Id()))
	for {
		hVisual.wss = append(hVisual.wss, ws)
		var m message
		if err := websocket.JSON.Receive(ws, &m); err != nil {
			if fmt.Sprint(err) == "EOF" {
				log.Println("Socket connection terminated.")
			}
			break
		}

		log.Printf("Received message: %s\n", m)

		switch m.Message {
		case "graph":
			graphString := hVisual.graphToJSONString()
			websocket.Message.Send(ws, graphString)
		case "trustGraph":
			graphString := hVisual.graphToJSONString()
			websocket.Message.Send(ws, fmt.Sprintf("{\"actionType\": \"trustGraph\", \"graph\": %v}", graphString))
		}
	}

}

func (hVisual *TrHTTPVisual) graphToJSONString() string {
	var edges []Edge
	names := make(map[uint64]string)
	for nodeId, node := range hVisual.graph.Vertices {
		if node.Instance != nil {
			names[node.Instance.Id()] = node.Instance.Name()
		}
		for destinationId, _ := range node.Edges {
			edges = append(edges, Edge{fmt.Sprintf("%v", nodeId), fmt.Sprintf("%v", destinationId)})
		}
	}

	var revokedList []string

	for id, node := range hVisual.graph.Revoked {
		name := ""
		if node != nil {
			name = node.Name()
		}
		names[id] = name                                         // add also nodes in the revoked list to names
		revokedList = append(revokedList, fmt.Sprintf("%v", id)) // fill the revoked list with ids
	}

	vg := VisualGraph{names, edges, revokedList}
	k, err := json.Marshal(vg)

	if err != nil {
		//log.Println(err)
		return ""
	}
	return string(k)
}

func (hv *TrHTTPVisual) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hv.TrHTTP.ServeHTTP(w, r)
	path := strings.ToLower(r.URL.Path)
	if !strings.HasPrefix(path, transport.Prefix) {
		return
	}
	actionType := path[len(transport.Prefix):]
	if hv.wss != nil {
		for _, ws := range hv.wss {
			if actionType == "read" || actionType == "sign" || actionType == "write" || actionType == "malwrite" || actionType == "malsign" { // for now, just inform the graph on these
				websocket.Message.Send(ws, fmt.Sprintf("{\"actionType\": \"%s\", \"to\": \"%s\"}", actionType, hv.graph.Name()))
			} else if actionType == "notify" {
				// decrypt the packet
				crypt := &crypto.Crypto{}
				req, _, _, err := crypt.Message.Decrypt(r.Body)

				if err != nil {
					log.Printf("server [%s]: transport security error: %s\n", hv.Server.Addr, err)
				}

				// get the list of revoked nodes
				nodes, err := crypt.Certificate.Parse(req)

				if err != nil {
					log.Printf("server [%s]: certificate parse error: %s\n", hv.Server.Addr, err)
				}

				var revoked []uint64
				for _, node := range nodes {
					revoked = append(revoked, node.Id())
				}

				// inform the visualization on the revoked nodes
				hv.RevokeVisual(revoked)
			}
		}
	}
}

func (hv *TrHTTPVisual) RevokeVisual(ids []uint64) {
	for _, ws := range hv.wss {
		for _, id := range ids {
			websocket.Message.Send(ws, fmt.Sprintf("{\"actionType\": \"revoke\", \"id\": \"%v\"}", id))
		}
	}
}

// If visualization is active, ServeHTTP here
func (hv *TrHTTPVisual) Start(o transport.TransportServer, addr string) {
	hv.Server = &http.Server{
		Addr:    addr,
		Handler: hv,
	}
	hv.O = o
	go hv.Server.ListenAndServe()
}
