// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"net/http"
	"sync"
)

// healthz is a simple health check server, if enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address else
// returns 503.
type healthz struct {
	sync.Mutex
	hasAddrs bool
}

func (h *healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Lock()
	defer h.Unlock()
	if h.hasAddrs {
		w.Write([]byte("ok"))
	} else {
		http.Error(w, "node currently has no tailscale IPs", http.StatusInternalServerError)
	}
}

// runHealthz runs a simple HTTP health endpoint on /healthz, listening on the
// provided address. A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func runHealthz(mux *http.ServeMux, h *healthz) {
	mux.Handle("GET /healthz", h)
}
