// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package egressservices contains shared types for exposing tailnet services to
// cluster workloads.
// These are split into a separate package for consumption of
// non-Kubernetes shared libraries and binaries. Be mindful of not increasing
// dependency size for those consumers when adding anything new here.
package egressservices

import (
	"net/netip"
)

// KeyEgressServices is name of the proxy state Secret field that contains the
// currently applied egress proxy config.
const KeyEgressServices = "egress-services"

// Configs contains the desired configuration for egress services keyed by
// service name.
type Configs map[string]Config

// Config is an egress service configuration.
type Config struct {
	// TailnetTarget is the target to which cluster traffic for this service
	// should be proxied.
	TailnetTarget TailnetTarget `json:"tailnetTarget"`
	// Ports contains mappings for ports that can be accessed on the tailnet
	// target keyed by a predictable name for easier lookup.
	// {"tcp:80:4003":{"protocol":"tcp","src":80,"dst":4003}}
	Ports map[PortMapName]PortMap `json:"ports"`
}

// TailnetTarget is the tailnet target to which traffic for the egress service
// should be proxied. Exactly one of IP or FQDN should be set.
type TailnetTarget struct {
	// IP is the tailnet IP of the target.
	IP string `json:"ip"`
	// FQDN is the full tailnet FQDN of the target.
	FQDN string `json:"fqdn"`
}

// PorMap is a mapping between match port on which proxy receives cluster
// traffic and target port where traffic received on match port should be
// fowardded to.
type PortMap struct {
	Protocol   string `json:"protocol"`
	MatchPort  uint16 `json:"matchPort"`
	TargetPort uint16 `json:"targetPort"`
}

// PortMapName is a name of a port mapping in form '<protocol>:<match port>:<target port>'.
type PortMapName string

// Status represents the currently configured firewall rules for all egress
// services for a proxy identified by the PodIP.
type Status struct {
	PodIP string `json:"podIP"`
	// All egress service status keyed by service name.
	Services map[string]*ServiceStatus `json:"services"`
}

// ServiceStatus is the currently configured firewall rules for an egress
// service.
type ServiceStatus struct {
	Ports map[PortMapName]PortMap `json:"ports"`
	// TailnetTargetIPs are the tailnet target IPs that were used to
	// configure these firewall rules. For a TailnetTarget with IP set, this
	// is the same as IP.
	TailnetTargetIPs []netip.Addr  `json:"tailnetTargetIPs"`
	TailnetTarget    TailnetTarget `json:"tailnetTarget"`
}