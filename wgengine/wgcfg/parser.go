// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/key"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %q", e.why, e.offender)
}

func parseEndpoint(s string) (host string, port uint16, err error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, &ParseError{"Missing port from endpoint", s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return "", 0, &ParseError{"Invalid endpoint host", host}
	}
	uport, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{"Brackets must contain an IPv6 address", host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			maybeV6 := net.ParseIP(host[1 : len(host)-1])
			if maybeV6 == nil || len(maybeV6) != net.IPv6len {
				return "", 0, err
			}
		} else {
			return "", 0, err
		}
		host = host[1 : len(host)-1]
	}
	return host, uint16(uport), nil
}

// memROCut separates a mem.RO at the separator if it exists, otherwise
// it returns two empty ROs and reports that it was not found.
func memROCut(s mem.RO, sep byte) (before, after mem.RO, found bool) {
	if i := mem.IndexByte(s, sep); i >= 0 {
		return s.SliceTo(i), s.SliceFrom(i + 1), true
	}
	found = false
	return
}

// FromUAPI generates a Config from r.
// r should be generated by calling device.IpcGetOperation;
// it is not compatible with other uapi streams.
func FromUAPI(r io.Reader) (*Config, error) {
	cfg := new(Config)
	var peer *Peer // current peer being operated on
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := mem.B(scanner.Bytes())
		if line.Len() == 0 {
			continue
		}
		key, value, ok := memROCut(line, '=')
		if !ok {
			return nil, fmt.Errorf("failed to cut line %q on =", line.StringCopy())
		}
		valueBytes := scanner.Bytes()[key.Len()+1:]

		if key.EqualString("public_key") {
			if deviceConfig {
				deviceConfig = false
			}
			// Load/create the peer we are now configuring.
			var err error
			peer, err = cfg.handlePublicKeyLine(valueBytes)
			if err != nil {
				return nil, err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = cfg.handleDeviceLine(key, value, valueBytes)
		} else {
			err = cfg.handlePeerLine(peer, key, value, valueBytes)
		}
		if err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (cfg *Config) handleDeviceLine(k, value mem.RO, valueBytes []byte) error {
	switch {
	case k.EqualString("private_key"):
		// wireguard-go guarantees not to send zero value; private keys are already clamped.
		var err error
		cfg.PrivateKey, err = key.ParseNodePrivateUntyped(value)
		if err != nil {
			return err
		}
	case k.EqualString("listen_port"):
		port, err := mem.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("failed to parse listen_port: %w", err)
		}
		cfg.ListenPort = uint16(port)
	case k.EqualString("fwmark"):
	// ignore
	default:
		return fmt.Errorf("unexpected IpcGetOperation key: %q", k.StringCopy())
	}
	return nil
}

func (cfg *Config) handlePublicKeyLine(valueBytes []byte) (*Peer, error) {
	p := Peer{}
	var err error
	p.PublicKey, err = key.ParseNodePublicUntyped(mem.B(valueBytes))
	if err != nil {
		return nil, err
	}
	cfg.Peers = append(cfg.Peers, p)
	return &cfg.Peers[len(cfg.Peers)-1], nil
}

func (cfg *Config) handlePeerLine(peer *Peer, k, value mem.RO, valueBytes []byte) error {
	switch {
	case k.EqualString("endpoint"):
		nk, err := key.ParseNodePublicUntyped(value)
		if err != nil {
			return fmt.Errorf("invalid endpoint %q for peer %q, expected a hex public key", value.StringCopy(), peer.PublicKey.ShortString())
		}
		// nk ought to equal peer.PublicKey.
		// Under some rare circumstances, it might not. See corp issue #3016.
		// Even if that happens, don't stop early, so that we can recover from it.
		// Instead, note the value of nk so we can fix as needed.
		peer.WGEndpoint = nk
	case k.EqualString("persistent_keepalive_interval"):
		n, err := mem.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		peer.PersistentKeepalive = uint16(n)
	case k.EqualString("allowed_ip"):
		ipp := netip.Prefix{}
		err := ipp.UnmarshalText(valueBytes)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, ipp)
	case k.EqualString("protocol_version"):
		if !value.EqualString("1") {
			return fmt.Errorf("invalid protocol version: %q", value.StringCopy())
		}
	case k.EqualString("replace_allowed_ips") ||
		k.EqualString("preshared_key") ||
		k.EqualString("last_handshake_time_sec") ||
		k.EqualString("last_handshake_time_nsec") ||
		k.EqualString("tx_bytes") ||
		k.EqualString("rx_bytes"):
	// ignore
	default:
		return fmt.Errorf("unexpected IpcGetOperation key: %q", k.StringCopy())
	}
	return nil
}
