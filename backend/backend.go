// Package backend provides tunnel backends for the SOCKS5 proxy.
//
// Each backend implements the Backend interface, providing DialContext
// to create connections either directly or through a VPN tunnel.
package backend

import (
	"context"
	"net"
)

// Backend is the interface that all tunnel backends implement.
type Backend interface {
	// DialContext creates a network connection through the backend.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)

	// Close shuts down the backend and releases resources.
	Close() error

	// Name returns the backend type name (e.g. "direct", "wireguard", "openvpn").
	Name() string
}
