package backend

import (
	"context"
	"net"
)

// Direct is a backend that connects directly without any VPN tunnel.
type Direct struct {
	dialer *net.Dialer
}

// NewDirect creates a direct (no VPN) backend.
func NewDirect() *Direct {
	return &Direct{
		dialer: &net.Dialer{},
	}
}

func (d *Direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *Direct) Close() error {
	return nil
}

func (d *Direct) Name() string {
	return "direct"
}
