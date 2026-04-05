package backend

import (
	"context"
	"fmt"
	"net"

	"github.com/galang-rs/socks5/netstack"

	ovpnconfig "github.com/galang-rs/ovpn/pkg/config"
	ovpntunnel "github.com/galang-rs/ovpn/pkg/tunnel"
)

// OpenVPNConfig holds configuration for the OpenVPN backend.
type OpenVPNConfig struct {
	// ConfigFile is the path to the .ovpn config file.
	ConfigFile string

	// AuthFile is the optional path to auth.txt (username/password).
	AuthFile string

	// DNSServers overrides DNS. If empty, defaults to 1.1.1.1.
	DNSServers []string

	// Logger for netstack debug output. If nil, logging is disabled.
	Logger netstack.Logger

	// LogLevel controls the verbosity of OpenVPN tunnel internal logs.
	// 0 = warn only (default), 1 = info, 2 = debug.
	LogLevel int
}

type openVPNBackend struct {
	tun   *ovpntunnel.TUN
	stack *netstack.Stack
}

// NewOpenVPN creates a backend that routes connections through an OpenVPN tunnel.
//
// Usage:
//
//	be, err := backend.NewOpenVPN(ctx, backend.OpenVPNConfig{
//	    ConfigFile: "config.ovpn",
//	    AuthFile:   "auth.txt",
//	})
//	defer be.Close()
func NewOpenVPN(ctx context.Context, cfg OpenVPNConfig) (Backend, error) {
	if cfg.ConfigFile == "" {
		return nil, fmt.Errorf("backend: OpenVPN config file is required")
	}

	// Build options.
	opts := []ovpnconfig.Option{
		ovpnconfig.WithConfigFile(cfg.ConfigFile),
		ovpnconfig.WithLogger(newOVPNLogger(cfg.LogLevel)),
	}
	if cfg.AuthFile != "" {
		opts = append(opts, ovpnconfig.WithAuthFile(cfg.AuthFile))
	}

	ovpnCfg := ovpnconfig.NewConfig(opts...)

	// Start OpenVPN tunnel.
	dialer := &net.Dialer{}
	tun, err := ovpntunnel.Start(ctx, dialer, ovpnCfg)
	if err != nil {
		return nil, fmt.Errorf("backend: openvpn start: %w", err)
	}

	// Get tunnel info.
	ti := tun.TunnelInfo()

	// Determine DNS.
	dns := cfg.DNSServers
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}

	// Determine MTU.
	mtu := ti.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	// Create virtual network stack.
	stack, err := netstack.New(netstack.StackConfig{
		TUN:      tun,
		LocalIP:  ti.IP,
		LocalIP6: ti.IPv6,
		Gateway:  ti.GW,
		MTU:      mtu,
		DNS:      dns,
		Logger:   cfg.Logger,
	})
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("backend: openvpn netstack: %w", err)
	}

	stack.Start(ctx)

	return &openVPNBackend{
		tun:   tun,
		stack: stack,
	}, nil
}

func (o *openVPNBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return o.stack.DialContext(ctx, network, addr)
}

func (o *openVPNBackend) Close() error {
	o.stack.Close()
	return o.tun.Close()
}

func (o *openVPNBackend) Name() string {
	return "openvpn"
}
