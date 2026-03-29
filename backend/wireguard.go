package backend

import (
	"context"
	"fmt"
	"net"

	"github.com/galang-rs/socks5/netstack"

	wgconfig "github.com/galang-rs/wireguard/pkg/config"
	wgtunnel "github.com/galang-rs/wireguard/pkg/tunnel"
)

// WireGuardConfig holds configuration for the WireGuard backend.
type WireGuardConfig struct {
	// ConfigFile is the path to the WireGuard .conf file.
	ConfigFile string

	// DNSServers overrides the DNS servers from the config.
	// If empty, uses DNS from the WireGuard config, or 1.1.1.1 as fallback.
	DNSServers []string

	// Logger for netstack debug output. If nil, logging is disabled.
	Logger netstack.Logger

	// LogLevel controls the verbosity of WireGuard tunnel internal logs.
	// 0 = warn only (default), 1 = info, 2 = debug.
	LogLevel int
}

type wireGuardBackend struct {
	tun   *wgtunnel.TUN
	stack *netstack.Stack
}

// NewWireGuard creates a backend that routes connections through a WireGuard tunnel.
//
// Usage:
//
//	be, err := backend.NewWireGuard(ctx, backend.WireGuardConfig{
//	    ConfigFile: "wg0.conf",
//	})
//	defer be.Close()
func NewWireGuard(ctx context.Context, cfg WireGuardConfig) (Backend, error) {
	if cfg.ConfigFile == "" {
		return nil, fmt.Errorf("backend: WireGuard config file is required")
	}

	// Parse WireGuard config.
	wgCfg := wgconfig.NewConfig(
		wgconfig.WithConfigFile(cfg.ConfigFile),
		wgconfig.WithLogger(newWGLogger(cfg.LogLevel)),
	)

	// Start WireGuard tunnel.
	dialer := &net.Dialer{}
	tun, err := wgtunnel.Start(ctx, dialer, wgCfg)
	if err != nil {
		return nil, fmt.Errorf("backend: wireguard start: %w", err)
	}

	// Get tunnel info.
	ti := tun.TunnelInfo()

	// Determine DNS servers.
	dns := cfg.DNSServers
	if len(dns) == 0 {
		dns = ti.DNS
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}

	// Determine MTU.
	mtu := ti.MTU
	if mtu <= 0 {
		mtu = 1420 // WireGuard default
	}

	// Create virtual network stack.
	stack, err := netstack.New(netstack.StackConfig{
		TUN:     tun,
		LocalIP: ti.IP,
		Gateway: ti.GW,
		MTU:     mtu,
		DNS:     dns,
		Logger:  cfg.Logger,
	})
	if err != nil {
		tun.Close()
		return nil, fmt.Errorf("backend: wireguard netstack: %w", err)
	}

	stack.Start(ctx)

	return &wireGuardBackend{
		tun:   tun,
		stack: stack,
	}, nil
}

func (w *wireGuardBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return w.stack.DialContext(ctx, network, addr)
}

func (w *wireGuardBackend) Close() error {
	w.stack.Close()
	return w.tun.Close()
}

func (w *wireGuardBackend) Name() string {
	return "wireguard"
}
