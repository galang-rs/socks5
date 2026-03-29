// Package backend provides tunnel backends for the SOCKS5 proxy.
//
// Each backend implements the Backend interface, providing DialContext
// to create connections either directly or through a VPN tunnel.
package backend

import (
	"context"
	"log"
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

// VPN tunnel log levels (used by WireGuardConfig.LogLevel / OpenVPNConfig.LogLevel).
const (
	// VPNLogWarn logs only warnings and errors from the VPN tunnel (default).
	VPNLogWarn = 0
	// VPNLogInfo also logs informational messages (handshakes, state changes).
	VPNLogInfo = 1
	// VPNLogDebug logs everything including per-packet crypto debug traces.
	VPNLogDebug = 2
)

// vpnLogger is a leveled logger adapter for WireGuard/OpenVPN Logger interfaces.
// Both packages use structurally identical Logger interfaces (Debugf/Infof/Warnf/Errorf),
// so this single struct satisfies both via Go's structural typing.
type vpnLogger struct {
	level  int
	prefix string
}

func (l *vpnLogger) Debugf(format string, args ...any) {
	if l.level >= VPNLogDebug {
		log.Printf(l.prefix+"[DEBUG] "+format, args...)
	}
}

func (l *vpnLogger) Infof(format string, args ...any) {
	if l.level >= VPNLogInfo {
		log.Printf(l.prefix+"[INFO]  "+format, args...)
	}
}

func (l *vpnLogger) Warnf(format string, args ...any) {
	log.Printf(l.prefix+"[WARN]  "+format, args...)
}

func (l *vpnLogger) Errorf(format string, args ...any) {
	log.Printf(l.prefix+"[ERROR] "+format, args...)
}

// newWGLogger creates a leveled logger for the WireGuard tunnel.
func newWGLogger(level int) *vpnLogger {
	return &vpnLogger{level: level, prefix: "wg: "}
}

// newOVPNLogger creates a leveled logger for the OpenVPN tunnel.
func newOVPNLogger(level int) *vpnLogger {
	return &vpnLogger{level: level, prefix: "ovpn: "}
}

