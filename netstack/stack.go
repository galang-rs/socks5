package netstack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// TUNDevice is the interface that VPN TUN devices must satisfy.
// Both wireguard and ovpn TUN types implement this.
type TUNDevice interface {
	Read(data []byte) (int, error)
	Write(data []byte) (int, error)
	Close() error
}

// Logger for the stack.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// Stack is a lightweight virtual TCP/IP network stack on top of a TUN device.
type Stack struct {
	tun      TUNDevice
	localIP  net.IP // IPv4 local address
	localIP6 net.IP // IPv6 local address (nil if not available)
	gateway  net.IP
	mtu      int
	dns      []string
	logger   Logger

	// TCP connections.
	connMu sync.RWMutex
	conns  map[connKey]*VirtualConn

	// UDP connections (general-purpose).
	udpConnMu sync.RWMutex
	udpConns  map[udpConnKey]*VirtualUDPConn

	// UDP handlers (legacy, for DNS resolver).
	udpMu       sync.RWMutex
	udpHandlers map[uint16]chan []byte

	// Port allocation.
	portMu   sync.Mutex
	nextPort uint16
	usedPort map[uint16]bool

	// Packet ID counter.
	packetID uint32

	// Resolver.
	Resolver *Resolver

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// StackConfig holds configuration for creating a Stack.
type StackConfig struct {
	TUN      TUNDevice
	LocalIP  string // IPv4 address (required)
	LocalIP6 string // IPv6 address (optional, for dual-stack)
	Gateway  string
	MTU      int
	DNS      []string
	Logger   Logger
}

// New creates a new virtual network stack on top of a TUN device.
func New(cfg StackConfig) (*Stack, error) {
	localIP := net.ParseIP(cfg.LocalIP).To4()
	if localIP == nil {
		return nil, fmt.Errorf("netstack: invalid local IP: %s", cfg.LocalIP)
	}

	// Parse optional IPv6 local address.
	var localIP6 net.IP
	if cfg.LocalIP6 != "" {
		localIP6 = net.ParseIP(cfg.LocalIP6)
		if localIP6 == nil {
			return nil, fmt.Errorf("netstack: invalid local IPv6: %s", cfg.LocalIP6)
		}
		localIP6 = localIP6.To16()
	}

	// Gateway is informational — try parsing as IP, resolve hostname, or fallback.
	gateway := net.ParseIP(cfg.Gateway).To4()
	if gateway == nil {
		// Try stripping port (e.g. "host:51820").
		host := cfg.Gateway
		if h, _, err := net.SplitHostPort(cfg.Gateway); err == nil {
			host = h
		}
		gateway = net.ParseIP(host).To4()
		if gateway == nil {
			// Try DNS resolve.
			if addrs, err := net.LookupHost(host); err == nil && len(addrs) > 0 {
				gateway = net.ParseIP(addrs[0]).To4()
			}
		}
		if gateway == nil {
			gateway = net.IPv4(0, 0, 0, 0).To4()
		}
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	logger := cfg.Logger
	if logger == nil {
		logger = nopLogger{}
	}

	dns := cfg.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}

	s := &Stack{
		tun:         cfg.TUN,
		localIP:     localIP,
		localIP6:    localIP6,
		gateway:     gateway,
		mtu:         mtu,
		dns:         dns,
		logger:      logger,
		conns:       make(map[connKey]*VirtualConn),
		udpConns:    make(map[udpConnKey]*VirtualUDPConn),
		udpHandlers: make(map[uint16]chan []byte),
		nextPort:    10000,
		usedPort:    make(map[uint16]bool),
	}

	s.Resolver = NewResolver(s, dns[0])
	return s, nil
}

// Start begins the TUN read loop. Call this after creating the stack.
func (s *Stack) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.readLoop(ctx)
}

// Close shuts down the stack and all active connections.
func (s *Stack) Close() error {
	if s.cancel != nil {
		s.cancel()
	}

	// Force-close the TUN device to unblock readLoop's blocking tun.Read().
	// TUN devices have closeOnce protection, so double-close is safe.
	s.tun.Close()

	// Close all TCP connections.
	s.connMu.Lock()
	for _, c := range s.conns {
		c.closeOnce.Do(func() { close(c.closeCh) })
	}
	s.conns = make(map[connKey]*VirtualConn)
	s.connMu.Unlock()

	// Close all UDP connections.
	s.udpConnMu.Lock()
	for _, c := range s.udpConns {
		c.closeOnce.Do(func() { close(c.closeCh) })
	}
	s.udpConns = make(map[udpConnKey]*VirtualUDPConn)
	s.udpConnMu.Unlock()

	s.wg.Wait()
	return nil
}

// HasIPv6 returns true if the stack has an IPv6 address configured.
func (s *Stack) HasIPv6() bool {
	return s.localIP6 != nil
}

// localIPFor returns the appropriate local IP for the given remote IP.
// If remote is IPv6, returns the stack's IPv6 address; otherwise IPv4.
func (s *Stack) localIPFor(remoteIP net.IP) net.IP {
	if remoteIP.To4() == nil && s.localIP6 != nil {
		return s.localIP6
	}
	return s.localIP
}

// DialContext creates a TCP or UDP connection through the tunnel.
// Hostnames are resolved via DNS through the tunnel.
func (s *Stack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netstack: invalid address %q: %w", addr, err)
	}

	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("netstack: invalid port %q: %w", portStr, err)
	}

	// Resolve hostname.
	remoteIP, err := s.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("netstack: resolve %q: %w", host, err)
	}

	// Determine local IP based on remote address family.
	localIP := s.localIPFor(remoteIP)

	// Branch based on network type.
	switch network {
	case "udp", "udp4", "udp6":
		return s.dialUDP(ctx, host, localIP, remoteIP, uint16(port))
	case "tcp", "tcp4", "tcp6", "":
		return s.dialTCP(ctx, host, localIP, remoteIP, uint16(port), addr)
	default:
		return nil, fmt.Errorf("netstack: unsupported network %q", network)
	}
}

// dialTCP creates a TCP connection through the tunnel.
func (s *Stack) dialTCP(ctx context.Context, host string, localIP, remoteIP net.IP, port uint16, addr string) (net.Conn, error) {
	localPort := s.allocPort()
	conn := newVirtualConn(s, localIP, localPort, remoteIP, port)

	// Register connection for dispatch.
	s.connMu.Lock()
	s.conns[conn.key()] = conn
	s.connMu.Unlock()

	s.logger.Debugf("tcp dial %s → %s:%d (local port %d)", host, remoteIP, port, localPort)

	// TCP handshake.
	if err := conn.handshake(ctx); err != nil {
		s.removeConn(conn.key())
		s.freePort(localPort)
		return nil, fmt.Errorf("netstack: connect %s: %w", addr, err)
	}

	s.logger.Infof("tcp connected %s:%d via tunnel", host, port)
	return conn, nil
}

// dialUDP creates a UDP connection through the tunnel.
// No handshake needed — UDP is connectionless. The connection is
// registered so that reply packets from the remote are delivered.
func (s *Stack) dialUDP(ctx context.Context, host string, localIP, remoteIP net.IP, port uint16) (net.Conn, error) {
	localPort := s.allocPort()
	conn := newVirtualUDPConn(s, localIP, localPort, remoteIP, port)

	// Register UDP connection for dispatch.
	s.udpConnMu.Lock()
	s.udpConns[conn.key()] = conn
	s.udpConnMu.Unlock()

	s.logger.Debugf("udp dial %s → %s:%d (local port %d)", host, remoteIP, port, localPort)
	s.logger.Infof("udp ready %s:%d via tunnel", host, port)
	return conn, nil
}

// MSS returns the maximum TCP segment size based on MTU.
func (s *Stack) MSS() int {
	return s.MSSFor(false)
}

// MSSFor returns the maximum TCP segment size for the specified IP version.
func (s *Stack) MSSFor(isIPv6 bool) int {
	// MTU - IP header - TCP header (20)
	hdrLen := ipHeaderLen
	if isIPv6 {
		hdrLen = ip6HeaderLen
	}
	mss := s.mtu - hdrLen - tcpHeaderLen
	if mss < 536 {
		mss = 536 // minimum MSS per RFC 879
	}
	return mss
}

// --- internal ---

// readLoop continuously reads IP packets from the TUN and dispatches them.
func (s *Stack) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, s.mtu+100) // extra space for safety

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.tun.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Errorf("TUN read: %v", err)
				return
			}
		}

		if n == 0 {
			continue
		}

		pkt, err := ParseIPPacket(buf[:n])
		if err != nil {
			continue // skip unsupported or malformed
		}

		s.dispatch(pkt)
	}
}

// dispatch routes an incoming IP packet to the correct handler.
func (s *Stack) dispatch(pkt *IPPacket) {
	switch pkt.Protocol {
	case ProtoTCP:
		s.dispatchTCP(pkt)
	case ProtoUDP:
		s.dispatchUDP(pkt)
	}
}

func (s *Stack) dispatchTCP(pkt *IPPacket) {
	seg, err := ParseTCPSegment(pkt.Payload)
	if err != nil {
		return
	}

	// Connection key: the source from the packet is the remote.
	var remoteAddr [16]byte
	copy(remoteAddr[:], pkt.SrcIP.To16())
	key := connKey{
		localPort:  seg.DstPort,
		remoteIP:   remoteAddr,
		remotePort: seg.SrcPort,
	}

	s.connMu.RLock()
	conn, ok := s.conns[key]
	s.connMu.RUnlock()

	if !ok {
		// No connection found — send RST to clean up.
		if seg.Flags&FlagRST == 0 {
			s.sendRST(pkt, seg)
		}
		return
	}

	conn.handleInbound(seg)
}

func (s *Stack) dispatchUDP(pkt *IPPacket) {
	udpPkt, err := ParseUDPPacket(pkt.Payload)
	if err != nil {
		return
	}

	// 1. Try connected UDP connections first (general-purpose UDP).
	var srcAddr [16]byte
	copy(srcAddr[:], pkt.SrcIP.To16())
	udpKey := udpConnKey{
		localPort:  udpPkt.DstPort,
		remoteIP:   srcAddr,
		remotePort: udpPkt.SrcPort,
	}

	s.udpConnMu.RLock()
	uconn, ok := s.udpConns[udpKey]
	s.udpConnMu.RUnlock()

	if ok {
		uconn.deliver(udpPkt.Payload)
		return
	}

	// 2. Fall back to legacy DNS handlers (port-only match).
	s.udpMu.RLock()
	ch, ok := s.udpHandlers[udpPkt.DstPort]
	s.udpMu.RUnlock()

	if ok {
		select {
		case ch <- udpPkt.Payload:
		default:
		}
	}
}

// sendRST sends a TCP RST for an unexpected incoming segment.
func (s *Stack) sendRST(pkt *IPPacket, seg *TCPSegment) {
	var ack uint32
	flags := uint8(FlagRST | FlagACK)
	if seg.Flags&FlagACK != 0 {
		ack = seg.SeqNum + uint32(len(seg.Payload))
	} else {
		ack = seg.SeqNum + 1
	}

	tcpData := BuildTCPSegment(
		seg.DstPort, seg.SrcPort,
		seg.AckNum, ack,
		flags, 0, nil,
		pkt.DstIP, pkt.SrcIP,
	)
	ipData := BuildIPPacket(pkt.DstIP, pkt.SrcIP, ProtoTCP, tcpData, s.nextID())
	s.writePacket(ipData)
}

func (s *Stack) writePacket(data []byte) error {
	_, err := s.tun.Write(data)
	return err
}

func (s *Stack) nextID() uint16 {
	return uint16(atomic.AddUint32(&s.packetID, 1))
}

// --- port management ---

func (s *Stack) allocPort() uint16 {
	s.portMu.Lock()
	defer s.portMu.Unlock()

	for {
		port := s.nextPort
		s.nextPort++
		if s.nextPort > 60000 {
			s.nextPort = 10000
		}
		if !s.usedPort[port] {
			s.usedPort[port] = true
			return port
		}
	}
}

func (s *Stack) freePort(port uint16) {
	s.portMu.Lock()
	delete(s.usedPort, port)
	s.portMu.Unlock()
}

// --- UDP handler management (used by DNS resolver) ---

func (s *Stack) registerUDP(port uint16, ch chan []byte) {
	s.udpMu.Lock()
	s.udpHandlers[port] = ch
	s.udpMu.Unlock()
}

func (s *Stack) unregisterUDP(port uint16) {
	s.udpMu.Lock()
	delete(s.udpHandlers, port)
	s.udpMu.Unlock()
}

func (s *Stack) removeConn(key connKey) {
	s.connMu.Lock()
	delete(s.conns, key)
	s.connMu.Unlock()
}

func (s *Stack) removeUDPConn(key udpConnKey) {
	s.udpConnMu.Lock()
	delete(s.udpConns, key)
	s.udpConnMu.Unlock()
}
