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

// connKey identifies a virtual TCP connection.
type connKey struct {
	localPort  uint16
	remoteIP   [4]byte
	remotePort uint16
}

// Logger for the stack.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// Stack is a lightweight virtual TCP/IP network stack on top of a TUN device.
type Stack struct {
	tun     TUNDevice
	localIP net.IP
	gateway net.IP
	mtu     int
	dns     []string
	logger  Logger

	// TCP connections.
	connMu sync.RWMutex
	conns  map[connKey]*VirtualConn

	// UDP handlers (for DNS).
	udpMu      sync.RWMutex
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
	TUN     TUNDevice
	LocalIP string
	Gateway string
	MTU     int
	DNS     []string
	Logger  Logger
}

// New creates a new virtual network stack on top of a TUN device.
func New(cfg StackConfig) (*Stack, error) {
	localIP := net.ParseIP(cfg.LocalIP).To4()
	if localIP == nil {
		return nil, fmt.Errorf("netstack: invalid local IP: %s", cfg.LocalIP)
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
		gateway:     gateway,
		mtu:         mtu,
		dns:         dns,
		logger:      logger,
		conns:       make(map[connKey]*VirtualConn),
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

	// Close all connections.
	s.connMu.Lock()
	for _, c := range s.conns {
		c.closeOnce.Do(func() { close(c.closeCh) })
	}
	s.conns = make(map[connKey]*VirtualConn)
	s.connMu.Unlock()

	s.wg.Wait()
	return nil
}

// DialContext creates a TCP connection through the tunnel.
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

	localPort := s.allocPort()
	conn := newVirtualConn(s, s.localIP, localPort, remoteIP.To4(), uint16(port))

	// Register connection for dispatch.
	s.connMu.Lock()
	s.conns[conn.key()] = conn
	s.connMu.Unlock()

	s.logger.Debugf("dial %s → %s:%d (local port %d)", host, remoteIP, port, localPort)

	// TCP handshake.
	if err := conn.handshake(ctx); err != nil {
		s.removeConn(conn.key())
		s.freePort(localPort)
		return nil, fmt.Errorf("netstack: connect %s: %w", addr, err)
	}

	s.logger.Infof("connected %s:%d via tunnel", host, port)
	return conn, nil
}

// MSS returns the maximum TCP segment size based on MTU.
func (s *Stack) MSS() int {
	// MTU - IP header (20) - TCP header (20)
	mss := s.mtu - ipHeaderLen - tcpHeaderLen
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
			continue // skip non-IPv4 or malformed
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
	var remoteAddr [4]byte
	copy(remoteAddr[:], pkt.SrcIP.To4())
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
