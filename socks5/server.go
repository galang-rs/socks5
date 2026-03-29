// Package socks5 provides a SOCKS5 proxy server (RFC 1928 / RFC 1929).
//
// Supports username/password authentication with multiple credentials
// and pluggable backends for routing connections.
//
// Usage:
//
//	srv := socks5.New(
//	    socks5.WithAddr(":1080"),
//	    socks5.WithAuth(authenticator),
//	    socks5.WithBackend(be),
//	)
//	srv.ListenAndServe(ctx)
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/galang-rs/socks5/auth"
	"github.com/galang-rs/socks5/backend"
)

// maxUDPPacket is the maximum UDP datagram size we handle.
const maxUDPPacket = 65535

// SOCKS5 constants.
const (
	socks5Version = 0x05

	// Auth methods.
	authNone         = 0x00
	authUserPass     = 0x02
	authNoAcceptable = 0xff

	// Auth sub-negotiation (RFC 1929).
	authUserPassVersion = 0x01
	authSuccess         = 0x00
	authFailure         = 0x01

	// Commands.
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	// Address types.
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes.
	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repConnNotAllowed   = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

// Logger interface for the SOCKS5 server.
type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type stdLogger struct{}

func (stdLogger) Infof(format string, args ...any)  { log.Printf("[SOCKS5] "+format, args...) }
func (stdLogger) Errorf(format string, args ...any) { log.Printf("[SOCKS5:ERR] "+format, args...) }

// Server is a SOCKS5 proxy server.
type Server struct {
	addr     string
	auth     *auth.Multi
	backend  backend.Backend
	logger   Logger
	listener net.Listener
	udpConn  *net.UDPConn
	udpFlows sync.Map // key: string(clientAddr) -> *udpRelay
	mu       sync.Mutex
	wg       sync.WaitGroup // tracks active goroutines for graceful shutdown
}

// udpRelay tracks a single client's UDP association.
type udpRelay struct {
	mu         sync.Mutex     // protects clientAddr
	clientAddr *net.UDPAddr
	flows      sync.Map // key: string(targetAddr) -> net.Conn (tunnel UDP conn)
	cancel     context.CancelFunc
}

// Option configures the Server.
type Option func(*Server)

// New creates a new SOCKS5 server with the given options.
func New(opts ...Option) *Server {
	s := &Server{
		addr:    "127.0.0.1:1080",
		backend: backend.NewDirect(),
		logger:  stdLogger{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithAddr sets the listen address (e.g. ":1080", "0.0.0.0:9050").
func WithAddr(addr string) Option {
	return func(s *Server) { s.addr = addr }
}

// WithAuth sets the multi-credential authenticator.
// If nil, no authentication is required.
func WithAuth(a *auth.Multi) Option {
	return func(s *Server) { s.auth = a }
}

// WithBackend sets the tunnel backend for upstream connections.
func WithBackend(b backend.Backend) Option {
	return func(s *Server) { s.backend = b }
}

// WithLogger sets a custom logger.
func WithLogger(l Logger) Option {
	return func(s *Server) { s.logger = l }
}

// ListenAndServe starts the SOCKS5 server and blocks until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Use tcp4/udp4 to avoid dual-stack source address mismatch.
	// IPv6-bound sockets send replies with ::ffff:x.x.x.x source which
	// IPv4 connected UDP clients reject.
	ln, err := net.Listen("tcp4", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: listen tcp: %w", err)
	}

	// Start UDP listener on the same port for UDP ASSOCIATE relay.
	udpAddr, err := net.ResolveUDPAddr("udp4", s.addr)
	if err != nil {
		ln.Close()
		return fmt.Errorf("socks5: resolve udp addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		ln.Close()
		return fmt.Errorf("socks5: listen udp: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.udpConn = udpConn
	s.mu.Unlock()

	s.logger.Infof("listening on %s TCP+UDP (backend: %s)", ln.Addr(), s.backend.Name())
	if s.auth != nil {
		s.logger.Infof("auth enabled: %d credential(s)", s.auth.Count())
	} else {
		s.logger.Infof("auth disabled (no authentication)")
	}

	// Close listeners when context is done.
	go func() {
		<-ctx.Done()
		ln.Close()
		udpConn.Close()
	}()

	// Start UDP relay loop (tracked).
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.udpRelayLoop(ctx)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.wg.Wait() // wait for all active goroutines to finish
				return nil
			default:
				s.logger.Errorf("accept: %v", err)
				return err
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Addr returns the listener's network address, or nil if not started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Close stops the SOCKS5 server and waits for active goroutines to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.mu.Unlock()

	// Wait for all active goroutines (handleConn, udpRelayLoop, etc.)
	s.wg.Wait()
	return err
}

// --- connection handling ---

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Method negotiation.
	user, err := s.negotiate(conn)
	if err != nil {
		s.logger.Errorf("%s: negotiate: %v", conn.RemoteAddr(), err)
		return
	}

	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// 2. Handle request.
	if err := s.handleRequest(ctx, conn, user); err != nil {
		s.logger.Errorf("%s: request: %v", conn.RemoteAddr(), err)
	}
}

// negotiate performs SOCKS5 method selection and optional authentication.
func (s *Server) negotiate(conn net.Conn) (string, error) {
	// Read version + method count.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read header: %w", err)
	}

	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported version: %d", header[0])
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}

	// Pick auth method.
	if s.auth != nil {
		// Require username/password.
		if !hasMethod(methods, authUserPass) {
			conn.Write([]byte{socks5Version, authNoAcceptable})
			return "", errors.New("client does not support username/password auth")
		}
		conn.Write([]byte{socks5Version, authUserPass})
		return s.authenticateUserPass(conn)
	}

	// No auth required.
	if hasMethod(methods, authNone) {
		conn.Write([]byte{socks5Version, authNone})
		return "", nil
	}

	conn.Write([]byte{socks5Version, authNoAcceptable})
	return "", errors.New("no acceptable auth method")
}

// authenticateUserPass performs RFC 1929 username/password authentication.
func (s *Server) authenticateUserPass(conn net.Conn) (string, error) {
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("auth read: %w", err)
	}

	if header[0] != authUserPassVersion {
		return "", fmt.Errorf("bad auth version: %d", header[0])
	}

	ulen := int(header[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return "", fmt.Errorf("auth read username: %w", err)
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return "", fmt.Errorf("auth read plen: %w", err)
	}

	plen := int(plenBuf[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return "", fmt.Errorf("auth read password: %w", err)
	}

	username := string(uname)
	password := string(passwd)

	if s.auth.Authenticate(username, password) {
		conn.Write([]byte{authUserPassVersion, authSuccess})
		return username, nil
	}

	conn.Write([]byte{authUserPassVersion, authFailure})
	return "", fmt.Errorf("authentication failed for user %q", username)
}

// handleRequest processes the SOCKS5 request after authentication.
func (s *Server) handleRequest(ctx context.Context, conn net.Conn, user string) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read request: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("bad version: %d", header[0])
	}

	cmd := header[1]

	// Parse destination address.
	addr, err := s.readAddr(conn, header[3])
	if err != nil {
		s.sendReply(conn, repAtypNotSupported, nil)
		return err
	}

	// Log connection.
	userInfo := "anon"
	if user != "" {
		userInfo = user
	}

	conn.SetDeadline(time.Time{}) // clear deadline for relay

	switch cmd {
	case cmdConnect:
		s.logger.Infof("[%s] CONNECT %s ← %s", userInfo, addr, conn.RemoteAddr())
		return s.handleConnect(ctx, conn, addr)

	case cmdUDPAssociate:
		s.logger.Infof("[%s] UDP ASSOCIATE %s ← %s", userInfo, addr, conn.RemoteAddr())
		return s.handleUDPAssociate(ctx, conn, addr)

	case cmdBind:
		s.logger.Infof("[%s] BIND %s ← %s", userInfo, addr, conn.RemoteAddr())
		return s.handleBind(ctx, conn, addr)

	default:
		s.sendReply(conn, repCmdNotSupported, nil)
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

// handleConnect handles SOCKS5 CONNECT command (TCP proxy).
func (s *Server) handleConnect(ctx context.Context, conn net.Conn, addr string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	target, err := s.backend.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		s.sendReply(conn, repHostUnreachable, nil)
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer target.Close()

	// Send success reply with bound address.
	if tcpAddr, ok := target.LocalAddr().(*net.TCPAddr); ok {
		s.sendReply(conn, repSuccess, tcpAddr)
	} else {
		s.sendReply(conn, repSuccess, nil)
	}

	// Bidirectional relay (context-aware, force-closeable).
	s.relay(ctx, conn, target)
	return nil
}

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE command.
// It tells the client which UDP address to send datagrams to (our UDP relay),
// then keeps the TCP control connection open until the client disconnects.
func (s *Server) handleUDPAssociate(ctx context.Context, conn net.Conn, clientHint string) error {
	s.mu.Lock()
	udpConn := s.udpConn
	s.mu.Unlock()

	if udpConn == nil {
		s.sendReply(conn, repGeneralFailure, nil)
		return errors.New("UDP relay not available")
	}

	// Get the UDP relay address to tell the client.
	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)

	// Determine the relay IP to send to the client.
	// If listening on 0.0.0.0, use the TCP connection's local IP instead.
	relayIP := udpAddr.IP
	if relayIP.IsUnspecified() {
		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			relayIP = tcpAddr.IP
		}
	}

	bindAddr := &net.TCPAddr{IP: relayIP, Port: udpAddr.Port}
	s.sendReply(conn, repSuccess, bindAddr)

	s.logger.Infof("UDP ASSOCIATE: relay at %s for client %s", bindAddr, conn.RemoteAddr())

	// Determine expected client UDP address from the hint or TCP remote.
	clientHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	clientUDPKey := normalizeIP(clientHost) // Key by normalized client IP

	// Create relay entry for this client.
	relayCtx, relayCancel := context.WithCancel(ctx)
	relay := &udpRelay{
		clientAddr: &net.UDPAddr{IP: net.ParseIP(clientHost)},
		cancel:     relayCancel,
	}
	s.udpFlows.Store(clientUDPKey, relay)

	// Keep the TCP control connection alive.
	// When it closes, clean up the UDP association.
	defer func() {
		relayCancel()
		// Close all tunnel UDP connections for this relay.
		relay.flows.Range(func(key, value any) bool {
			if c, ok := value.(net.Conn); ok {
				c.Close()
			}
			return true
		})
		s.udpFlows.Delete(clientUDPKey)
		s.logger.Infof("UDP ASSOCIATE: cleaned up relay for %s", clientHost)
	}()

	// Force-close the TCP conn when context is cancelled so io.Copy unblocks.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-relayCtx.Done()
		conn.Close()
	}()

	// Block until TCP control connection closes or context is cancelled.
	// Per RFC 1928: "A UDP association terminates when the TCP connection
	// that the UDP ASSOCIATE request arrived at terminates."
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, conn)
		close(done)
	}()

	select {
	case <-done:
	case <-relayCtx.Done():
	}
	return nil
}

// handleBind handles SOCKS5 BIND command.
func (s *Server) handleBind(ctx context.Context, conn net.Conn, addr string) error {
	// BIND is rarely used (FTP active mode). For now, return not supported
	// but with proper error instead of crashing.
	s.sendReply(conn, repCmdNotSupported, nil)
	return fmt.Errorf("BIND not implemented")
}

// --- UDP relay ---

// udpRelayLoop reads SOCKS5 UDP datagrams from clients and relays them.
func (s *Server) udpRelayLoop(ctx context.Context) {
	buf := make([]byte, maxUDPPacket)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Errorf("UDP read: %v", err)
				continue
			}
		}

		if n < 4 {
			continue // too short for SOCKS5 UDP header
		}

		// Parse SOCKS5 UDP datagram header (RFC 1928 §7).
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		// +----+------+------+----------+----------+----------+
		data := make([]byte, n)
		copy(data, buf[:n])

		// Skip fragments.
		frag := data[2]
		if frag != 0x00 {
			continue
		}

		// Parse target address.
		targetAddr, headerLen, err := parseSocks5UDPAddr(data)
		if err != nil {
			s.logger.Errorf("UDP parse addr: %v", err)
			continue
		}

		payload := data[headerLen:]

		s.logger.Infof("UDP RELAY: %s → %s (%d bytes payload)", clientAddr, targetAddr, len(payload))

		// Find the relay for this client.
		clientKey := normalizeIP(clientAddr.IP.String())
		relayVal, ok := s.udpFlows.Load(clientKey)
		if !ok {
			s.logger.Errorf("UDP: no association for client %s", clientKey)
			continue
		}
		relay := relayVal.(*udpRelay)

		// Update the client's actual UDP address (port may vary).
		relay.mu.Lock()
		relay.clientAddr = clientAddr
		relay.mu.Unlock()

		// Get or create tunnel connection for this target.
		var tunnelConn net.Conn
		if v, ok := relay.flows.Load(targetAddr); ok {
			tunnelConn = v.(net.Conn)
		} else {
			// Dial through the tunnel backend.
			s.logger.Infof("UDP RELAY: dialing tunnel to %s", targetAddr)
			dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			tc, err := s.backend.DialContext(dialCtx, "udp", targetAddr)
			cancel()
			if err != nil {
				s.logger.Errorf("UDP tunnel dial %s: %v", targetAddr, err)
				continue
			}
			s.logger.Infof("UDP RELAY: tunnel connected to %s", targetAddr)
			tunnelConn = tc
			relay.flows.Store(targetAddr, tunnelConn)

			// Start goroutine to read replies from tunnel and send back to client.
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.udpReplyLoop(ctx, relay, tunnelConn, targetAddr)
			}()
		}

		// Forward payload to tunnel.
		if _, err := tunnelConn.Write(payload); err != nil {
			s.logger.Errorf("UDP tunnel write: %v", err)
			tunnelConn.Close()
			relay.flows.Delete(targetAddr)
		} else {
			s.logger.Infof("UDP RELAY: forwarded %d bytes to %s", len(payload), targetAddr)
		}
	}
}

// udpReplyLoop reads replies from a tunnel UDP connection and sends them
// back to the SOCKS5 client with proper datagram encapsulation.
func (s *Server) udpReplyLoop(ctx context.Context, relay *udpRelay, tunnelConn net.Conn, targetAddr string) {
	defer func() {
		s.logger.Infof("UDP REPLY: loop ended for %s", targetAddr)
		tunnelConn.Close()
		relay.flows.Delete(targetAddr)
	}()

	// Force-close tunnelConn when context is cancelled to unblock Read.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		tunnelConn.Close()
	}()

	s.logger.Infof("UDP REPLY: starting reply loop for %s", targetAddr)
	buf := make([]byte, maxUDPPacket)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tunnelConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, err := tunnelConn.Read(buf)
		if err != nil {
			s.logger.Infof("UDP REPLY: read from %s error: %v", targetAddr, err)
			return
		}

		// Read clientAddr under lock.
		relay.mu.Lock()
		clientAddr := relay.clientAddr
		relay.mu.Unlock()

		s.logger.Infof("UDP REPLY: got %d bytes from %s, sending to client %s", n, targetAddr, clientAddr)

		// Build SOCKS5 UDP datagram response.
		host, portStr, _ := net.SplitHostPort(targetAddr)
		port, _ := net.LookupPort("udp", portStr)

		var header []byte
		header = append(header, 0x00, 0x00, 0x00) // RSV + FRAG

		ip := net.ParseIP(host)
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, atypIPv4)
			header = append(header, ip4...)
		} else if ip16 := ip.To16(); ip16 != nil {
			header = append(header, atypIPv6)
			header = append(header, ip16...)
		} else {
			header = append(header, atypDomain)
			header = append(header, byte(len(host)))
			header = append(header, []byte(host)...)
		}

		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(port))
		header = append(header, portBuf...)

		// Combine header + payload.
		datagram := append(header, buf[:n]...)

		if clientAddr != nil {
			nn, err := s.udpConn.WriteToUDP(datagram, clientAddr)
			s.logger.Infof("UDP REPLY: sent %d bytes to client %s (err=%v)", nn, clientAddr, err)
		}
	}
}

// parseSocks5UDPAddr parses the target address from a SOCKS5 UDP datagram.
// Returns the target address string, the total header length, and any error.
func parseSocks5UDPAddr(data []byte) (string, int, error) {
	if len(data) < 4 {
		return "", 0, errors.New("datagram too short")
	}

	atyp := data[3]
	offset := 4

	var host string
	switch atyp {
	case atypIPv4:
		if len(data) < offset+4+2 {
			return "", 0, errors.New("datagram too short for IPv4")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4

	case atypDomain:
		if len(data) < offset+1 {
			return "", 0, errors.New("datagram too short for domain length")
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return "", 0, errors.New("datagram too short for domain")
		}
		host = string(data[offset : offset+domainLen])
		offset += domainLen

	case atypIPv6:
		if len(data) < offset+16+2 {
			return "", 0, errors.New("datagram too short for IPv6")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16

	default:
		return "", 0, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), offset, nil
}

// readAddr reads the destination address from the SOCKS5 request.
func (s *Server) readAddr(conn net.Conn, atyp byte) (string, error) {
	var host string

	switch atyp {
	case atypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		host = net.IP(ipBuf).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		host = string(domainBuf)

	case atypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		host = net.IP(ipBuf).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// Read port (2 bytes, big endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// sendReply sends a SOCKS5 reply to the client.
func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr net.Addr) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+

	var ip net.IP
	var port int

	switch a := bindAddr.(type) {
	case *net.TCPAddr:
		ip = a.IP
		port = a.Port
	case *net.UDPAddr:
		ip = a.IP
		port = a.Port
	default:
		// nil or unknown — zero address.
	}

	// Normalize IPv6 to IPv4 when possible:
	// - ::1 (IPv6 loopback) → 127.0.0.1
	// - ::ffff:x.x.x.x (IPv4-mapped IPv6) → x.x.x.x
	if ip != nil {
		if ip.IsLoopback() {
			ip = net.IPv4(127, 0, 0, 1)
		} else if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
	}

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		reply := []byte{socks5Version, rep, 0x00, atypIPv4}
		reply = append(reply, ip4...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(port))
		reply = append(reply, portBuf...)
		conn.Write(reply)
	} else if ip16 := ip.To16(); ip16 != nil {
		// IPv6
		reply := []byte{socks5Version, rep, 0x00, atypIPv6}
		reply = append(reply, ip16...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(port))
		reply = append(reply, portBuf...)
		conn.Write(reply)
	} else {
		// Zero address fallback.
		reply := []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
		conn.Write(reply)
	}
}

// relay copies data bidirectionally between two connections.
// It is context-aware: when ctx is cancelled, both connections are
// force-closed to unblock any in-progress io.Copy calls.
func (s *Server) relay(ctx context.Context, client, target net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3) // 2 copy goroutines + 1 force-close sentinel

	// Force-close both connections when context is cancelled,
	// which unblocks any blocking io.Copy calls.
	go func() {
		defer wg.Done()
		<-ctx.Done()
		client.Close()
		target.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		cancel() // signal the other direction to stop
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		cancel() // signal the other direction to stop
	}()

	wg.Wait()
}

// normalizeIP converts IPv6 loopback (::1) and IPv4-mapped IPv6
// addresses to plain IPv4 strings for consistent key matching.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if ip.IsLoopback() {
		return "127.0.0.1"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func hasMethod(methods []byte, method byte) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}
