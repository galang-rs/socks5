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
	cmdConnect = 0x01

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
	mu       sync.Mutex
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
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.logger.Infof("listening on %s (backend: %s)", ln.Addr(), s.backend.Name())
	if s.auth != nil {
		s.logger.Infof("auth enabled: %d credential(s)", s.auth.Count())
	} else {
		s.logger.Infof("auth disabled (no authentication)")
	}

	// Close listener when context is done.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Errorf("accept: %v", err)
				return err
			}
		}

		go s.handleConn(ctx, conn)
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

// Close stops the SOCKS5 server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
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

	if header[1] != cmdConnect {
		s.sendReply(conn, repCmdNotSupported, nil)
		return fmt.Errorf("unsupported command: %d", header[1])
	}

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
	s.logger.Infof("[%s] CONNECT %s ← %s", userInfo, addr, conn.RemoteAddr())

	// Connect through backend.
	conn.SetDeadline(time.Time{}) // clear deadline for relay

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	target, err := s.backend.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		s.sendReply(conn, repHostUnreachable, nil)
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer target.Close()

	// Send success reply.
	localAddr := target.LocalAddr().(*net.TCPAddr)
	s.sendReply(conn, repSuccess, localAddr)

	// Bidirectional relay.
	s.relay(conn, target)
	return nil
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
func (s *Server) sendReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+

	reply := []byte{socks5Version, rep, 0x00, atypIPv4}

	if bindAddr != nil && bindAddr.IP.To4() != nil {
		reply = append(reply, bindAddr.IP.To4()...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(bindAddr.Port))
		reply = append(reply, portBuf...)
	} else {
		// Zero address.
		reply = append(reply, 0, 0, 0, 0, 0, 0)
	}

	conn.Write(reply)
}

// relay copies data bidirectionally between two connections.
func (s *Server) relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func hasMethod(methods []byte, method byte) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}
