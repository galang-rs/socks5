package netstack

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// udpConnKey identifies a virtual UDP connection (connected mode).
type udpConnKey struct {
	localPort  uint16
	remoteIP   [16]byte
	remotePort uint16
}

// VirtualUDPConn is a UDP connection routed through the virtual network stack.
// It implements net.Conn for connected UDP (specific remote endpoint).
type VirtualUDPConn struct {
	stack      *Stack
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16

	mu       sync.Mutex
	closed   bool
	closeCh  chan struct{}
	closeOnce sync.Once

	// Inbound datagrams are delivered here by the stack's readLoop.
	recvCh chan []byte

	readDeadline  time.Time
	writeDeadline time.Time
}

func newVirtualUDPConn(stack *Stack, localIP net.IP, localPort uint16,
	remoteIP net.IP, remotePort uint16) *VirtualUDPConn {

	return &VirtualUDPConn{
		stack:      stack,
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		recvCh:     make(chan []byte, 64), // buffer up to 64 datagrams
		closeCh:    make(chan struct{}),
	}
}

// key returns the connection key for dispatch lookup.
func (c *VirtualUDPConn) key() udpConnKey {
	var remoteAddr [16]byte
	copy(remoteAddr[:], c.remoteIP.To16())
	return udpConnKey{
		localPort:  c.localPort,
		remoteIP:   remoteAddr,
		remotePort: c.remotePort,
	}
}

// deliver is called by the stack's dispatchUDP to push an inbound datagram.
// Must not block.
func (c *VirtualUDPConn) deliver(payload []byte) {
	// Copy payload to avoid aliasing with read buffer.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case c.recvCh <- buf:
	default:
		// Drop if channel is full (backpressure).
	}
}

// --- net.Conn implementation ---

// Read reads the next inbound UDP datagram payload.
// Each call returns exactly one datagram (or blocks until one arrives).
func (c *VirtualUDPConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	var deadlineCh <-chan time.Time
	if !c.readDeadline.IsZero() {
		if time.Now().After(c.readDeadline) {
			return 0, errors.New("i/o timeout")
		}
		t := time.NewTimer(time.Until(c.readDeadline))
		defer t.Stop()
		deadlineCh = t.C
	}

	select {
	case data := <-c.recvCh:
		n := copy(b, data)
		return n, nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	case <-deadlineCh:
		return 0, errors.New("i/o timeout")
	}
}

// Write sends a UDP datagram to the connected remote endpoint through the tunnel.
func (c *VirtualUDPConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	// Build UDP packet.
	udpData := BuildUDPPacket(c.localPort, c.remotePort, b, c.localIP, c.remoteIP)
	// Build IP packet.
	ipData := BuildIPPacket(c.localIP, c.remoteIP, ProtoUDP, udpData, c.stack.nextID())

	if err := c.stack.writePacket(ipData); err != nil {
		return 0, fmt.Errorf("netstack: udp write: %w", err)
	}

	return len(b), nil
}

// Close closes the UDP connection and unregisters it from the stack.
func (c *VirtualUDPConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	c.closeOnce.Do(func() { close(c.closeCh) })

	// Unregister from stack.
	c.stack.removeUDPConn(c.key())
	c.stack.freePort(c.localPort)

	// Drain receive channel to free buffered datagrams.
	for {
		select {
		case <-c.recvCh:
		default:
			return nil
		}
	}
}

func (c *VirtualUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *VirtualUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: c.remoteIP, Port: int(c.remotePort)}
}

func (c *VirtualUDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *VirtualUDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *VirtualUDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
