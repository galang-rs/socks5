package netstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultWindow = 65535
	maxRetries    = 3
	retryTimeout  = 3 * time.Second
)

// VirtualConn is a TCP connection routed through the virtual network stack.
// It implements net.Conn.
type VirtualConn struct {
	stack      *Stack
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16

	mu     sync.Mutex
	state  int
	seqNum uint32 // our next seq to send
	ackNum uint32 // next expected seq from remote

	recvBuf    bytes.Buffer
	recvNotify chan struct{} // signaled when new data arrives

	synAckCh chan *TCPSegment // handshake: receives SYN-ACK
	closeCh  chan struct{}    // closed when connection ends
	closeOnce sync.Once

	readDeadline  time.Time
	writeDeadline time.Time

	closed bool
}

func newVirtualConn(stack *Stack, localIP net.IP, localPort uint16,
	remoteIP net.IP, remotePort uint16) *VirtualConn {

	return &VirtualConn{
		stack:      stack,
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		state:      StateClosed,
		seqNum:     randomISN(),
		recvNotify: make(chan struct{}, 1),
		synAckCh:   make(chan *TCPSegment, 1),
		closeCh:    make(chan struct{}),
	}
}

// handshake performs the TCP 3-way handshake through the tunnel.
func (c *VirtualConn) handshake(ctx context.Context) error {
	c.mu.Lock()
	c.state = StateSynSent

	synSeg := BuildTCPSegment(
		c.localPort, c.remotePort,
		c.seqNum, 0,
		FlagSYN, defaultWindow, nil,
		c.localIP, c.remoteIP,
	)
	synPkt := BuildIPPacket(c.localIP, c.remoteIP, ProtoTCP, synSeg, c.stack.nextID())
	c.mu.Unlock()

	// Send SYN with retry.
	for attempt := 0; attempt < maxRetries; attempt++ {
		c.stack.logger.Debugf("TCP: SYN %s:%d → %s:%d attempt %d/%d",
			c.localIP, c.localPort, c.remoteIP, c.remotePort, attempt+1, maxRetries)

		if err := c.stack.writePacket(synPkt); err != nil {
			return fmt.Errorf("netstack: send SYN: %w", err)
		}

		timer := time.NewTimer(retryTimeout)
		select {
		case synAck := <-c.synAckCh:
			timer.Stop()
			c.stack.logger.Debugf("TCP: SYN-ACK received from %s:%d", c.remoteIP, c.remotePort)
			return c.completeSynAck(synAck)
		case <-timer.C:
			c.stack.logger.Debugf("TCP: SYN timeout %s:%d attempt %d/%d",
				c.remoteIP, c.remotePort, attempt+1, maxRetries)
			// retry
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}

	c.stack.logger.Errorf("TCP: handshake timeout %s:%d after %d attempts",
		c.remoteIP, c.remotePort, maxRetries)
	return errors.New("netstack: handshake timeout")
}

func (c *VirtualConn) completeSynAck(synAck *TCPSegment) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seqNum++ // SYN consumes 1 sequence number
	c.ackNum = synAck.SeqNum + 1
	c.state = StateEstablished

	// Send ACK.
	c.sendPacketLocked(FlagACK, nil)
	return nil
}

// handleInbound is called by the stack's read loop when a TCP segment arrives
// for this connection. Must not block.
func (c *VirtualConn) handleInbound(seg *TCPSegment) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// RST from remote — immediate close.
	if seg.Flags&FlagRST != 0 {
		c.state = StateClosed
		c.closeOnce.Do(func() { close(c.closeCh) })
		return
	}

	switch c.state {
	case StateSynSent:
		if seg.Flags&(FlagSYN|FlagACK) == FlagSYN|FlagACK {
			select {
			case c.synAckCh <- seg:
			default:
			}
		}

	case StateEstablished:
		c.handleEstablishedLocked(seg)

	case StateFinWait1:
		if seg.Flags&FlagACK != 0 {
			c.state = StateFinWait2
		}
		if seg.Flags&FlagFIN != 0 {
			c.ackNum++
			c.sendPacketLocked(FlagACK, nil)
			if c.state == StateFinWait2 {
				c.state = StateTimeWait
			} else {
				c.state = StateClosing
			}
			c.closeOnce.Do(func() { close(c.closeCh) })
		}

	case StateFinWait2:
		// Consume any remaining data.
		if len(seg.Payload) > 0 && seg.SeqNum == c.ackNum {
			c.recvBuf.Write(seg.Payload)
			c.ackNum += uint32(len(seg.Payload))
			c.sendPacketLocked(FlagACK, nil)
			c.notifyRecv()
		}
		if seg.Flags&FlagFIN != 0 {
			c.ackNum++
			c.sendPacketLocked(FlagACK, nil)
			c.state = StateTimeWait
			c.closeOnce.Do(func() { close(c.closeCh) })
		}

	case StateClosing:
		if seg.Flags&FlagACK != 0 {
			c.state = StateTimeWait
			c.closeOnce.Do(func() { close(c.closeCh) })
		}

	case StateLastAck:
		if seg.Flags&FlagACK != 0 {
			c.state = StateClosed
			c.closeOnce.Do(func() { close(c.closeCh) })
		}
	}
}

func (c *VirtualConn) handleEstablishedLocked(seg *TCPSegment) {
	c.stack.logger.Debugf("TCP rx: seq=%d ack=%d flags=0x%02x payload=%d (expect ackNum=%d)",
		seg.SeqNum, seg.AckNum, seg.Flags, len(seg.Payload), c.ackNum)

	// Process data.
	if len(seg.Payload) > 0 {
		if seg.SeqNum == c.ackNum {
			c.recvBuf.Write(seg.Payload)
			c.ackNum += uint32(len(seg.Payload))
			c.sendPacketLocked(FlagACK, nil)
			c.notifyRecv()
			c.stack.logger.Debugf("TCP rx: accepted %d bytes, new ackNum=%d", len(seg.Payload), c.ackNum)
		} else {
			// Out-of-order: send duplicate ACK.
			c.stack.logger.Debugf("TCP rx: out-of-order seq=%d (expected %d), sending dup ACK",
				seg.SeqNum, c.ackNum)
			c.sendPacketLocked(FlagACK, nil)
		}
	}

	// FIN from remote.
	if seg.Flags&FlagFIN != 0 {
		c.ackNum++
		c.sendPacketLocked(FlagACK, nil)
		c.state = StateCloseWait
		c.closeOnce.Do(func() { close(c.closeCh) })
		c.stack.logger.Debugf("TCP rx: FIN received, state → CloseWait")
	}
}

func (c *VirtualConn) notifyRecv() {
	select {
	case c.recvNotify <- struct{}{}:
	default:
	}
}

// --- net.Conn implementation ---

// Read reads decrypted data arriving through the tunnel.
func (c *VirtualConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.recvBuf.Len() > 0 {
			n, _ := c.recvBuf.Read(b)
			c.mu.Unlock()
			return n, nil
		}
		state := c.state
		closed := c.closed
		c.mu.Unlock()

		if closed || state == StateClosed || state == StateCloseWait ||
			state == StateTimeWait {
			return 0, io.EOF
		}

		// Wait for data or timeout.
		if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
			return 0, errors.New("i/o timeout")
		}

		var deadlineCh <-chan time.Time
		if !c.readDeadline.IsZero() {
			t := time.NewTimer(time.Until(c.readDeadline))
			defer t.Stop()
			deadlineCh = t.C
		}

		select {
		case <-c.recvNotify:
			continue
		case <-c.closeCh:
			// Drain any remaining data.
			c.mu.Lock()
			if c.recvBuf.Len() > 0 {
				n, _ := c.recvBuf.Read(b)
				c.mu.Unlock()
				return n, nil
			}
			c.mu.Unlock()
			return 0, io.EOF
		case <-deadlineCh:
			return 0, errors.New("i/o timeout")
		}
	}
}

// Write sends data through the tunnel.
func (c *VirtualConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.state != StateEstablished {
		return 0, net.ErrClosed
	}

	mss := c.stack.MSS()
	total := 0

	for total < len(b) {
		end := total + mss
		if end > len(b) {
			end = len(b)
		}
		chunk := b[total:end]

		if err := c.sendPacketLocked(FlagACK|FlagPSH, chunk); err != nil {
			return total, err
		}
		c.seqNum += uint32(len(chunk))
		total += len(chunk)
	}

	return total, nil
}

// Close initiates TCP connection teardown.
func (c *VirtualConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	state := c.state

	switch state {
	case StateEstablished:
		// Active close: send FIN.
		c.state = StateFinWait1
		c.sendPacketLocked(FlagFIN|FlagACK, nil)
		c.seqNum++ // FIN consumes 1 seq
		c.mu.Unlock()

		// Wait briefly for remote FIN-ACK.
		select {
		case <-c.closeCh:
		case <-time.After(5 * time.Second):
		}

	case StateCloseWait:
		// Passive close: remote already sent FIN, send ours.
		c.state = StateLastAck
		c.sendPacketLocked(FlagFIN|FlagACK, nil)
		c.seqNum++
		c.mu.Unlock()

	default:
		c.mu.Unlock()
	}

	c.closeOnce.Do(func() { close(c.closeCh) })

	// Unregister from stack and free resources.
	c.stack.removeConn(c.key())
	c.stack.freePort(c.localPort)

	// Clear receive buffer to release memory.
	c.mu.Lock()
	c.recvBuf.Reset()
	c.mu.Unlock()

	return nil
}

func (c *VirtualConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *VirtualConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.remoteIP, Port: int(c.remotePort)}
}

func (c *VirtualConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *VirtualConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *VirtualConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// --- internal helpers ---

// sendPacketLocked builds and sends a TCP+IP packet. Caller must hold c.mu.
func (c *VirtualConn) sendPacketLocked(flags uint8, payload []byte) error {
	tcpData := BuildTCPSegment(
		c.localPort, c.remotePort,
		c.seqNum, c.ackNum,
		flags, defaultWindow, payload,
		c.localIP, c.remoteIP,
	)
	ipData := BuildIPPacket(c.localIP, c.remoteIP, ProtoTCP, tcpData, c.stack.nextID())
	return c.stack.writePacket(ipData)
}

func (c *VirtualConn) key() connKey {
	var remoteAddr [4]byte
	copy(remoteAddr[:], c.remoteIP.To4())
	return connKey{
		localPort:  c.localPort,
		remoteIP:   remoteAddr,
		remotePort: c.remotePort,
	}
}

// randomISN generates a pseudo-random initial sequence number.
func randomISN() uint32 {
	return uint32(time.Now().UnixNano() & 0xffffffff)
}
