package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Resolver resolves hostnames through the virtual network stack by
// sending DNS queries as UDP packets through the TUN device.
type Resolver struct {
	stack     *Stack
	dnsServer string // IP address of DNS server (e.g. "1.1.1.1")
}

// NewResolver creates a DNS resolver that queries through the stack.
func NewResolver(stack *Stack, dnsServer string) *Resolver {
	// Strip port if present.
	host := dnsServer
	if h, _, err := net.SplitHostPort(dnsServer); err == nil {
		host = h
	}
	return &Resolver{stack: stack, dnsServer: host}
}

// Resolve resolves a hostname to an IPv4 address through the tunnel.
// If hostname is already an IP address, it is returned directly.
func (r *Resolver) Resolve(ctx context.Context, hostname string) (net.IP, error) {
	// Already an IP?
	if ip := net.ParseIP(hostname); ip != nil {
		return ip, nil
	}

	port := r.stack.allocPort()
	defer r.stack.freePort(port)

	replyCh := make(chan []byte, 1)
	r.stack.registerUDP(port, replyCh)
	defer r.stack.unregisterUDP(port)

	queryID := uint16(rand.Intn(0xffff))
	query := buildDNSQuery(hostname, queryID)

	dstIP := net.ParseIP(r.dnsServer).To4()
	if dstIP == nil {
		return nil, fmt.Errorf("netstack: invalid DNS server IP: %s", r.dnsServer)
	}

	udpData := BuildUDPPacket(port, 53, query, r.stack.localIP, dstIP)
	ipData := BuildIPPacket(r.stack.localIP, dstIP, ProtoUDP, udpData, r.stack.nextID())

	for attempt := 0; attempt < maxRetries; attempt++ {
		r.stack.logger.Debugf("DNS: resolve %s attempt %d/%d via %s (srcPort=%d)",
			hostname, attempt+1, maxRetries, r.dnsServer, port)

		if err := r.stack.writePacket(ipData); err != nil {
			return nil, fmt.Errorf("netstack: send DNS query: %w", err)
		}

		timer := time.NewTimer(retryTimeout)
		select {
		case data := <-replyCh:
			timer.Stop()
			ip, err := parseDNSResponse(data, queryID)
			if err != nil {
				r.stack.logger.Errorf("DNS: parse response for %s: %v", hostname, err)
				return nil, fmt.Errorf("netstack: DNS: %w", err)
			}
			r.stack.logger.Debugf("DNS: resolved %s → %s", hostname, ip)
			return ip, nil
		case <-timer.C:
			r.stack.logger.Debugf("DNS: timeout for %s attempt %d/%d", hostname, attempt+1, maxRetries)
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	r.stack.logger.Errorf("DNS: all %d attempts failed for %s", maxRetries, hostname)
	return nil, fmt.Errorf("netstack: DNS resolution timeout for %s", hostname)
}

// --- DNS wire format (minimal A record query/response) ---

// buildDNSQuery builds a DNS query packet for an A record.
func buildDNSQuery(hostname string, id uint16) []byte {
	// Header: 12 bytes
	// Question: variable
	var buf []byte

	// Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)       // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)   // Flags: standard query, recursion desired
	binary.BigEndian.PutUint16(header[4:6], 1)         // QDCOUNT: 1 question
	// ANCOUNT, NSCOUNT, ARCOUNT: 0
	buf = append(buf, header...)

	// Question: QNAME + QTYPE + QCLASS
	buf = append(buf, encodeDNSName(hostname)...)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], 1) // A record
	binary.BigEndian.PutUint16(qtype[2:4], 1) // IN class
	buf = append(buf, qtype...)

	return buf
}

// encodeDNSName encodes a hostname into DNS wire format.
// "www.google.com" → \x03www\x06google\x03com\x00
func encodeDNSName(name string) []byte {
	var buf []byte
	parts := strings.Split(name, ".")
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0) // root label
	return buf
}

// parseDNSResponse parses a DNS response and extracts the first A record IP.
func parseDNSResponse(data []byte, expectedID uint16) (net.IP, error) {
	if len(data) < 12 {
		return nil, errors.New("DNS response too short")
	}

	id := binary.BigEndian.Uint16(data[0:2])
	if id != expectedID {
		return nil, errors.New("DNS response ID mismatch")
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	rcode := flags & 0x000f
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error rcode=%d", rcode)
	}

	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil, errors.New("DNS: no answers")
	}

	// Skip header.
	offset := 12

	// Skip questions.
	for i := 0; i < int(qdcount); i++ {
		var err error
		offset, err = skipDNSName(data, offset)
		if err != nil {
			return nil, err
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answers.
	for i := 0; i < int(ancount); i++ {
		var err error
		offset, err = skipDNSName(data, offset)
		if err != nil {
			return nil, err
		}

		if offset+10 > len(data) {
			return nil, errors.New("DNS answer too short")
		}

		atype := binary.BigEndian.Uint16(data[offset : offset+2])
		// aclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		// ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdlength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if atype == 1 && rdlength == 4 { // A record
			if offset+4 > len(data) {
				return nil, errors.New("DNS A record data too short")
			}
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			return ip, nil
		}

		offset += int(rdlength)
	}

	return nil, errors.New("DNS: no A record found")
}

// skipDNSName skips a DNS name at the given offset, handling compression pointers.
func skipDNSName(data []byte, offset int) (int, error) {
	for {
		if offset >= len(data) {
			return 0, errors.New("DNS name: unexpected end")
		}

		labelLen := int(data[offset])
		if labelLen == 0 {
			return offset + 1, nil // root label
		}

		// Compression pointer.
		if labelLen&0xc0 == 0xc0 {
			return offset + 2, nil
		}

		offset += 1 + labelLen
	}
}
