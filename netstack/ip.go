// Package netstack provides a lightweight virtual TCP/IP stack
// for routing connections through TUN devices.
//
// This package implements just enough of the IPv4/IPv6/TCP/UDP/DNS
// protocols to support SOCKS5 CONNECT and UDP ASSOCIATE operations
// through a VPN tunnel's TUN device.
package netstack

import (
	"encoding/binary"
	"errors"
	"net"
)

// IP protocol numbers.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

const (
	ipVersion4  = 4
	ipVersion6  = 6
	ipHeaderLen = 20 // IPv4 fixed header length
	ip6HeaderLen = 40 // IPv6 fixed header length
	defaultTTL  = 64
)

// Errors.
var (
	ErrPacketTooShort   = errors.New("netstack: packet too short")
	ErrInvalidIPVersion = errors.New("netstack: unsupported IP version")
)

// IPPacket represents a parsed IPv4 or IPv6 packet.
type IPPacket struct {
	Version  uint8
	IHL      uint8  // IPv4 only
	TotalLen uint16
	ID       uint16 // IPv4 only
	Flags    uint8  // IPv4 only
	TTL      uint8  // TTL (v4) or Hop Limit (v6)
	Protocol uint8  // Protocol (v4) or Next Header (v6)
	Checksum uint16 // IPv4 only
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

// IsIPv6 returns true if this packet is IPv6.
func (p *IPPacket) IsIPv6() bool {
	return p.Version == ipVersion6
}

// ParseIPPacket parses raw bytes into an IPPacket (supports IPv4 and IPv6).
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 1 {
		return nil, ErrPacketTooShort
	}

	version := data[0] >> 4
	switch version {
	case ipVersion4:
		return parseIPv4Packet(data)
	case ipVersion6:
		return parseIPv6Packet(data)
	default:
		return nil, ErrInvalidIPVersion
	}
}

// parseIPv4Packet parses an IPv4 packet.
func parseIPv4Packet(data []byte) (*IPPacket, error) {
	if len(data) < ipHeaderLen {
		return nil, ErrPacketTooShort
	}

	ihl := data[0] & 0x0f
	headerLen := int(ihl) * 4
	if len(data) < headerLen {
		return nil, ErrPacketTooShort
	}

	totalLen := binary.BigEndian.Uint16(data[2:4])
	if int(totalLen) > len(data) {
		totalLen = uint16(len(data))
	}

	pkt := &IPPacket{
		Version:  ipVersion4,
		IHL:      ihl,
		TotalLen: totalLen,
		ID:       binary.BigEndian.Uint16(data[4:6]),
		Flags:    data[6] >> 5,
		TTL:      data[8],
		Protocol: data[9],
		Checksum: binary.BigEndian.Uint16(data[10:12]),
	}

	// Copy IPs (don't alias the input slice).
	pkt.SrcIP = make(net.IP, 4)
	copy(pkt.SrcIP, data[12:16])
	pkt.DstIP = make(net.IP, 4)
	copy(pkt.DstIP, data[16:20])

	if int(totalLen) > headerLen {
		pkt.Payload = make([]byte, int(totalLen)-headerLen)
		copy(pkt.Payload, data[headerLen:totalLen])
	}

	return pkt, nil
}

// parseIPv6Packet parses an IPv6 packet.
// IPv6 header format (40 bytes):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Version| Traffic Class |           Flow Label                  |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|         Payload Length        |  Next Header  |   Hop Limit   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Source Address (128 bits)                   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                  Destination Address (128 bits)                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func parseIPv6Packet(data []byte) (*IPPacket, error) {
	if len(data) < ip6HeaderLen {
		return nil, ErrPacketTooShort
	}

	payloadLen := binary.BigEndian.Uint16(data[4:6])
	nextHeader := data[6]
	hopLimit := data[7]

	pkt := &IPPacket{
		Version:  ipVersion6,
		TotalLen: uint16(ip6HeaderLen) + payloadLen,
		TTL:      hopLimit,
		Protocol: nextHeader,
	}

	// Copy 128-bit addresses.
	pkt.SrcIP = make(net.IP, 16)
	copy(pkt.SrcIP, data[8:24])
	pkt.DstIP = make(net.IP, 16)
	copy(pkt.DstIP, data[24:40])

	// Payload.
	end := ip6HeaderLen + int(payloadLen)
	if end > len(data) {
		end = len(data)
	}
	if end > ip6HeaderLen {
		pkt.Payload = make([]byte, end-ip6HeaderLen)
		copy(pkt.Payload, data[ip6HeaderLen:end])
	}

	return pkt, nil
}

// BuildIPPacket constructs a raw IP packet (IPv4 or IPv6) ready to write
// to a TUN device. The IP version is auto-detected from the source IP length.
func BuildIPPacket(srcIP, dstIP net.IP, proto uint8, payload []byte, id uint16) []byte {
	// Use IPv6 if either address is not representable as IPv4.
	if srcIP.To4() == nil || dstIP.To4() == nil {
		return buildIPv6Packet(srcIP, dstIP, proto, payload)
	}
	return buildIPv4Packet(srcIP.To4(), dstIP.To4(), proto, payload, id)
}

// buildIPv4Packet constructs a raw IPv4 packet.
func buildIPv4Packet(srcIP, dstIP net.IP, proto uint8, payload []byte, id uint16) []byte {
	totalLen := ipHeaderLen + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = (ipVersion4 << 4) | (ipHeaderLen / 4) // Version + IHL
	// pkt[1] = 0 — TOS/DSCP
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't Fragment
	pkt[8] = defaultTTL
	pkt[9] = proto
	// pkt[10:12] = checksum, computed below.

	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	copy(pkt[ipHeaderLen:], payload)

	// IP header checksum.
	binary.BigEndian.PutUint16(pkt[10:12], checksumBytes(pkt[:ipHeaderLen]))

	return pkt
}

// buildIPv6Packet constructs a raw IPv6 packet.
func buildIPv6Packet(srcIP, dstIP net.IP, proto uint8, payload []byte) []byte {
	totalLen := ip6HeaderLen + len(payload)
	pkt := make([]byte, totalLen)

	// Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
	pkt[0] = (ipVersion6 << 4) // Version = 6, TC = 0
	// pkt[1], pkt[2], pkt[3] = 0 (TC low bits + Flow Label)

	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload))) // Payload Length
	pkt[6] = proto                                              // Next Header
	pkt[7] = defaultTTL                                         // Hop Limit

	// Source and Destination addresses (128-bit each).
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// Payload.
	copy(pkt[ip6HeaderLen:], payload)

	// IPv6 has no header checksum.
	return pkt
}

// checksumBytes computes the ones-complement checksum (RFC 1071).
func checksumBytes(data []byte) uint16 {
	var sum uint32
	n := len(data)

	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if n%2 != 0 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoHeaderChecksum computes the TCP/UDP pseudo-header checksum contribution.
// Supports both IPv4 (4-byte) and IPv6 (16-byte) addresses.
func pseudoHeaderChecksum(srcIP, dstIP net.IP, proto uint8, length uint16) uint32 {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()

	if src4 != nil && dst4 != nil {
		// IPv4 pseudo-header.
		var sum uint32
		sum += uint32(src4[0])<<8 | uint32(src4[1])
		sum += uint32(src4[2])<<8 | uint32(src4[3])
		sum += uint32(dst4[0])<<8 | uint32(dst4[1])
		sum += uint32(dst4[2])<<8 | uint32(dst4[3])
		sum += uint32(proto)
		sum += uint32(length)
		return sum
	}

	// IPv6 pseudo-header (RFC 2460 §8.1).
	// +------+------+------+------+
	// |         Source Address      | (128 bits)
	// +------+------+------+------+
	// |      Destination Address    | (128 bits)
	// +------+------+------+------+
	// |   Upper-Layer Packet Length  | (32 bits)
	// +------+------+------+------+
	// |  zero  |    Next Header     | (32 bits)
	// +------+------+------+------+
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(src16[i])<<8 | uint32(src16[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst16[i])<<8 | uint32(dst16[i+1])
	}
	sum += uint32(length) // upper-layer packet length (fits in 16 bits for our use)
	sum += uint32(proto)
	return sum
}

// checksumFinalize folds a running checksum sum into the final 16-bit value.
func checksumFinalize(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// IPHeaderLen returns the IP header length for the given IP version.
func IPHeaderLen(isIPv6 bool) int {
	if isIPv6 {
		return ip6HeaderLen
	}
	return ipHeaderLen
}
