// Package netstack provides a lightweight virtual TCP/IP stack
// for routing connections through TUN devices.
//
// This package implements just enough of the IPv4/TCP/UDP/DNS
// protocols to support SOCKS5 CONNECT (TCP) operations through
// a VPN tunnel's TUN device.
package netstack

import (
	"encoding/binary"
	"errors"
	"net"
)

// IP protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

const (
	ipVersion4  = 4
	ipHeaderLen = 20
	defaultTTL  = 64
)

// Errors.
var (
	ErrPacketTooShort   = errors.New("netstack: packet too short")
	ErrInvalidIPVersion = errors.New("netstack: not IPv4")
)

// IPPacket represents a parsed IPv4 packet.
type IPPacket struct {
	Version  uint8
	IHL      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint8
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

// ParseIPPacket parses raw bytes into an IPPacket.
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < ipHeaderLen {
		return nil, ErrPacketTooShort
	}

	version := data[0] >> 4
	if version != ipVersion4 {
		return nil, ErrInvalidIPVersion
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
		Version:  version,
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

// BuildIPPacket constructs a raw IPv4 packet ready to write to a TUN device.
func BuildIPPacket(srcIP, dstIP net.IP, proto uint8, payload []byte, id uint16) []byte {
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
func pseudoHeaderChecksum(srcIP, dstIP net.IP, proto uint8, length uint16) uint32 {
	src := srcIP.To4()
	dst := dstIP.To4()
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// checksumFinalize folds a running checksum sum into the final 16-bit value.
func checksumFinalize(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
