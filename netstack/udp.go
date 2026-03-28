package netstack

import (
	"encoding/binary"
	"net"
)

const udpHeaderLen = 8

// UDPPacket represents a parsed UDP packet.
type UDPPacket struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

// ParseUDPPacket parses raw bytes into a UDPPacket.
func ParseUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < udpHeaderLen {
		return nil, ErrPacketTooShort
	}

	pkt := &UDPPacket{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}

	payloadLen := int(pkt.Length) - udpHeaderLen
	if payloadLen > 0 && len(data) >= udpHeaderLen+payloadLen {
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, data[udpHeaderLen:udpHeaderLen+payloadLen])
	}

	return pkt, nil
}

// BuildUDPPacket constructs a raw UDP packet with correct checksum.
func BuildUDPPacket(srcPort, dstPort uint16, payload []byte,
	srcIP, dstIP net.IP) []byte {

	totalLen := udpHeaderLen + len(payload)
	pkt := make([]byte, totalLen)

	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(totalLen))
	// pkt[6:8] = checksum, computed below.

	copy(pkt[udpHeaderLen:], payload)

	// UDP checksum with pseudo-header.
	csum := udpChecksum(srcIP, dstIP, pkt)
	if csum == 0 {
		csum = 0xffff // RFC 768: 0 means no checksum, use 0xffff instead.
	}
	binary.BigEndian.PutUint16(pkt[6:8], csum)

	return pkt
}

// udpChecksum computes the UDP checksum including the pseudo-header.
func udpChecksum(srcIP, dstIP net.IP, udpData []byte) uint16 {
	sum := pseudoHeaderChecksum(srcIP, dstIP, ProtoUDP, uint16(len(udpData)))

	n := len(udpData)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpData[i : i+2]))
	}
	if n%2 != 0 {
		sum += uint32(udpData[n-1]) << 8
	}

	return checksumFinalize(sum)
}
