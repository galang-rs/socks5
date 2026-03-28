package netstack

import (
	"encoding/binary"
	"net"
)

// TCP flags.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

// TCP connection states.
const (
	StateClosed = iota
	StateSynSent
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateClosing
	StateCloseWait
	StateLastAck
	StateTimeWait
)

const tcpHeaderLen = 20

// TCPSegment represents a parsed TCP segment.
type TCPSegment struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

// ParseTCPSegment parses raw bytes into a TCPSegment.
func ParseTCPSegment(data []byte) (*TCPSegment, error) {
	if len(data) < tcpHeaderLen {
		return nil, ErrPacketTooShort
	}

	dataOffset := (data[12] >> 4) * 4
	if int(dataOffset) > len(data) {
		return nil, ErrPacketTooShort
	}

	seg := &TCPSegment{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: dataOffset,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}

	if dataOffset > tcpHeaderLen {
		seg.Options = make([]byte, dataOffset-tcpHeaderLen)
		copy(seg.Options, data[tcpHeaderLen:dataOffset])
	}

	if int(dataOffset) < len(data) {
		seg.Payload = make([]byte, len(data)-int(dataOffset))
		copy(seg.Payload, data[dataOffset:])
	}

	return seg, nil
}

// BuildTCPSegment constructs a raw TCP segment with correct checksum.
// srcIP/dstIP are needed for the pseudo-header checksum.
func BuildTCPSegment(srcPort, dstPort uint16, seq, ack uint32,
	flags uint8, window uint16, payload []byte,
	srcIP, dstIP net.IP) []byte {

	headerLen := uint8(tcpHeaderLen)
	totalLen := int(headerLen) + len(payload)
	seg := make([]byte, totalLen)

	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = (headerLen / 4) << 4 // Data offset
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], window)
	// seg[16:18] = checksum, computed below.
	// seg[18:20] = urgent pointer, 0.

	copy(seg[headerLen:], payload)

	// TCP checksum with pseudo-header.
	csum := tcpChecksum(srcIP, dstIP, seg)
	binary.BigEndian.PutUint16(seg[16:18], csum)

	return seg
}

// tcpChecksum computes the TCP checksum including the pseudo-header.
func tcpChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	sum := pseudoHeaderChecksum(srcIP, dstIP, ProtoTCP, uint16(len(tcpData)))

	n := len(tcpData)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if n%2 != 0 {
		sum += uint32(tcpData[n-1]) << 8
	}

	return checksumFinalize(sum)
}

// FlagsString returns a human-readable representation of TCP flags.
func FlagsString(flags uint8) string {
	s := ""
	if flags&FlagSYN != 0 {
		s += "SYN "
	}
	if flags&FlagACK != 0 {
		s += "ACK "
	}
	if flags&FlagFIN != 0 {
		s += "FIN "
	}
	if flags&FlagRST != 0 {
		s += "RST "
	}
	if flags&FlagPSH != 0 {
		s += "PSH "
	}
	if s == "" {
		return "none"
	}
	return s[:len(s)-1]
}
