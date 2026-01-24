package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	UDP4MulticastAddress  = "224.76.78.75:20808"
	DiscoverPacketAddress = "224.76.78.75:20909"
	LinkHeader            = "_asdp_v"
	DiscoveryHeader       = "ablsd_v"
	MaxDatagramSize       = 8192
	LinkPort              = ":20808"
	DiscoveryPort         = ":20909"

	// Packet types
	PacketTypeTimeline   = 0x01
	PacketTypeDisconnect = 0x03

	// Header size
	HeaderSize = 20

	// TLV keys
	TLVKeyTimeline    = "tmln"
	TLVKeySession     = "sess"
	TLVKeyMEP4        = "mep4"
	TLVKeyStartStop   = "stst"
	TLVKeyPrevSession = "pses"
)

// LinkPacketHeader represents the fixed 20-byte header of Link packets.
// Based on reverse engineering from westhom/AbletonLinkProtocol:
//
//	Bytes 0-6:   Magic ("_asdp_v")
//	Byte 7:      Version (0x01)
//	Byte 8:      Packet Type (0x01=timeline, 0x03=disconnect)
//	Byte 9:      Flags (0x05 for timeline)
//	Bytes 10-11: Reserved (0x0000)
//	Bytes 12-19: Client/Session ID (8 bytes)
type LinkPacketHeader struct {
	Magic      [7]byte // "_asdp_v"
	Version    uint8   // Protocol version (0x01)
	PacketType uint8   // 0x01=timeline, 0x03=disconnect
	Flags      uint8   // Usually 0x05 for timeline packets
	Reserved   uint16  // Expected to be 0x0000
	ClientID   [8]byte // Unique client identifier
}

// TLV represents a Type-Length-Value field in Link packets.
// Format: 4-byte key (ASCII), 4-byte length (big-endian), variable value
type TLV struct {
	Key    string
	Length uint32
	Value  []byte
}

// Timeline encapsulates the timeline data from a "tmln" TLV.
// All values are 64-bit fixed-point (32.32) in big-endian.
type Timeline struct {
	Beat     float64 // Current beat position
	Tempo    float64 // Tempo in beats per minute
	Phase    float64 // Phase offset for synchronization
	RawBeat  uint64  // Raw fixed-point value
	RawTempo uint64  // Raw fixed-point value
	RawPhase uint64  // Raw fixed-point value
}

func (timeline *Timeline) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("\n\tbeat: %f (raw: %016x)\n", timeline.Beat, timeline.RawBeat))
	builder.WriteString(fmt.Sprintf("\ttempo: %f (raw: %016x)\n", timeline.Tempo, timeline.RawTempo))
	builder.WriteString(fmt.Sprintf("\tphase: %f (raw: %016x)\n", timeline.Phase, timeline.RawPhase))
	return builder.String()
}

// ParseTimeline converts a 24-byte slice (the value from a "tmln" TLV)
// into a Timeline struct. Values are 32.32 fixed-point, big-endian.
func ParseTimeline(data []byte) (Timeline, error) {
	if len(data) != 24 {
		return Timeline{}, fmt.Errorf("invalid timeline data length; expected 24 bytes, got %d", len(data))
	}

	beatFixed := binary.BigEndian.Uint64(data[0:8])
	tempoFixed := binary.BigEndian.Uint64(data[8:16])
	phaseFixed := binary.BigEndian.Uint64(data[16:24])

	// Convert from 32.32 fixed-point to float64
	const scale = float64(1 << 32)
	beat := float64(beatFixed) / scale
	tempo := float64(tempoFixed) / scale
	phase := float64(phaseFixed) / scale

	return Timeline{
		Beat:     beat,
		Tempo:    tempo,
		Phase:    phase,
		RawBeat:  beatFixed,
		RawTempo: tempoFixed,
		RawPhase: phaseFixed,
	}, nil
}

// MEP4 represents the mep4 TLV which contains the sender's IP address.
// Format: 4-byte IP address + 2-byte port (big-endian)
type MEP4 struct {
	IP   net.IP
	Port uint16
}

func (m *MEP4) String() string {
	return fmt.Sprintf("%s:%d", m.IP.String(), m.Port)
}

// ParseMEP4 parses the mep4 TLV value (6 bytes: 4 IP + 2 port)
func ParseMEP4(data []byte) (*MEP4, error) {
	if len(data) != 6 {
		return nil, fmt.Errorf("invalid mep4 data length; expected 6 bytes, got %d", len(data))
	}
	return &MEP4{
		IP:   net.IPv4(data[0], data[1], data[2], data[3]),
		Port: binary.BigEndian.Uint16(data[4:6]),
	}, nil
}

// LinkPacket holds the parsed header and TLVs from a Link packet.
type LinkPacket struct {
	Header       LinkPacketHeader
	TLVs         []*TLV
	SessionID    uint64    // Extracted from the "sess" TLV, if present
	MEP4         *MEP4     // Parsed mep4 TLV
	MEP4Hex      string    // Hex representation of MEP4 for deduplication
	Timeline     *Timeline // Parsed timeline, if present
	IsDisconnect bool      // True if this is a disconnect packet
	Raw          []byte    // Original raw packet bytes
}

func (lp *LinkPacket) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("=== Link Packet ===\n"))
	builder.WriteString(fmt.Sprintf("Magic: %s\n", string(lp.Header.Magic[:])))
	builder.WriteString(fmt.Sprintf("Version: 0x%02x\n", lp.Header.Version))
	builder.WriteString(fmt.Sprintf("Type: 0x%02x (%s)\n", lp.Header.PacketType, packetTypeName(lp.Header.PacketType)))
	builder.WriteString(fmt.Sprintf("Flags: 0x%02x\n", lp.Header.Flags))
	builder.WriteString(fmt.Sprintf("Reserved: 0x%04x\n", lp.Header.Reserved))
	builder.WriteString(fmt.Sprintf("ClientID: %x\n", lp.Header.ClientID))

	for _, tlv := range lp.TLVs {
		key := tlv.Key
		switch key {
		case TLVKeyMEP4:
			if lp.MEP4 != nil {
				builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): %s\n", key, tlv.Length, lp.MEP4.String()))
			} else {
				builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): %x\n", key, tlv.Length, tlv.Value))
			}
		case TLVKeyTimeline:
			if lp.Timeline != nil {
				builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): %s\n", key, tlv.Length, lp.Timeline.String()))
			} else {
				builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): %x\n", key, tlv.Length, tlv.Value))
			}
		case TLVKeySession:
			builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): session_id=%x\n", key, tlv.Length, lp.SessionID))
		default:
			builder.WriteString(fmt.Sprintf("TLV [%s] (len=%d): %x\n", key, tlv.Length, tlv.Value))
		}
	}
	return builder.String()
}

func packetTypeName(t uint8) string {
	switch t {
	case PacketTypeTimeline:
		return "timeline"
	case PacketTypeDisconnect:
		return "disconnect"
	default:
		return "unknown"
	}
}

var tlvRegex = regexp.MustCompile(`^[a-z0-9]{4}$`)

// ParseLinkPacket parses a raw Link packet from data.
// It expects a 20-byte header, then zero or more TLVs.
func ParseLinkPacket(data []byte) (*LinkPacket, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("data too short for header")
	}

	var header LinkPacketHeader
	copy(header.Magic[:], data[0:7])
	header.Version = data[7]
	header.PacketType = data[8]
	header.Flags = data[9]
	header.Reserved = binary.BigEndian.Uint16(data[10:12])
	copy(header.ClientID[:], data[12:20])

	// Validate magic
	if string(header.Magic[:]) != LinkHeader {
		return nil, fmt.Errorf("invalid magic: expected %q, got %q", LinkHeader, string(header.Magic[:]))
	}

	packet := &LinkPacket{
		Header:       header,
		TLVs:         []*TLV{},
		IsDisconnect: header.PacketType == PacketTypeDisconnect,
		Raw:          make([]byte, len(data)),
	}
	copy(packet.Raw, data)

	// Disconnect packets have no TLVs after the header
	if packet.IsDisconnect {
		return packet, nil
	}

	offset := HeaderSize

	for offset < len(data) {
		// Need at least 8 bytes for key + length
		if offset+8 > len(data) {
			break
		}

		key := string(data[offset : offset+4])
		offset += 4

		// Validate key format
		if !tlvRegex.MatchString(key) {
			break
		}

		tlvLength := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(tlvLength) > len(data) {
			return nil, fmt.Errorf("TLV %q: data too short for value (need %d bytes, have %d)", key, tlvLength, len(data)-offset)
		}

		value := make([]byte, tlvLength)
		copy(value, data[offset:offset+int(tlvLength)])
		offset += int(tlvLength)

		tlv := &TLV{Key: key, Length: tlvLength, Value: value}
		packet.TLVs = append(packet.TLVs, tlv)

		// Parse known TLVs
		switch key {
		case TLVKeyMEP4:
			if mep4, err := ParseMEP4(value); err == nil {
				packet.MEP4 = mep4
				packet.MEP4Hex = fmt.Sprintf("%x", value)
			}
		case TLVKeyTimeline:
			if timeline, err := ParseTimeline(value); err == nil {
				packet.Timeline = &timeline
			}
		case TLVKeySession:
			if len(value) >= 8 {
				packet.SessionID = binary.BigEndian.Uint64(value[0:8])
			}
		}
	}

	return packet, nil
}

// GetMEP4Offset returns the byte offset where the MEP4 IP address starts in the packet.
// Returns -1 if not found. This is useful for rewriting the source IP.
func (lp *LinkPacket) GetMEP4Offset() int {
	offset := HeaderSize
	for _, tlv := range lp.TLVs {
		if tlv.Key == TLVKeyMEP4 {
			// Key (4) + Length (4) + Value offset to IP (0)
			return offset + 8
		}
		// Move past this TLV: key(4) + length(4) + value
		offset += 8 + int(tlv.Length)
	}
	return -1
}

// RewriteMEP4IP rewrites the MEP4 IP address in the raw packet bytes.
// This is necessary when relaying packets to avoid subnet mismatches.
// Returns the modified packet bytes.
func RewriteMEP4IP(data []byte, newIP net.IP) ([]byte, error) {
	packet, err := ParseLinkPacket(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packet for rewrite: %w", err)
	}

	offset := packet.GetMEP4Offset()
	if offset == -1 {
		return nil, errors.New("mep4 TLV not found in packet")
	}

	ip4 := newIP.To4()
	if ip4 == nil {
		return nil, errors.New("invalid IPv4 address")
	}

	// Make a copy to avoid modifying the original
	result := make([]byte, len(data))
	copy(result, data)

	// Rewrite the IP address (first 4 bytes of mep4 value)
	copy(result[offset:offset+4], ip4)

	return result, nil
}

// RewriteMEP4 rewrites both IP and port in the MEP4 TLV.
// This is necessary when relaying packets so that the MEP4 matches
// the UDP source address of the relayed packet.
func RewriteMEP4(data []byte, newIP net.IP, newPort uint16) ([]byte, error) {
	packet, err := ParseLinkPacket(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse packet for rewrite: %w", err)
	}

	offset := packet.GetMEP4Offset()
	if offset == -1 {
		return nil, errors.New("mep4 TLV not found in packet")
	}

	ip4 := newIP.To4()
	if ip4 == nil {
		return nil, errors.New("invalid IPv4 address")
	}

	// Make a copy to avoid modifying the original
	result := make([]byte, len(data))
	copy(result, data)

	// Rewrite the IP address (first 4 bytes of mep4 value)
	copy(result[offset:offset+4], ip4)

	// Rewrite the port (next 2 bytes, big-endian)
	binary.BigEndian.PutUint16(result[offset+4:offset+6], newPort)

	return result, nil
}

// IsValidLinkPacket performs quick validation on raw data.
func IsValidLinkPacket(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}
	return string(data[0:7]) == LinkHeader
}

// MinPacketSize returns the minimum expected packet size for a given type.
// Timeline packets are typically 82-107+ bytes, disconnect packets are 20 bytes.
func MinPacketSize(packetType uint8) int {
	switch packetType {
	case PacketTypeDisconnect:
		return HeaderSize
	case PacketTypeTimeline:
		// Header + at least one TLV (tmln: 4+4+24 = 32)
		return HeaderSize + 32
	default:
		return HeaderSize
	}
}
