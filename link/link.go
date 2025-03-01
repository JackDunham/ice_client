package link

import (
	"encoding/binary"
	"errors"
	"fmt"
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
)

type LinkPacketHeader struct {
	Magic       [7]byte // e.g., "_asdp_v"
	Version     uint8   // e.g., 0x01
	PacketType  uint8   // e.g., 0x01 for state packet
	Flags       uint8   // e.g., 0x05
	Reserved    uint16  // expected to be 0x0000 (for validation)
	HeaderExtra uint32  // additional header data
	Checksum    uint32
}

type TLV struct {
	Key    string // For a standard TLV, this is 8 bytes; for "sess" TLV, it's 4 bytes ("sess")
	Length uint32 // For a "sess" TLV, this will always be 8.
	Value  []byte // For a "sess" TLV, only the first 4 bytes are used as the session ID.
}

// Timeline encapsulates the timeline data from a "tmln" TLV.
type Timeline struct {
	Beat  float64 // Current beat position.
	Tempo float64 // Tempo in beats per minute.
	Phase float64 // Phase offset for synchronization.
}

func (timeline *Timeline) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("\n\tbeat: %f\n", timeline.Beat))
	builder.WriteString(fmt.Sprintf("\ttempo: %f\n", timeline.Tempo))
	builder.WriteString(fmt.Sprintf("\tphase: %f\n", timeline.Phase))
	return builder.String()
}

// ParseTimeline converts a 24-byte slice (the value from a "tmln" TLV)
// into a Timeline struct. It returns an error if the slice is not 24 bytes.
func ParseTimeline(data []byte) (Timeline, error) {
	if len(data) != 24 {
		return Timeline{}, errors.New("invalid timeline data length; expected 24 bytes")
	}
	beatFixed := binary.BigEndian.Uint64(data[0:8])
	tempoFixed := binary.BigEndian.Uint64(data[8:16])
	phaseFixed := binary.BigEndian.Uint64(data[16:24])

	// Convert from 32.32 fixed-point to float64.
	const scale = 1 << 32
	beat := float64(beatFixed) / float64(scale)
	tempo := float64(tempoFixed) / float64(scale)
	phase := float64(phaseFixed) / float64(scale)

	return Timeline{
		Beat:  beat,
		Tempo: tempo,
		Phase: phase,
	}, nil
}

// LinkPacket holds the parsed header and two sets of TLVs.
// PreSessTLVs contains all TLVs found before the "sess" TLV,
// and PostSessTLVs contains all TLVs that follow.
type LinkPacket struct {
	Header    LinkPacketHeader
	TLVs      []*TLV
	SessionID uint32 // Extracted from the "sess" TLV, if present.
}

func (lp *LinkPacket) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("magic: %s\n", string(lp.Header.Magic[:])))
	builder.WriteString(fmt.Sprintf("version: %x\n", lp.Header.Version))
	builder.WriteString(fmt.Sprintf("type: %x\n", lp.Header.PacketType))
	builder.WriteString(fmt.Sprintf("flags: %x\n", lp.Header.Flags))
	builder.WriteString(fmt.Sprintf("reserved: %x\n", lp.Header.Reserved))
	builder.WriteString(fmt.Sprintf("extra: %x\n", lp.Header.HeaderExtra))
	builder.WriteString(fmt.Sprintf("checksum: %d\n", lp.Header.Checksum))

	for _, tlv := range lp.TLVs {
		key := tlv.Key
		if key == "mep4" {
			builder.WriteString(fmt.Sprintf("key: %s (length=%d): %d %x\n", key, tlv.Length, tlv.Value[0:4], tlv.Value[4:]))
		} else if key == "tmln" {
			timeline, err := ParseTimeline(tlv.Value)
			if err == nil {
				builder.WriteString(fmt.Sprintf("key: %s (length=%d): %s\n", key, tlv.Length, timeline.String()))
			}
		} else {
			builder.WriteString(fmt.Sprintf("key: %s (length=%d): %x\n", key, tlv.Length, tlv.Value))
		}
	}
	return builder.String()
}

var tlvRegex = regexp.MustCompile(`^[a-z0-9]{4}$`)

// ParseLinkPacket parses a raw Link packet from data.
// It expects a 16-byte header, then one or more TLVs.
// When a TLV with key "sess" is encountered (which is exactly 12 bytes long),
// the parser extracts the session ID from its value and splits TLVs accordingly.
func ParseLinkPacket(data []byte) (*LinkPacket, error) {
	const headerSize = 20
	if len(data) < headerSize {
		return nil, errors.New("data too short for header")
	}
	//tmln
	//sess
	//stst
	//mep4
	var header LinkPacketHeader
	copy(header.Magic[:], data[0:7])
	header.Version = data[7]
	header.PacketType = data[8]
	header.Flags = data[9]
	header.Reserved = binary.BigEndian.Uint16(data[10:12])
	header.HeaderExtra = binary.BigEndian.Uint32(data[12:16])
	header.Checksum = binary.BigEndian.Uint32(data[16:20])

	packet := &LinkPacket{
		Header: header,
		TLVs:   []*TLV{},
	}

	offset := headerSize // don't know what the

	for offset < len(data) {
		// Check if we can read in a key + length
		if offset+8 > len(data) {
			continue
		}
		key := string(data[offset : offset+4])
		offset += 4
		if !tlvRegex.MatchString(key) {
			break
		}

		tlvLength := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if offset+int(tlvLength) > len(data) {
			return nil, errors.New("data too short for TLV value")
		}
		value := make([]byte, tlvLength)
		copy(value, data[offset:offset+int(tlvLength)])
		offset += int(tlvLength)

		tlv := TLV{Key: key, Length: tlvLength, Value: value}
		packet.TLVs = append(packet.TLVs, &tlv)
	}

	return packet, nil
}
