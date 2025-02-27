package main

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"ice-client/link"
	"log"
	"math"
	"net"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
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

func JoinMulticastGroups(p *ipv4.PacketConn, groupIP net.IP) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error listing interfaces: %v", err)
		return
	}
	for _, iface := range ifaces {
		// Consider only interfaces that are up, support multicast, and have an IPv4 address.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, a := range addrs {
			if strings.Contains(a.String(), ".") {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}

		// Attempt to join the multicast group on this interface.
		group := &net.UDPAddr{IP: groupIP}
		if err := p.JoinGroup(&iface, group); err != nil {
			log.Printf("Interface %s: failed to join multicast group %s: %v", iface.Name, groupIP, err)
		} else {
			log.Printf("Interface %s: successfully joined multicast group %s", iface.Name, groupIP)
		}
	}
}

func CreateListenConfig() (lc net.ListenConfig) {
	lc = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					controlErr = err
					return
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil {
					controlErr = err
					return
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}
	return
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Suppose data is your entire Ableton Link packet
func ExtractTempo(tempoBytes []byte) float32 {
	// Convert the 4 bytes from big-endian to a uint32.
	bits := binary.BigEndian.Uint32(tempoBytes)
	// Convert the bits to a float32.
	tempo := math.Float32frombits(bits)
	return tempo
}

func ExtractFrameTimestamp(packet []byte) uint64 {
	if len(packet) < 32 {
		log.Fatalf("Packet too short: expected at least 32 bytes, got %d", len(packet))
	}
	// Extract bytes 24 to 31 (8 bytes) as the frame timestamp.
	return binary.BigEndian.Uint64(packet[56:64])
}

func ListenForLinkPackets(p *ipv4.PacketConn, multicastIP net.IP, linkHeader string) {
	log.Printf("Listening for Ableton Link packets on %s (bound on 0.0.0.0:20808)", UDP4MulticastAddress)
	buf := make([]byte, MaxDatagramSize)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}
		data := buf[:n]

		// Optionally, check that the destination address in the control message matches the multicast group.
		if cm != nil && !cm.Dst.Equal(multicastIP) {
			continue
		}

		// For debugging, log the first 32 bytes.
		log.Printf("Received packet from %v: % x", src, data[:Min(n, 32)])

		// Filter for packets that begin with the expected Link header.
		if len(data) < len(linkHeader) || string(data[:len(linkHeader)]) != linkHeader {
			continue
		}

		// Ensure the packet is long enough.
		if n < 64 {
			log.Printf("Packet too short from %v", src)
			continue
		}

		link.DeterminePacketType(data)
		// Check that bytes 52-56 equal "sess".
		sessHeader := string(data[52:56])
		if sessHeader != "sess" {
			log.Printf("Missing session header from %v", src)
			continue
		}

		// Extract session ID (bytes 56-64) and sender ID (last 4 bytes).
		sessID := hex.EncodeToString(data[56:64])
		senderID := fmt.Sprintf("%x", data[n-4:n])
		tempoBytes := data[24:28]
		tempo := ExtractTempo(tempoBytes)
		timestamp := ExtractFrameTimestamp(data)
		fmt.Printf("Extracted frame timestamp: %d\n", timestamp)

		// Compute an MD5 hash for debugging.
		hash := md5.Sum(data)
		encodedHash := hex.EncodeToString(hash[:])

		// Determine the interface on which the packet was received.
		ifaceName := "unknown"
		if cm != nil && cm.IfIndex != 0 {
			if iface, err := net.InterfaceByIndex(cm.IfIndex); err == nil {
				ifaceName = iface.Name
			}
		}

		fmt.Printf("Interface %s: Received Link packet from %v:\n", ifaceName, src)
		fmt.Printf("  Packet size: %d bytes\n", n)
		fmt.Printf("  MD5 hash: %s\n", encodedHash)
		fmt.Printf("  Session header: %s\n", sessHeader)
		fmt.Printf("  Session ID: %s\n", sessID)
		fmt.Printf("  Sender ID: %s\n", senderID)
		fmt.Printf("  Tempo: %f\n", tempo)
	}
}

func GetMulticastPacketConnection(pc net.PacketConn, linkMulticastAddress string) (*ipv4.PacketConn, net.IP, error) {
	p := ipv4.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		return nil, nil, fmt.Errorf("Error setting control message: %w", err)
	}

	// Optionally, set the underlying connection's read buffer.
	if udpConn, ok := pc.(*net.UDPConn); ok {
		if err := udpConn.SetReadBuffer(MaxDatagramSize); err != nil {
			return nil, nil, fmt.Errorf("failed to set read buffer: %w", err)
		}
	}

	// Determine the multicast IP.
	multicastIPStr := strings.Split(linkMulticastAddress, ":")[0]
	multicastIP := net.ParseIP(multicastIPStr)
	if multicastIP == nil {
		return nil, nil, fmt.Errorf("invalid multicast IP: %s", multicastIPStr)
	}
	return p, multicastIP, nil
}

func main() {
	ctx := context.Background()

	// Use ListenConfig to bind with reuse options.
	lc := CreateListenConfig()

	// Bind one UDP socket on all interfaces (0.0.0.0) at port 20808.
	pc, err := lc.ListenPacket(ctx, "udp4", LinkPort)
	if err != nil {
		log.Fatalf("Failed to bind UDP socket: %v", err)
	}
	defer pc.Close()

	// Wrap the connection with ipv4.PacketConn to manage multicast.
	p, multicastIP, err := GetMulticastPacketConnection(pc, UDP4MulticastAddress)
	if err != nil {
		log.Fatalf("Error getting multicast connection: %s", err.Error())
	}

	// Join the multicast group on all eligible interfaces.
	JoinMulticastGroups(p, multicastIP)
	go ListenForLinkPackets(p, multicastIP, LinkHeader)

	pc2, err := lc.ListenPacket(ctx, "udp4", DiscoveryPort)
	if err != nil {
		log.Fatalf("Failed to bind UDP socket: %v", err)
	}
	defer pc.Close()
	// Wrap the connection with ipv4.PacketConn to manage multicast.
	p2, discoveryIP, err := GetMulticastPacketConnection(pc2, DiscoverPacketAddress)
	if err != nil {
		log.Fatalf("Error getting multicast connection: %s", err.Error())
	}

	// Join the multicast group on all eligible interfaces.
	JoinMulticastGroups(p2, discoveryIP)
	go ListenForLinkPackets(p, discoveryIP, DiscoveryHeader)
}

// new
type LinkPacketHeader struct {
	Magic       [7]byte // e.g., "_asdp_v"
	Version     uint8   // e.g., 0x01
	PacketType  uint8   // e.g., 0x01 for state packet
	Flags       uint8   // e.g., 0x05
	Reserved    uint16  // expected to be 0x0000 (for validation)
	HeaderExtra uint32  // additional header data
}

type TLV struct {
	Key    string // For a standard TLV, this is 8 bytes; for "sess" TLV, it's 4 bytes ("sess")
	Length uint32 // For a "sess" TLV, this will always be 8.
	Value  []byte // For a "sess" TLV, only the first 4 bytes are used as the session ID.
}

// LinkPacket holds the parsed header and two sets of TLVs.
// PreSessTLVs contains all TLVs found before the "sess" TLV,
// and PostSessTLVs contains all TLVs that follow.
type LinkPacket struct {
	Header       LinkPacketHeader
	PreSessTLVs  []TLV
	SessionID    uint32 // Extracted from the "sess" TLV, if present.
	PostSessTLVs []TLV
}

/////////////////////////////////////
// TODO(jack): use this! (below)
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////
/////////////////////////////////////

// ParseLinkPacket parses a raw Link packet from data.
// It expects a 16-byte header, then one or more TLVs.
// When a TLV with key "sess" is encountered (which is exactly 12 bytes long),
// the parser extracts the session ID from its value and splits TLVs accordingly.
func ParseLinkPacket(data []byte) (*LinkPacket, error) {
	const headerSize = 16
	if len(data) < headerSize {
		return nil, errors.New("data too short for header")
	}

	var header LinkPacketHeader
	copy(header.Magic[:], data[0:7])
	header.Version = data[7]
	header.PacketType = data[8]
	header.Flags = data[9]
	header.Reserved = binary.BigEndian.Uint16(data[10:12])
	header.HeaderExtra = binary.BigEndian.Uint32(data[12:16])

	packet := &LinkPacket{
		Header:       header,
		PreSessTLVs:  make([]TLV, 0),
		PostSessTLVs: make([]TLV, 0),
	}

	offset := headerSize
	sessionFound := false

	for offset < len(data) {
		// Check if the next 4 bytes equal "sess".
		if len(data)-offset >= 4 && string(data[offset:offset+4]) == "sess" {
			// Session TLV must be exactly 12 bytes.
			if len(data)-offset < 12 {
				return nil, errors.New("data too short for session TLV")
			}
			// Read the key ("sess")
			key := string(data[offset : offset+4])
			fmt.Print(key)
			// Read the length (should be 0x00000008)
			length := binary.BigEndian.Uint32(data[offset+4 : offset+8])
			if length != 8 {
				return nil, errors.New("invalid session TLV length")
			}
			// Read the session ID (first 4 bytes of the value)
			sessionID := binary.BigEndian.Uint32(data[offset+8 : offset+12])
			packet.SessionID = sessionID

			// Skip over this TLV.
			offset += 12
			sessionFound = true
		} else {
			// Parse a standard TLV: 8-byte key, 4-byte length, then value.
			if len(data)-offset < 12 {
				return nil, errors.New("data too short for TLV header")
			}
			key := string(data[offset : offset+8])
			offset += 8

			tlvLength := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

			if len(data)-offset < int(tlvLength) {
				return nil, errors.New("data too short for TLV value")
			}
			value := make([]byte, tlvLength)
			copy(value, data[offset:offset+int(tlvLength)])
			offset += int(tlvLength)

			tlv := TLV{Key: key, Length: tlvLength, Value: value}
			if !sessionFound {
				packet.PreSessTLVs = append(packet.PreSessTLVs, tlv)
			} else {
				packet.PostSessTLVs = append(packet.PostSessTLVs, tlv)
			}
		}
	}

	return packet, nil
}

func exampleUse() {
	// Sample packet built from:
	// - A 16-byte header.
	// - A pre-session TLV (standard TLV).
	// - The session TLV ("sess" + 4-byte length field + 4-byte session ID).
	// - A post-session TLV (standard TLV).

	// Build the header (16 bytes).
	header := []byte{
		0x5f, 0x61, 0x73, 0x64, 0x70, 0x5f, 0x76, // Magic: "_asdp_v"
		0x01,       // Version
		0x01,       // PacketType
		0x05,       // Flags
		0x00, 0x00, // Reserved
		0x12, 0x34, 0x56, 0x78, // HeaderExtra: 0x12345678
	}

	// Pre-session TLV: standard TLV.
	preTLV := []byte{
		// Key: "DAD7tmln" (8 bytes)
		0x44, 0x41, 0x44, 0x37, 0x74, 0x6d, 0x6c, 0x6e,
		// Length: 0x00 00 00 18 (24 bytes)
		0x00, 0x00, 0x00, 0x18,
	}
	// Append 24 bytes of dummy data.
	for i := 0; i < 24; i++ {
		preTLV = append(preTLV, byte(i))
	}

	// Session TLV: exactly 12 bytes.
	sessionTLV := []byte{
		's', 'e', 's', 's', // Key "sess" (4 bytes)
		0x00, 0x00, 0x00, 0x08, // Length field (4 bytes, value 8)
		0xAA, 0xBB, 0xCC, 0xDD, // Session ID (4 bytes)
	}

	// Post-session TLV: standard TLV.
	postTLV := []byte{
		// Key: "DAD7stst" (8 bytes)
		0x44, 0x41, 0x44, 0x37, 0x73, 0x74, 0x73, 0x74,
		// Length: 0x00 00 00 11 (17 bytes)
		0x00, 0x00, 0x00, 0x11,
	}
	// Append 17 bytes of dummy data.
	for i := 0; i < 17; i++ {
		postTLV = append(postTLV, byte(i+100))
	}

	// Assemble the full packet.
	packetData := append(header, preTLV...)
	packetData = append(packetData, sessionTLV...)
	packetData = append(packetData, postTLV...)

	packet, err := ParseLinkPacket(packetData)
	if err != nil {
		fmt.Println("Error parsing packet:", err)
		return
	}

	// Print the parsed header.
	fmt.Println("Parsed Link Packet Header:")
	fmt.Printf("  Magic:       %s\n", string(packet.Header.Magic[:]))
	fmt.Printf("  Version:     %d\n", packet.Header.Version)
	fmt.Printf("  PacketType:  %d\n", packet.Header.PacketType)
	fmt.Printf("  Flags:       %d\n", packet.Header.Flags)
	fmt.Printf("  Reserved:    %d\n", packet.Header.Reserved)
	fmt.Printf("  HeaderExtra: 0x%x\n", packet.Header.HeaderExtra)

	// Print Pre-session TLVs.
	fmt.Println("\nPreSess TLVs:")
	for _, tlv := range packet.PreSessTLVs {
		fmt.Printf("  Key: %s, Length: %d, Value: %x\n", tlv.Key, tlv.Length, tlv.Value)
	}

	// Print the extracted session ID.
	fmt.Printf("\nSession ID: 0x%x\n", packet.SessionID)

	// Print Post-session TLVs.
	fmt.Println("\nPostSess TLVs:")
	for _, tlv := range packet.PostSessTLVs {
		fmt.Printf("  Key: %s, Length: %d, Value: %x\n", tlv.Key, tlv.Length, tlv.Value)
	}
}
