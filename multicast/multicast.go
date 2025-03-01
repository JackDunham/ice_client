package multicast

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"ice-client/link"
	"log"
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

func ListenForLinkPackets(p *ipv4.PacketConn, multicastIP net.IP, linkHeader string) {
	log.Printf("Listening for Ableton Link packets on %s (bound on 0.0.0.0:20808)", UDP4MulticastAddress)
	buf := make([]byte, MaxDatagramSize)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %s", err.Error())
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

		linkPacket, err := link.ParseLinkPacket(data)
		if err != nil {
			continue
		}
		fmt.Printf("%s\n", linkPacket.String())

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
