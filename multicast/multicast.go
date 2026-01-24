package multicast

import (
	"context"
	"fmt"
	"ice-client/link"
	"log"
	"net"
	"os"
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
			fmt.Fprintf(os.Stderr, "Interface %s: failed to join multicast group %s: %v", iface.Name, groupIP, err)
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

type PacketAndMep4 struct {
	Data  []byte
	MEP4  string
	Iface string
}

func ListenForLinkPackets(ctx context.Context, p *ipv4.PacketConn, multicastIP net.IP, linkHeader string, rxChan chan PacketAndMep4) {
	buf := make([]byte, MaxDatagramSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, cm, src, err := p.ReadFrom(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Read error (src=%+v): %s", src, err.Error())
				continue
			}
			data := buf[:n]

			// Check that the destination address in the control message matches the multicast group.
			if cm != nil && !cm.Dst.Equal(multicastIP) {
				continue
			}

			// Filter for packets that begin with the expected Link header.
			if len(data) < len(linkHeader) || string(data[:len(linkHeader)]) != linkHeader {
				continue
			}

			// Minimum valid packet is header (20 bytes)
			minSize := 20
			if len(data) < minSize {
				continue
			}

			linkPacket, err := link.ParseLinkPacket(data)
			if err != nil {
				continue
			}

			// Determine the interface on which the packet was received.
			ifaceName := "unknown"
			if cm != nil && cm.IfIndex != 0 {
				if iface, err := net.InterfaceByIndex(cm.IfIndex); err == nil {
					ifaceName = iface.Name
				}
			}
			rxChan <- PacketAndMep4{Data: data, MEP4: linkPacket.MEP4Hex, Iface: ifaceName}
		}
	}
}

func GetMulticastPacketConnection(pc net.PacketConn, linkMulticastAddress string) (*ipv4.PacketConn, net.IP, error) {
	p := ipv4.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		return nil, nil, fmt.Errorf("Error setting control message: %w", err)
	}

	// Set the underlying connection's read buffer.
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

// SendLinkPacket sends a valid link-packet packet to the multicast group.
// NOTE: This uses SetMulticastInterface which must be called before this function.
// For explicit interface control, use SendLinkPacketOnInterface instead.
func SendLinkPacket(p *ipv4.PacketConn, multicastIP net.IP, linkMsg []byte) error {
	destAddr, err := net.ResolveUDPAddr("udp4", UDP4MulticastAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %v", err)
	}

	n, err := p.WriteTo(linkMsg, nil, destAddr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}
	if n != len(linkMsg) {
		return fmt.Errorf("sent %d bytes, expected %d", n, len(linkMsg))
	}
	return nil
}

// SendLinkPacketOnInterface sends a link packet to the multicast group via a specific interface.
// This explicitly sets the outgoing interface in the control message.
func SendLinkPacketOnInterface(p *ipv4.PacketConn, iface *net.Interface, linkMsg []byte) error {
	destAddr, err := net.ResolveUDPAddr("udp4", UDP4MulticastAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %v", err)
	}

	// Create control message to specify the outgoing interface
	var cm *ipv4.ControlMessage
	if iface != nil {
		cm = &ipv4.ControlMessage{IfIndex: iface.Index}
	}

	n, err := p.WriteTo(linkMsg, cm, destAddr)
	if err != nil {
		return fmt.Errorf("failed to send packet on interface %s: %v", iface.Name, err)
	}
	if n != len(linkMsg) {
		return fmt.Errorf("sent %d bytes, expected %d", n, len(linkMsg))
	}
	return nil
}
