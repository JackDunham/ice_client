package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
)

const (
	UDP4MulticastAddress = "224.76.78.75:20808"
	linkHeader           = "_asdp_v"
	maxDatagramSize      = 8192
)

func joinMulticastGroups(p *ipv4.PacketConn, groupIP net.IP) {
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

func main() {
	ctx := context.Background()

	// Use ListenConfig to bind with reuse options.
	lc := net.ListenConfig{
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

	// Bind one UDP socket on all interfaces (0.0.0.0) at port 20808.
	pc, err := lc.ListenPacket(ctx, "udp4", ":20808")
	if err != nil {
		log.Fatalf("Failed to bind UDP socket: %v", err)
	}
	defer pc.Close()

	// Wrap the connection with ipv4.PacketConn to manage multicast.
	p := ipv4.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		log.Printf("Error setting control message: %v", err)
	}

	// Optionally, set the underlying connection's read buffer.
	if udpConn, ok := pc.(*net.UDPConn); ok {
		if err := udpConn.SetReadBuffer(maxDatagramSize); err != nil {
			log.Printf("Failed to set read buffer: %v", err)
		}
	}

	// Determine the multicast IP.
	multicastIPStr := strings.Split(UDP4MulticastAddress, ":")[0]
	multicastIP := net.ParseIP(multicastIPStr)
	if multicastIP == nil {
		log.Fatalf("Invalid multicast IP: %s", multicastIPStr)
	}

	// Join the multicast group on all eligible interfaces.
	joinMulticastGroups(p, multicastIP)

	log.Printf("Listening for Ableton Link packets on %s (bound on 0.0.0.0:20808)", UDP4MulticastAddress)
	buf := make([]byte, maxDatagramSize)
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
		log.Printf("Received packet from %v: % x", src, data[:min(n, 32)])

		// Filter for packets that begin with the expected Link header.
		if len(data) < len(linkHeader) || string(data[:len(linkHeader)]) != linkHeader {
			continue
		}

		// Ensure the packet is long enough.
		if n < 64 {
			log.Printf("Packet too short from %v", src)
			continue
		}

		// Check that bytes 52-56 equal "sess".
		sessHeader := string(data[52:56])
		if sessHeader != "sess" {
			log.Printf("Missing session header from %v", src)
			continue
		}

		// Extract session ID (bytes 56-64) and sender ID (last 4 bytes).
		sessID := hex.EncodeToString(data[56:64])
		senderID := fmt.Sprintf("%x", data[n-4:n])

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
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
