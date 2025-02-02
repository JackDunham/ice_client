package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	multicastAddress = "224.76.78.75:20808"
	maxDatagramSize  = 8192
)

func main() {
	// Create a context with a generous timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Set up a ListenConfig with control options to enable reuse.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				// Set socket options to allow port sharing.
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

	// Bind the socket to the wildcard address so that it can share the port.
	pc, err := lc.ListenPacket(ctx, "udp4", ":20808")
	if err != nil {
		log.Fatalf("Failed to bind wildcard socket: %v", err)
	}
	defer pc.Close()
	log.Printf("Successfully bound to wildcard address on port 20808")

	// Wrap the PacketConn with ipv4.PacketConn to gain access to control messages.
	p := ipv4.NewPacketConn(pc)
	if err := p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		log.Fatalf("Error setting control message: %v", err)
	}

	// Optionally, set the underlying UDP connection's read buffer.
	if udpConn, ok := pc.(*net.UDPConn); ok {
		if err := udpConn.SetReadBuffer(maxDatagramSize); err != nil {
			log.Printf("Failed to set read buffer: %v", err)
		}
	}

	// Resolve the multicast group address.
	mcastAddr, err := net.ResolveUDPAddr("udp4", multicastAddress)
	if err != nil {
		log.Fatalf("Error resolving multicast address %s: %v", multicastAddress, err)
	}

	// Join the multicast group on all eligible interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Error listing interfaces: %v", err)
	}
	for _, iface := range ifaces {
		// Only join on interfaces that are UP and support multicast.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		// Verify the interface has an IPv4 address.
		foundIPv4 := false
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if strings.Contains(addr.String(), ".") {
					foundIPv4 = true
					break
				}
			}
		}
		if !foundIPv4 {
			continue
		}
		if err := p.JoinGroup(&iface, mcastAddr); err != nil {
			log.Printf("Interface %s: failed to join multicast group %s: %v", iface.Name, mcastAddr.IP, err)
		} else {
			log.Printf("Interface %s: joined multicast group %s", iface.Name, mcastAddr.IP)
		}
	}

	log.Printf("Wildcard socket bound on :20808, listening for multicast packets on %s", multicastAddress)
	buf := make([]byte, maxDatagramSize)
	for {
		// Read from the socket.
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}
		data := buf[:n]
		log.Printf("Received %d bytes from %v", n, src)
		if cm != nil {
			log.Printf("Control message: Dst=%v, IfIndex=%v", cm.Dst, cm.IfIndex)
			// Attempt to resolve the interface name.
			if cm.IfIndex != 0 {
				if iface, err := net.InterfaceByIndex(cm.IfIndex); err == nil {
					log.Printf("Packet received on interface: %s", iface.Name)
				} else {
					log.Printf("Error resolving interface index %v: %v", cm.IfIndex, err)
				}
			}
		}
		// For debugging, simply print the raw data.
		fmt.Printf("Data: %s\n", string(data))
		// (Optionally, you could add filtering here, e.g., check for a specific header.)
	}
}
