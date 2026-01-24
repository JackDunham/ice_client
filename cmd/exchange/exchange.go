package main

import (
	"context"
	"flag"
	"fmt"
	"ice-client/link"
	"ice-client/multicast"
	"ice-client/relay"
	"ice-client/session"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type PacketSource string

const (
	LocalNetwork  PacketSource = "local"
	RemoteNetwork PacketSource = "remote"
)

// Ping/pong proxy constants
const (
	PingPongProxyPort = 20809
	PingPongHeader    = "_link_v"

	// Relay message prefixes to distinguish packet types
	RelayPrefixMulticast = 'M' // Multicast discovery packet
	RelayPrefixPingPong  = 'P' // Ping/pong measurement packet
)

// MEP4Mapping tracks original MEP4 endpoints for ping/pong routing
type MEP4Mapping struct {
	OriginalMEP4 string // Original MEP4 "ip:port"
	NodeID       string // NodeID hex from the packet
}

var (
	mep4MappingMutex sync.RWMutex
	// Map from rewritten MEP4Hex to original MEP4 info (for remote peers)
	mep4Mappings = map[string]MEP4Mapping{}

	// Map from NodeID to local peer's MEP4 (for local peers)
	localPeerMEP4Mutex sync.RWMutex
	localPeerMEP4s     = map[string]string{} // nodeID hex -> MEP4 "ip:port"
)

// getLocalIP returns a local IP address suitable for Link communication.
// It prefers non-loopback, non-TURN network addresses.
func getLocalIP() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip non-IPv4 and loopback
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}

			// Prefer 172.28.1.x or 172.28.2.x (host networks) over 172.28.0.x (turn network)
			// This is a heuristic for the test environment
			if ip.To4()[0] == 172 && ip.To4()[1] == 28 {
				if ip.To4()[2] == 1 || ip.To4()[2] == 2 {
					return ip
				}
			}
		}
	}

	// Fallback: return any non-loopback IPv4
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP
			}
		}
	}

	return nil
}

// getInterfaceByIP returns the network interface that has the given IP address.
func getInterfaceByIP(targetIP net.IP) *net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.Equal(targetIP) {
				return &iface
			}
		}
	}

	return nil
}

var (
	mep4MapMutex sync.Mutex
	mep4Map      = map[string]PacketSource{}
)

func GetFromMepMap(mep4 string) (PacketSource, bool) {
	mep4MapMutex.Lock()
	defer mep4MapMutex.Unlock()

	val, ok := mep4Map[mep4]
	return val, ok
}

func AddToMepMap(mep4 string, packetSource PacketSource) error {
	mep4MapMutex.Lock()
	defer mep4MapMutex.Unlock()

	_, ok := mep4Map[mep4]
	if ok {
		return fmt.Errorf("key %s: already set", mep4)
	}
	mep4Map[mep4] = packetSource
	return nil
}

// StoreMEP4Mapping stores the mapping from rewritten MEP4 to original MEP4
func StoreMEP4Mapping(rewrittenMEP4Hex string, originalMEP4 string, nodeID string) {
	mep4MappingMutex.Lock()
	defer mep4MappingMutex.Unlock()
	mep4Mappings[rewrittenMEP4Hex] = MEP4Mapping{
		OriginalMEP4: originalMEP4,
		NodeID:       nodeID,
	}
}

// GetMEP4Mapping retrieves the original MEP4 for a rewritten MEP4
func GetMEP4Mapping(rewrittenMEP4Hex string) (MEP4Mapping, bool) {
	mep4MappingMutex.RLock()
	defer mep4MappingMutex.RUnlock()
	mapping, ok := mep4Mappings[rewrittenMEP4Hex]
	return mapping, ok
}

// GetMEP4MappingByNodeID retrieves the original MEP4 by NodeID
func GetMEP4MappingByNodeID(nodeID string) (MEP4Mapping, bool) {
	mep4MappingMutex.RLock()
	defer mep4MappingMutex.RUnlock()
	for _, mapping := range mep4Mappings {
		if mapping.NodeID == nodeID {
			return mapping, true
		}
	}
	return MEP4Mapping{}, false
}

// StoreLocalPeerMEP4 stores the MEP4 of a local peer for ping/pong forwarding
func StoreLocalPeerMEP4(nodeID string, mep4 string) {
	localPeerMEP4Mutex.Lock()
	defer localPeerMEP4Mutex.Unlock()
	localPeerMEP4s[nodeID] = mep4
}

// GetLocalPeerMEP4 retrieves the MEP4 of a local peer by NodeID
func GetLocalPeerMEP4(nodeID string) (string, bool) {
	localPeerMEP4Mutex.RLock()
	defer localPeerMEP4Mutex.RUnlock()
	mep4, ok := localPeerMEP4s[nodeID]
	return mep4, ok
}

type ExchangeStatus struct {
	Session        *session.LinkSession
	Relay          *relay.TurnRelay
	InCount        uint64
	OutCount       uint64
	PingCount      uint64
	LastInPacket   *link.LinkPacket
	LastOutPacket  *link.LinkPacket
	inCountMutex   sync.Mutex
	outCountMutex  sync.Mutex
	pingCountMutex sync.Mutex
	lastOutMutex   sync.Mutex
	lastInMutex    sync.Mutex
}

func (ex *ExchangeStatus) IncrInCount() {
	ex.inCountMutex.Lock()
	defer ex.inCountMutex.Unlock()
	ex.InCount++
}

func (ex *ExchangeStatus) IncrOutCount() {
	ex.outCountMutex.Lock()
	defer ex.outCountMutex.Unlock()
	ex.OutCount++
}

func (ex *ExchangeStatus) IncrPingCount() {
	ex.pingCountMutex.Lock()
	defer ex.pingCountMutex.Unlock()
	ex.PingCount++
}

func (ex *ExchangeStatus) SetLastIn(p *link.LinkPacket) {
	ex.lastInMutex.Lock()
	defer ex.lastInMutex.Unlock()
	ex.LastInPacket = p
}

func (ex *ExchangeStatus) SetLastOut(p *link.LinkPacket) {
	ex.lastOutMutex.Lock()
	defer ex.lastOutMutex.Unlock()
	ex.LastOutPacket = p
}

func (ex *ExchangeStatus) GetInCount() uint64 {
	ex.inCountMutex.Lock()
	defer ex.inCountMutex.Unlock()
	return ex.InCount
}

func (ex *ExchangeStatus) GetOutCount() uint64 {
	ex.outCountMutex.Lock()
	defer ex.outCountMutex.Unlock()
	return ex.OutCount
}

func (ex *ExchangeStatus) GetPingCount() uint64 {
	ex.pingCountMutex.Lock()
	defer ex.pingCountMutex.Unlock()
	return ex.PingCount
}

func (ex *ExchangeStatus) GetLastIn() *link.LinkPacket {
	ex.lastInMutex.Lock()
	defer ex.lastInMutex.Unlock()
	return ex.LastInPacket
}

func (ex *ExchangeStatus) GetLastOut() *link.LinkPacket {
	ex.lastOutMutex.Lock()
	defer ex.lastOutMutex.Unlock()
	return ex.LastOutPacket
}

// isPingPongPacket checks if the data starts with the _link_v header
func isPingPongPacket(data []byte) bool {
	if len(data) < len(PingPongHeader) {
		return false
	}
	return string(data[:len(PingPongHeader)]) == PingPongHeader
}

// PingPongProxy handles ping/pong measurement traffic between local and remote peers
type PingPongProxy struct {
	conn    *net.UDPConn
	localIP net.IP
	relay   *relay.TurnRelay
	ctx     context.Context

	// Track remote source addresses for routing pong responses
	// Key: local peer MEP4 string, Value: remote source address from wrapper
	pendingMutex  sync.RWMutex
	remoteSources map[string]*net.UDPAddr // localMEP4 -> remote source addr
}

// startPingPongProxy starts a UDP listener for ping/pong measurement traffic
func startPingPongProxy(ctx context.Context, localIP net.IP, relay1 *relay.TurnRelay) (*PingPongProxy, error) {
	addr := &net.UDPAddr{
		IP:   localIP,
		Port: PingPongProxyPort,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to start ping/pong proxy on %s: %w", addr, err)
	}

	log.Printf("Started ping/pong proxy on %s", addr)

	proxy := &PingPongProxy{
		conn:          conn,
		localIP:       localIP,
		relay:         relay1,
		ctx:           ctx,
		remoteSources: make(map[string]*net.UDPAddr),
	}

	// Handle incoming local ping/pong packets
	go proxy.handleLocalTraffic()

	return proxy, nil
}

// handleLocalTraffic handles ping/pong packets from local Link clients
func (p *PingPongProxy) handleLocalTraffic() {
	buf := make([]byte, 1024)
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := p.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			data := buf[:n]
			if !isPingPongPacket(data) {
				continue
			}

			// Check message type: ping (1) or pong (2)
			if len(data) < 9 {
				continue
			}
			msgType := data[8] // After 8-byte "_link_v\x01" header

			if msgType == 1 {
				// PING from local Link client trying to reach a remote peer
				// The MEP4 in the discovery packet told them to send to us (the proxy)
				// We need to forward this ping through the relay to the actual remote peer

				// Wrap the packet for relay:
				// [1 byte: 'P'] [4+2 bytes: local client addr] [N bytes: original packet]
				wrapped := make([]byte, 1+6+len(data))
				wrapped[0] = RelayPrefixPingPong
				copy(wrapped[1:5], remoteAddr.IP.To4())
				wrapped[5] = byte(remoteAddr.Port >> 8)
				wrapped[6] = byte(remoteAddr.Port & 0xff)
				copy(wrapped[7:], data)

				// Send through relay
				p.relay.WriteToRelay(wrapped)
				log.Printf("Forwarded PING from local client %s to relay", remoteAddr)

			} else if msgType == 2 {
				// PONG from local Link peer responding to a ping we forwarded from the relay
				// Look up the remote source address and route the pong back

				localMEP4 := remoteAddr.String()
				p.pendingMutex.RLock()
				remoteSource, ok := p.remoteSources[localMEP4]
				p.pendingMutex.RUnlock()

				if !ok {
					log.Printf("No remote source found for pong from %s, dropping", localMEP4)
					continue
				}

				// Wrap the packet for relay with the REMOTE source address
				// (so the other exchange knows where to deliver the pong)
				wrapped := make([]byte, 1+6+len(data))
				wrapped[0] = RelayPrefixPingPong
				copy(wrapped[1:5], remoteSource.IP.To4())
				wrapped[5] = byte(remoteSource.Port >> 8)
				wrapped[6] = byte(remoteSource.Port & 0xff)
				copy(wrapped[7:], data)

				// Send through relay
				p.relay.WriteToRelay(wrapped)
				log.Printf("Forwarded PONG from local peer %s to relay (dest: %s)", localMEP4, remoteSource)
			}
		}
	}
}

// HandleFromRelay processes ping/pong packets received from the relay
func (p *PingPongProxy) HandleFromRelay(data []byte) {
	if len(data) < 7 {
		return
	}

	// Extract the source info from the wrapper
	// This is the address of the original sender on the remote network
	sourceIP := net.IPv4(data[0], data[1], data[2], data[3])
	sourcePort := int(data[4])<<8 | int(data[5])
	originalPacket := data[6:]
	remoteSource := &net.UDPAddr{IP: sourceIP, Port: sourcePort}

	if !isPingPongPacket(originalPacket) {
		log.Printf("Received relay ping/pong packet with invalid header")
		return
	}

	// Determine if this is a ping (type 1) or pong (type 2)
	if len(originalPacket) < 9 {
		return
	}
	msgType := originalPacket[8] // After 8-byte header

	if msgType == 1 {
		// This is a PING from a remote Link client
		// We need to forward it to the appropriate local peer
		// The local peer's MEP4 should be stored in localPeerMEP4s

		// Forward to all known local peers and store the remote source for pong routing
		localPeerMEP4Mutex.RLock()
		for nodeID, mep4Str := range localPeerMEP4s {
			// Parse the MEP4 string to get IP:port
			parts := strings.Split(mep4Str, ":")
			if len(parts) != 2 {
				continue
			}
			ip := net.ParseIP(parts[0])
			port, err := strconv.Atoi(parts[1])
			if err != nil || ip == nil {
				continue
			}

			destAddr := &net.UDPAddr{IP: ip, Port: port}

			// Store the remote source address so we can route pong responses back
			p.pendingMutex.Lock()
			p.remoteSources[mep4Str] = remoteSource
			p.pendingMutex.Unlock()

			_, err = p.conn.WriteToUDP(originalPacket, destAddr)
			if err != nil {
				log.Printf("Failed to forward ping to local peer %s (%s): %v", nodeID, mep4Str, err)
			} else {
				log.Printf("Forwarded PING from relay (%s) to local peer %s at %s", remoteSource, nodeID, mep4Str)
			}
		}
		localPeerMEP4Mutex.RUnlock()

	} else if msgType == 2 {
		// This is a PONG from a remote peer (responding to our local client's ping)
		// The wrapper contains the address of the local client to deliver to
		_, err := p.conn.WriteToUDP(originalPacket, remoteSource)
		if err != nil {
			log.Printf("Failed to forward PONG to local client %s: %v", remoteSource, err)
		} else {
			log.Printf("Forwarded PONG from relay to local client %s", remoteSource)
		}
	}
}

func printStatus(status *ExchangeStatus) {
	// Clear the screen once at the start.
	fmt.Print("\033[2J")
	// Move the cursor to the top left (row 1, col 1)
	fmt.Print("\033[H")

	var statusBuilder strings.Builder
	statusBuilder.WriteString(fmt.Sprintf("SessionID: %s\n", status.Session.SessionID))
	statusBuilder.WriteString("Session Hosts:\n")
	for idx, host := range status.Session.GetSessionHosts() {
		statusBuilder.WriteString(fmt.Sprintf("\t%d: %s\n", idx, host))
	}
	statusBuilder.WriteString(fmt.Sprintf("Public TURN Address: %s\n", status.Relay.ThisHost))
	lastIn := status.GetLastIn()
	if lastIn != nil {
		statusBuilder.WriteString(fmt.Sprintf("Last in mpe4: %s\n", lastIn.MEP4))
	}
	statusBuilder.WriteString(fmt.Sprintf("In count: %d\n", status.GetInCount()))
	lastOut := status.GetLastOut()
	if lastOut != nil {
		statusBuilder.WriteString(fmt.Sprintf("Last out mpe4: %s\n", lastOut.MEP4))
	}
	statusBuilder.WriteString(fmt.Sprintf("Out count: %d\n", status.GetOutCount()))
	statusBuilder.WriteString(fmt.Sprintf("Ping count: %d\n", status.GetPingCount()))
	statusStr := statusBuilder.String()
	os.WriteFile("status", []byte(statusStr), 0o644)
	fmt.Print(statusStr)
}

// Exchange Link packets between local and remote network(s)
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up a channel to receive OS signals.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	// Launch a goroutine to wait for a quit signal.
	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v. Cancelling context...", sig)
		cancel()
	}()

	// Get session-ID from "session" flag or SESSION_ID env var
	sessionID := flag.String("session", "", "session-ID to join, or blank, to create a new session")
	// Parse the flags.
	flag.Parse()

	// Environment variable overrides flag
	if envSessionID := os.Getenv("SESSION_ID"); envSessionID != "" {
		*sessionID = envSessionID
		fmt.Printf("Using session ID from environment: %s\n", envSessionID)
	}

	/////////////////////
	/////////////////////
	// Setup TURN relay
	/////////////////////
	/////////////////////
	fromRelay := make(chan []byte, 1024)
	relay1, err := relay.StartTurnClient(fromRelay, ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Join or create link session
	linkSession1 := &session.LinkSession{}
	if sessionID == nil {
		linkSession1.JoinOrCreateSession("", relay1.ThisHost)
	} else {
		linkSession1.JoinOrCreateSession(*sessionID, relay1.ThisHost)
	}
	os.WriteFile("current_session_id", []byte(linkSession1.SessionID+"\n"), 0o644)

	// IMMEDIATELY initialize relay with current session hosts (don't wait for ticker)
	{
		hosts := []string{}
		for _, host := range linkSession1.GetSessionHosts() {
			if host == relay1.ThisHost {
				continue
			}
			hosts = append(hosts, host)
		}
		if len(hosts) > 0 {
			log.Printf("Immediately setting %d session hosts", len(hosts))
			relay1.SetSessionHosts(hosts)
		}
	}

	/////////////////////
	/////////////////////
	// Keep the link session + relay updated
	/////////////////////
	/////////////////////
	go func(linkSession1 *session.LinkSession, relay1 *relay.TurnRelay, ctx context.Context) {
		// Fast initial polling (every 2 seconds for first 30 seconds)
		// Then switch to slower interval (15 seconds)
		fastTicker := time.NewTicker(2 * time.Second)
		slowTicker := time.NewTicker(15 * time.Second)
		initialPhase := time.After(30 * time.Second)
		useFastTicker := true

		updateHosts := func() {
			linkSession1.UpdateSessionInfo()
			hosts := []string{}
			for _, host := range linkSession1.GetSessionHosts() {
				if host == relay1.ThisHost {
					continue
				}
				hosts = append(hosts, host)
			}
			relay1.SetSessionHosts(hosts)
		}

		for {
			select {
			case <-initialPhase:
				useFastTicker = false
				fastTicker.Stop()
			case <-fastTicker.C:
				if useFastTicker {
					updateHosts()
				}
			case <-slowTicker.C:
				if !useFastTicker {
					updateHosts()
				}
			case <-ctx.Done():
				fastTicker.Stop()
				slowTicker.Stop()
				return
			}
		}
	}(linkSession1, relay1, ctx)

	/////////////////////
	/////////////////////
	// SETUP multicast listening
	/////////////////////
	/////////////////////
	// Use ListenConfig to bind with reuse options.
	lc := multicast.CreateListenConfig()

	// Bind one UDP socket on all interfaces (0.0.0.0) at port 20808.
	pc, err := lc.ListenPacket(ctx, "udp4", multicast.LinkPort)
	if err != nil {
		log.Fatalf("Failed to bind UDP socket: %v", err)
	}
	defer pc.Close()

	// Wrap the connection with ipv4.PacketConn to manage multicast.
	p, multicastIP, err := multicast.GetMulticastPacketConnection(pc, multicast.UDP4MulticastAddress)
	if err != nil {
		log.Fatalf("Error getting multicast connection: %s", err.Error())
	}

	exchangeStatus := &ExchangeStatus{
		Session: linkSession1,
		Relay:   relay1,
	}

	// Get local IP for rewriting MEP4 in relayed packets
	// This should be the IP on the local network (not the TURN network)
	localIP := getLocalIP()
	if localIP == nil {
		log.Printf("Warning: Could not determine local IP, using 127.0.0.1 for MEP4 rewrite")
		localIP = net.IPv4(127, 0, 0, 1)
	} else {
		log.Printf("Using local IP %s for MEP4 rewrite", localIP.String())
	}

	// Start the ping/pong proxy for measurement traffic
	pingPongProxy, err := startPingPongProxy(ctx, localIP, relay1)
	if err != nil {
		log.Printf("Warning: Failed to start ping/pong proxy: %v", err)
	}

	// Set the multicast interface for OUTGOING packets to match localIP's interface
	// This ensures multicast goes out the right interface (host network, not TURN network)
	localIface := getInterfaceByIP(localIP)
	if localIface != nil {
		if err := p.SetMulticastInterface(localIface); err != nil {
			log.Printf("Warning: Failed to set multicast interface to %s: %v", localIface.Name, err)
		} else {
			log.Printf("Set multicast interface to %s for outgoing packets", localIface.Name)
		}
	} else {
		log.Printf("Warning: Could not find interface for IP %s", localIP.String())
	}

	// Join the multicast group on all eligible interfaces.
	multicast.JoinMulticastGroups(p, multicastIP)
	// Listen for link-packets on local network interface(s) + retransmit to relay
	rxChan := make(chan multicast.PacketAndMep4, 1024)
	go multicast.ListenForLinkPackets(ctx, p, multicastIP, multicast.LinkHeader, rxChan)
	go func(ctx context.Context, rxChan chan multicast.PacketAndMep4, relay1 *relay.TurnRelay, exchangeStatus *ExchangeStatus) {
		ticker := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ticker.C:
				relay1.WriteToRelay([]byte("PING"))
			case linkPacket := <-rxChan:
				// if this packet was already recorded as coming from "outside", don't relay it
				val, ok := GetFromMepMap(linkPacket.MEP4)
				if val == RemoteNetwork {
					continue
				}
				if !ok {
					// first time we've seen this packet-source. Record it.
					AddToMepMap(linkPacket.MEP4, LocalNetwork)

					// Parse the packet to store local peer's MEP4 for ping/pong routing
					parsedPacket, err := link.ParseLinkPacket(linkPacket.Data)
					if err == nil && parsedPacket.MEP4 != nil {
						nodeID := fmt.Sprintf("%x", parsedPacket.Header.ClientID)
						StoreLocalPeerMEP4(nodeID, parsedPacket.MEP4.String())
						log.Printf("Stored local peer MEP4: nodeID=%s, MEP4=%s", nodeID, parsedPacket.MEP4.String())
					}
				}
				relay1.WriteToRelay(linkPacket.Data)
				exchangeStatus.IncrOutCount()
			case <-ctx.Done():
				return
			}
		}
	}(ctx, rxChan, relay1, exchangeStatus)

	/////////////////////
	/////////////////////
	// listen for messages from "outside", send to this relay endpoint
	/////////////////////
	/////////////////////
	go func(ctx context.Context, relay1 *relay.TurnRelay, exchangeStatus *ExchangeStatus, pingPongProxy *PingPongProxy) {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-relay1.FromRelay:
				// Handle PING keepalive messages
				if string(msg) == "PING" {
					exchangeStatus.IncrPingCount()
					continue
				}

				// Check if this is a ping/pong packet (prefixed with 'P')
				if len(msg) > 0 && msg[0] == RelayPrefixPingPong {
					if pingPongProxy != nil {
						pingPongProxy.HandleFromRelay(msg[1:]) // Skip the prefix
					}
					continue
				}

				// Validate it's a Link packet (minimum header size)
				if !link.IsValidLinkPacket(msg) {
					continue
				}

				linkPacket, err := link.ParseLinkPacket(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse incoming relay packet: %s\n", err.Error())
					continue
				}

				// Skip disconnect packets - they have no MEP4
				if linkPacket.IsDisconnect {
					continue
				}

				// Need MEP4 for deduplication
				if linkPacket.MEP4Hex == "" {
					continue
				}

				// If we've already seen this source in the local network, skip it.
				val, ok := GetFromMepMap(linkPacket.MEP4Hex)
				if val == LocalNetwork {
					continue
				} else if !ok {
					// First time we've seen this packet-source. Record it.
					AddToMepMap(linkPacket.MEP4Hex, RemoteNetwork)
				}

				// Store the mapping from original MEP4 so we can route ping/pong traffic
				originalMEP4 := ""
				if linkPacket.MEP4 != nil {
					originalMEP4 = linkPacket.MEP4.String()
				}
				nodeID := fmt.Sprintf("%x", linkPacket.Header.ClientID)

				// Rewrite MEP4 (IP and port) to point to our ping/pong proxy.
				// When local Link clients try to do unicast ping/pong measurement,
				// they'll send to localIP:20809 where our proxy is listening.
				// The proxy will relay ping/pong traffic through TURN.
				rewrittenMsg, err := link.RewriteMEP4(msg, localIP, PingPongProxyPort)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to rewrite MEP4: %s\n", err.Error())
					// Fall back to sending original packet
					rewrittenMsg = msg
				}

				// IMPORTANT: Add the rewritten MEP4Hex to the map to prevent feedback loop.
				// When we broadcast this packet, we'll receive it on multicast too.
				// If we don't add the rewritten MEP4Hex, we'd relay our own broadcast.
				rewrittenPacket, err := link.ParseLinkPacket(rewrittenMsg)
				if err == nil && rewrittenPacket.MEP4Hex != "" {
					AddToMepMap(rewrittenPacket.MEP4Hex, RemoteNetwork)
					// Store the mapping so ping/pong proxy knows where to forward
					StoreMEP4Mapping(rewrittenPacket.MEP4Hex, originalMEP4, nodeID)
				}

				multicast.SendLinkPacket(p, multicastIP, rewrittenMsg)
				exchangeStatus.SetLastIn(linkPacket)
				exchangeStatus.IncrInCount()
			}
		}
	}(ctx, relay1, exchangeStatus, pingPongProxy)

	go func(ctx context.Context, exchangeStatus *ExchangeStatus) {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printStatus(exchangeStatus)
			}
		}
	}(ctx, exchangeStatus)

	fmt.Println("Waiting for termination signal")
	<-ctx.Done()
}
