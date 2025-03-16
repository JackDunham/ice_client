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
	"os"
	"os/signal"
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

	// Get session-ID from "session" flag (if present)
	sessionID := flag.String("session", "", "session-ID to join, or blank, to create a new session")
	// Parse the flags.
	flag.Parse()

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
	//fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	// Join or create link session
	linkSession1 := &session.LinkSession{}
	if sessionID == nil {
		linkSession1.JoinOrCreateSession("", relay1.ThisHost)
	} else {
		linkSession1.JoinOrCreateSession(*sessionID, relay1.ThisHost)
	}
	os.WriteFile("current_session_id", []byte(linkSession1.SessionID+"\n"), 0o644)
	/////////////////////
	/////////////////////
	// Keep the link session + relay updated
	/////////////////////
	/////////////////////
	go func(linkSession1 *session.LinkSession, relay1 *relay.TurnRelay, ctx context.Context) {
		ticker := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-ticker.C:
				linkSession1.UpdateSessionInfo()
				hosts := []string{}
				for _, host := range linkSession1.Hosts {
					if host == relay1.ThisHost {
						continue
					}
					hosts = append(hosts, host)
				}
				relay1.SetSessionHosts(hosts)
			case <-ctx.Done():
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
				//fmt.Printf("LinkPacket %+v", linkPacket)
				// if this packet was already recorded as coming from "outside", don't relay it
				val, ok := GetFromMepMap(linkPacket.MEP4)
				if val == RemoteNetwork {
					continue
				}
				if !ok {
					// first time we've seen this packet-source. Record it.
					AddToMepMap(linkPacket.MEP4, LocalNetwork)
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
	go func(ctx context.Context, relay1 *relay.TurnRelay, exchangeStatus *ExchangeStatus) {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-relay1.FromRelay: // TODO(jack): could use the local variable
				//fmt.Printf("received: %s", string(msg))
				if string(msg) == "PING" {
					exchangeStatus.IncrPingCount()
					//fmt.Printf("received PING")
					continue
				} else if len(msg) != 107 {
					continue
				}
				linkPacket, err := link.ParseLinkPacket(msg)
				if err != nil {
					continue
				}
				// if we've already seen this source in the local network, skip it.
				val, ok := GetFromMepMap(linkPacket.MEP4)
				if val == LocalNetwork {
					continue
				} else if !ok {
					// first time we've seen this packet-source. Record it.
					AddToMepMap(linkPacket.MEP4, RemoteNetwork)
				}
				// change source IP to be localhost, in case there's a subnet mismatch w/ local-network
				msg[101] = 127
				msg[102] = 0
				msg[103] = 0
				msg[104] = 1
				multicast.SendLinkPacket(p, multicastIP, msg)
				exchangeStatus.SetLastIn(linkPacket)
				exchangeStatus.IncrInCount()
			}
		}
	}(ctx, relay1, exchangeStatus)

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
