package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"ice-client/multicast"
	"ice-client/relay"
	"ice-client/session"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

func StartLinkRelay(fromLocalNet chan []byte) (*LinkRelay, error) {
	ctx := context.Background()
	killChan := make(chan bool)
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

	// Join the multicast group on all eligible interfaces.
	multicast.JoinMulticastGroups(p, multicastIP)
	// TODO(jack):
	go multicast.ListenForLinkPacketsUsingChannels(p, multicastIP, multicast.LinkHeader, fromLocalNet, killChan)

	//  TEST that we can actually SEND a link-packet
	//multicast.SendLinkPacket(p, multicastIP, multicast.LinkHeader, []byte("DERPDERPDERP"))

	return &LinkRelay{FromLocalNetwork: fromLocalNet, KillChan: killChan, PacketConn: p, MulticastIP: multicastIP}, nil
}

type LinkRelay struct {
	FromLocalNetwork chan []byte
	KillChan         chan bool
	PacketConn       *ipv4.PacketConn
	MulticastIP      net.IP
}

func (lr *LinkRelay) SendToLocalNetwork(msg []byte) error {
	hash := md5.Sum(msg)
	encodedHash := hex.EncodeToString(hash[:])
	fmt.Print(encodedHash)

	err := multicast.SendLinkPacket(lr.PacketConn, lr.MulticastIP, multicast.LinkHeader, msg)
	if err != nil {
		return fmt.Errorf("error sending link packet: %w", err)
	}
	return nil
}

func (lr *LinkRelay) Shutdown() error {
	close(lr.KillChan)
	return nil
}

// Exchange Link packets between local and remote network(s)
func main() {
	// Ensure we can terminate politely:
	// Create a channel to receive OS signals.
	signals := make(chan os.Signal, 1)
	// We'll also use a channel to know when to exit.
	done := make(chan bool, 1)

	// Tell signal.Notify which signals to relay.
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	// Start a goroutine to handle incoming signals.
	go func() {
		sig := <-signals
		fmt.Printf("Received signal: %v\n", sig)
		// Do any cleanup here if necessary.
		close(done)
	}()

	// Get session-ID from "session" flag (if present)
	sessionID := flag.String("session", "", "session-ID to join, or blank, to create a new session")
	// Parse the flags.
	flag.Parse()

	fromRelay := make(chan []byte, 1024)
	fromLocalNet := make(chan []byte, 1024)

	relay1, err := relay.StartTurnClient(fromRelay)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	linkSession1 := &session.LinkSession{}
	if sessionID == nil {
		linkSession1.JoinOrCreateSession("", relay1.ThisHost)
	} else {
		linkSession1.JoinOrCreateSession(*sessionID, relay1.ThisHost)
	}
	linkSession1.JoinOrCreateSession("", relay1.ThisHost)

	// Keep the link session + relay updated
	go func(linkSession1 *session.LinkSession, relay1 *relay.TurnRelay, done chan bool) {
		ticker := time.NewTicker(15 * time.Second)
		for {
			select {
			case <-ticker.C:
				linkSession1.UpdateSessionInfo()
				relay1.SetSessionHosts(linkSession1.Hosts)
			case <-done:
				return
			}
		}
	}(linkSession1, relay1, done)

	linkRelay, err := StartLinkRelay(fromLocalNet)
	if err != nil {
		log.Fatal(err)
	}

	// listen for message from the "outside", to this relay endpoint
	go func(relay1 *relay.TurnRelay, done chan bool, linkRelay *LinkRelay) {
		for {
			select {
			case msg := <-relay1.FromRelay: // TODO(jack): could use the local variable
				fmt.Printf("received: %s", string(msg))
				linkRelay.SendToLocalNetwork(msg)
			case <-done:
				return
			}
		}
	}(relay1, done, linkRelay)

	// listen for LINK messages, on UDP, and relay to other hosts in the link-session
	go func(relay1 *relay.TurnRelay, done chan bool, linkRelay *LinkRelay) {
		for {
			select {
			case msg := <-linkRelay.FromLocalNetwork: // TODO(jack): could use the local variable
				fmt.Printf("captured: %s", string(msg))
				relay1.WriteToRelay(msg)
			case <-done:
				return
			}
		}
	}(relay1, done, linkRelay)

	fmt.Println("Waiting for termination signal")
	<-done
	fmt.Println("Exiting gracefully")
	relay1.Shutdown()

}
