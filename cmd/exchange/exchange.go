package main

import (
	"flag"
	"fmt"
	"ice-client/relay"
	"ice-client/session"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

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

	fromChan := make(chan []byte, 1024)
	toChan := make(chan []byte, 1024)

	relay1, err := relay.StartTurnClient(fromChan, toChan)
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

	// listen for message from the "outside", to this relay endpoint
	go func(relay1 *relay.TurnRelay, done chan bool) {
		for {
			select {
			case msg := <-relay1.FromRelay:
				fmt.Printf("received: %s", string(msg))
				// TODO(jack): forward to UDP multicast
			case <-done:
				return
			}
		}
	}(relay1, done)

	// TODO(jack): listen for LINK messages, on UDP, and relay to
	// other hosts in the link-session
	relay1.WriteToRelay([]byte("HELLLLOOOOOOOO"))

	fmt.Println("Waiting for termination signal")
	<-done
	fmt.Println("Exiting gracefully")
	relay1.Shutdown()

}
