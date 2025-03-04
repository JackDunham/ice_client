package main

import (
	"fmt"
	"ice-client/relay"
	"ice-client/session"
	"log"
	"time"
)

// TestAdd is a simple test for a function that adds two integers.
func main() {
	fromChan := make(chan []byte, 1024)
	toChan := make(chan []byte, 1024)

	relay1, err := relay.StartTurnClient(fromChan, toChan)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	relay2, err := relay.StartTurnClient(fromChan, toChan)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	linkSession1 := &session.LinkSession{}
	linkSession1.JoinOrCreateSession("", relay1.ThisHost)

	linkSession2 := &session.LinkSession{}
	linkSession2.JoinOrCreateSession(linkSession1.SessionID, relay2.ThisHost)
	linkSession1.UpdateSessionInfo()
	linkSession2.UpdateSessionInfo()

	relay1.SetSessionHosts(linkSession1.Hosts)
	relay2.SetSessionHosts(linkSession2.Hosts)

	go func() {
		msg := <-relay1.FromRelay
		fmt.Printf("received: %s", string(msg))
	}()
	relay1.WriteToRelay([]byte("HELLLLOOOOOOOO"))
	time.Sleep(time.Minute)
	relay1.Shutdown()
	relay2.Shutdown()

}
