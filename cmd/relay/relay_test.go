package relay

import (
	"fmt"
	"ice-client/session"
	"testing"
	"time"
)

// TestAdd is a simple test for a function that adds two integers.
func TestRelay(t *testing.T) {
	fromChan := make(chan []byte)
	toChan := make(chan []byte)

	relay1, err := StartTurnClient(fromChan, toChan)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	relay2, err := StartTurnClient(fromChan, toChan)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	linkSession1 := &session.LinkSession{}
	linkSession1.JoinOrCreateSession("", relay1.ThisHost)

	linkSession2 := &session.LinkSession{}
	linkSession2.JoinOrCreateSession(linkSession1.SessionID, relay2.ThisHost)

	relay1.SetSessionHosts(linkSession1.Hosts)
	relay2.SetSessionHosts(linkSession2.Hosts)

	time.Sleep(time.Hour)
	relay1.Shutdown()
	relay2.Shutdown()

}
