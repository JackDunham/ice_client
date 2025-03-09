package relay

import (
	"context"
	"fmt"
	"ice-client/session"
	"testing"
	"time"
)

// TestAdd is a simple test for a function that adds two integers.
func TestRelay(t *testing.T) {
	fromChan := make(chan []byte, 1024)
	toChan := make(chan []byte, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay1, err := StartTurnClient(fromChan, ctx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("relay1 host: %+v", relay1.RelayConn.LocalAddr())

	relay2, err := StartTurnClient(toChan, ctx)
	if err != nil {
		t.Fatal(err)
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
		msg := <-relay2.FromRelay
		fmt.Printf("\n\n\nreceived: %s", string(msg))
	}()
	relay1.WriteToRelay([]byte("HELLLLOOOOOOOO"))
	time.Sleep(time.Second * 15)
	relay1.Shutdown()
	relay2.Shutdown()

}
