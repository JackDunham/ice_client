package relay

import (
	"fmt"
	"ice-client/session"
	"testing"

	"github.com/google/uuid"
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

	sessionID := uuid.New().String()
	relay1.SetLinkSession(&session.LinkSession{SessionID: sessionID, ThisHost: relay1.ThisHost})
	relay2.SetLinkSession(&session.LinkSession{SessionID: sessionID, ThisHost: relay2.ThisHost})

	relay1.Shutdown()
	relay2.Shutdown()

}
