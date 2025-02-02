// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN client using UDP
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"

	// Embed credentials.json
	_ "embed"
)

//go:embed credentials.json
var credentialsData []byte

// IceServers holds the TURN/STUN server details.

type IceServers struct {
	Urls       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

// TurnCredentials wraps the iceServers object.
type TurnCredentials struct {
	IceServers IceServers `json:"iceServers"`
}

func main() { //nolint:cyclop
	// Parse the embedded credentials.
	var creds TurnCredentials
	if err := json.Unmarshal(credentialsData, &creds); err != nil {
		log.Fatalf("Failed to parse credentials.json: %v", err)
	}
	fmt.Printf("Using ICE servers with username: %s\n", creds.IceServers.Username)

	/*
		host := flag.String("host", "", "TURN Server name.")
		port := flag.Int("port", 3478, "Listening port.")
		user := flag.String("user", "", "A pair of username and password (e.g. \"user=pass\")")
		realm := flag.String("realm", "pion.ly", "Realm (defaults to \"pion.ly\")")
		ping := flag.Bool("ping", false, "Run ping test")
		flag.Parse()
	*/
	hostAndPort := creds.IceServers.Urls[1]
	host := strings.TrimPrefix(hostAndPort[0:strings.LastIndex(hostAndPort, ":")], "turn:")
	port := strings.TrimPrefix(strings.Split(hostAndPort[strings.LastIndex(hostAndPort, ":"):], "?")[0], ":")
	user := creds.IceServers.Username
	cred := creds.IceServers.Credential
	realm := ""
	ping := true

	// TURN client won't create a local listening socket by itself.
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()

	turnServerAddr := fmt.Sprintf("%s:%s", host, port)

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       user,
		Password:       cred,
		Realm:          realm,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		log.Panicf("Failed to create TURN client: %s", err)
	}
	defer client.Close()

	// Start listening on the conn provided.
	err = client.Listen()
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err := client.Allocate()
	if err != nil {
		log.Panicf("Failed to allocate: %s", err)
	}
	defer func() {
		if closeErr := relayConn.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	// If you provided `-ping`, perform a ping test against the
	// relayConn we have just allocated.
	if ping {
		err = doPingTest(client, relayConn)
		if err != nil {
			log.Panicf("Failed to ping: %s", err)
		}
	}
}

func doPingTest(client *turn.Client, relayConn net.PacketConn) error { //nolint:cyclop
	// Send BindingRequest to learn our external IP
	mappedAddr, err := client.SendBindingRequest()
	if err != nil {
		return err
	}

	// Set up pinger socket (pingerConn)
	pingerConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	defer func() {
		if closeErr := pingerConn.Close(); closeErr != nil {
			log.Panicf("Failed to close connection: %s", closeErr)
		}
	}()

	// Punch a UDP hole for the relayConn by sending a data to the mappedAddr.
	// This will trigger a TURN client to generate a permission request to the
	// TURN server. After this, packets from the IP address will be accepted by
	// the TURN server.
	_, err = relayConn.WriteTo([]byte("Hello"), mappedAddr)
	if err != nil {
		return err
	}

	// Start read-loop on pingerConn
	go func() {
		buf := make([]byte, 1600)
		for {
			n, from, pingerErr := pingerConn.ReadFrom(buf)
			if pingerErr != nil {
				break
			}

			msg := string(buf[:n])
			if sentAt, pingerErr := time.Parse(time.RFC3339Nano, msg); pingerErr == nil {
				rtt := time.Since(sentAt)
				log.Printf("%d bytes from from %s time=%d ms\n", n, from.String(), int(rtt.Seconds()*1000))
			}
		}
	}()

	// Start read-loop on relayConn
	go func() {
		buf := make([]byte, 1600)
		for {
			n, from, readerErr := relayConn.ReadFrom(buf)
			if readerErr != nil {
				break
			}

			// Echo back
			if _, readerErr = relayConn.WriteTo(buf[:n], from); readerErr != nil {
				break
			}
		}
	}()

	time.Sleep(500 * time.Millisecond)

	// Send 10 packets from relayConn to the echo server
	for i := 0; i < 10; i++ {
		msg := time.Now().Format(time.RFC3339Nano)
		_, err = pingerConn.WriteTo([]byte(msg), relayConn.LocalAddr())
		if err != nil {
			return err
		}

		// For simplicity, this example does not wait for the pong (reply).
		// Instead, sleep 1 second.
		time.Sleep(time.Second)
	}

	return nil
}
