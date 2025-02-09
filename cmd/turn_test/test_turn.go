package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"

	// Embed credentials.json
	_ "embed"
)

const (
	SECONDS_PER_DAY               = 86400
	API_BEARER_TOKEN              = "2a25a05b3daef821a3e93596f6942ac56eace5d9886ca8a2e36b4264fe83b056"
	TURN_TOKEN_ID                 = "0dcb3c9c553467f3ca69f05a6afd39ce"
	CLOUDFLARE_CREDENTIALS_URL    = "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate"
	CONTENT_TYPE_APPLICATION_JSON = "application/json"
	LIGHTSAIL_CONTAINER_HOST      = "https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com"
	LIGHTSAIL_CONTAINER_USER      = "admin"
	LIGHTSAIL_CONTAINER_PASS      = "secret"
	LIGHTSAIL_BASIC_AUTH_TOKEN    = "YWRtaW46c2VjcmV0"
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

type TurnCredentialsPostBody struct {
	TTL int `json:"ttl"`
}

type SessionEntry struct {
	Host string `json:"host"`
}

func getTurnCredentials() (*TurnCredentials, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*time.Duration(5))
	defer cancelFunc()

	turnCredentialsPostBody := TurnCredentialsPostBody{TTL: SECONDS_PER_DAY}
	postBodyBytes, err := json.Marshal(turnCredentialsPostBody)
	if err != nil {
		return nil, fmt.Errorf("failed marsh calling credentials pod body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf(CLOUDFLARE_CREDENTIALS_URL, TURN_TOKEN_ID), bytes.NewBuffer(postBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed creating credentials request: %w", err)
	}
	req.Header.Set("Content-Type", CONTENT_TYPE_APPLICATION_JSON)
	req.Header.Set("Authorization", "Bearer "+API_BEARER_TOKEN)
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed requesting credentials: %w", err)
	}
	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	} else if len(body) == 0 {
		return nil, fmt.Errorf("error empty response (status-code=%d): %w", resp.StatusCode, err)
	}

	var creds TurnCredentials
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}
	fmt.Printf("Using ICE servers with username: %s\n", creds.IceServers.Username)
	return &creds, nil
}

func getHostPortUserCredRealm(creds *TurnCredentials) (host, port, user, cred, realm string) {
	hostAndPort := creds.IceServers.Urls[1]
	host = strings.TrimPrefix(hostAndPort[0:strings.LastIndex(hostAndPort, ":")], "turn:")
	port = strings.TrimPrefix(strings.Split(hostAndPort[strings.LastIndex(hostAndPort, ":"):], "?")[0], ":")
	user = creds.IceServers.Username
	cred = creds.IceServers.Credential
	realm = ""
	return
}

func main() { //nolint:cyclop
	sessionID := ""
	createSession := false
	if len(os.Args) == 2 && os.Args[1] != "" {
		sessionID = os.Args[1]
	} else {
		createSession = true
	}
	fmt.Printf("sessionID=%s (create-session=%v)", sessionID, createSession)

	creds, err := getTurnCredentials()
	if err != nil {
		log.Fatalf("Error retrieving credentials: %v", err)
	}
	fmt.Printf("Using ICE servers with username: %s\n", creds.IceServers.Username)

	host, port, user, cred, realm := getHostPortUserCredRealm(creds)
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

	// register relay-address
	if createSession {
		sessionCtx, sessionCancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(5))
		defer sessionCancelFunc()

		sessionEntry := SessionEntry{Host: relayConn.LocalAddr().String()}
		sessionEntryBytes, jsonErr := json.Marshal(sessionEntry)
		if jsonErr != nil {
			log.Panicf("Failed to marshal session entry %+v: %s", sessionEntry, jsonErr)
		}
		sessionReq, reqCreationErr := http.NewRequestWithContext(sessionCtx, http.MethodPost, LIGHTSAIL_CONTAINER_HOST+"/session", bytes.NewBuffer(sessionEntryBytes))
		if reqCreationErr != nil {
			log.Panicf("Failed to create session request: %v", reqCreationErr)
		}
		sessionReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", LIGHTSAIL_BASIC_AUTH_TOKEN))

		sessionClient := http.DefaultClient
		sessionResp, sessErr := sessionClient.Do(sessionReq)
		if sessErr != nil {
			log.Panicf("Failed session request: %v", sessErr)
		}
		defer sessionResp.Body.Close()

		if sessionResp.StatusCode != http.StatusOK {
			log.Panicf("Bad session response: %d", sessionResp.StatusCode)
		}
		bodyBytes, readErr := io.ReadAll(sessionResp.Body)
		if readErr != nil {
			log.Panicf("Failed reading session body-bytes: %v", readErr)
		} else if len(bodyBytes) == 0 {
			log.Panicf("Empty session body-bytes")
		}
		newSessionInfo := struct {
			Host      string `json:"host"`
			SessionID string `json:"session_id"`
		}{}
		unmarshalErr := json.Unmarshal(bodyBytes, &newSessionInfo)
		if unmarshalErr != nil {
			log.Panicf("Failed unmarshaling session response %s: %v", string(bodyBytes), unmarshalErr)
		}
		fmt.Print(newSessionInfo)
	} else {
		fmt.Print("NO OP")
	}

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
	// TODO(jack): here woud be the place to READ packets from other Link relays
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

	time.Sleep(time.Minute * time.Duration(15))
	return nil
}
