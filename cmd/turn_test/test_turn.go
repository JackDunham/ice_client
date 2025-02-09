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
	"sync"
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
	DO_PING_TEST                  = false
)

//go:embed credentials.json
var credentialsData []byte

var hostsDataMutex sync.Mutex

var sessionID string

type LinkSession struct {
	SessionID string
	Hosts     []string
	ThisHost  string
}

var linkSession = &LinkSession{}

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

func updateSessionHosts(hosts []string) {
	hostsDataMutex.Lock()
	defer hostsDataMutex.Unlock()

	tempHosts := []string{}
	for _, host := range hosts {
		if host != linkSession.ThisHost {
			tempHosts = append(tempHosts, host)
		}
	}

	linkSession.Hosts = tempHosts
}

func getSessionHosts() []string {
	hostsDataMutex.Lock()
	defer hostsDataMutex.Unlock()

	return linkSession.Hosts
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

func updateSessionInfo() error {
	sessionID = linkSession.SessionID
	sessionCtx, sessionCancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(5))
	defer sessionCancelFunc()

	sessionURL := fmt.Sprintf("%s/session/%s", LIGHTSAIL_CONTAINER_HOST, sessionID)
	sessionReq, reqCreationErr := http.NewRequestWithContext(sessionCtx, http.MethodGet, sessionURL, http.NoBody)
	if reqCreationErr != nil {
		return fmt.Errorf("failed to create session request: %w", reqCreationErr)
	}
	sessionReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", LIGHTSAIL_BASIC_AUTH_TOKEN))

	sessionClient := http.DefaultClient
	sessionResp, sessErr := sessionClient.Do(sessionReq)
	if sessErr != nil {
		return fmt.Errorf("failed session request: %w", sessErr)
	}
	defer sessionResp.Body.Close()

	if sessionResp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad session response: %d", sessionResp.StatusCode)
	}
	bodyBytes, readErr := io.ReadAll(sessionResp.Body)
	if readErr != nil {
		return fmt.Errorf("failed reading session body-bytes: %w", readErr)
	} else if len(bodyBytes) == 0 {
		return fmt.Errorf("empty session body-bytes")
	}
	hostsList := []string{}
	unmarshalErr := json.Unmarshal(bodyBytes, &hostsList)
	if unmarshalErr != nil {
		log.Panicf("Failed unmarshaling session response %s: %v", string(bodyBytes), unmarshalErr)
	}
	fmt.Print(hostsList)
	updateSessionHosts(hostsList)
	return nil
}

// join or create an Link session. If successful, this will periodically monitor the session to
// update the list of hosts
func joinOrCreateSession(sessionID, relayAddress string) error {
	sessionEntry := SessionEntry{Host: relayAddress}
	sessionEntryBytes, jsonErr := json.Marshal(sessionEntry)

	if jsonErr != nil {
		return fmt.Errorf("failed to marshal session entry %+v: %w", sessionEntry, jsonErr)
	}

	sessionCtx, sessionCancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(5))
	defer sessionCancelFunc()

	var httpMethod string
	var sessionURL string
	// we are joining an existing session
	if sessionID != "" {
		httpMethod = http.MethodPut
		sessionURL = fmt.Sprintf("%s/session/%s", LIGHTSAIL_CONTAINER_HOST, sessionID)
	} else {
		// we are creation a new session
		sessionURL = fmt.Sprintf("%s/session", LIGHTSAIL_CONTAINER_HOST)
		httpMethod = http.MethodPost
	}

	sessionReq, reqCreationErr := http.NewRequestWithContext(sessionCtx, httpMethod, sessionURL, bytes.NewBuffer(sessionEntryBytes))
	if reqCreationErr != nil {
		return fmt.Errorf("failed to create session request: %w", reqCreationErr)
	}
	sessionReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", LIGHTSAIL_BASIC_AUTH_TOKEN))

	sessionClient := http.DefaultClient
	sessionResp, sessErr := sessionClient.Do(sessionReq)
	if sessErr != nil {
		return fmt.Errorf("failed session request: %w", sessErr)
	}
	defer sessionResp.Body.Close()

	if sessionResp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad session response: %d", sessionResp.StatusCode)
	}
	bodyBytes, readErr := io.ReadAll(sessionResp.Body)
	if readErr != nil {
		return fmt.Errorf("failed reading session body-bytes: %w", readErr)
	} else if len(bodyBytes) == 0 {
		return fmt.Errorf("empty session body-bytes")
	}

	sessionHosts := []string{}
	if sessionID == "" {
		newSessionInfo := struct {
			Host      string `json:"host"`
			SessionID string `json:"session_id"`
		}{}
		unmarshalErr := json.Unmarshal(bodyBytes, &newSessionInfo)
		if unmarshalErr != nil {
			return fmt.Errorf("failed unmarshaling session POST response %s: %w", string(bodyBytes), unmarshalErr)
		}
		sessionID = newSessionInfo.SessionID
		fmt.Print(newSessionInfo)
	} else {
		unmarshalErr := json.Unmarshal(bodyBytes, &sessionHosts)
		if unmarshalErr != nil {
			return fmt.Errorf("failed unmarshaling session PUT response %s: %s", string(bodyBytes), unmarshalErr)
		}
		fmt.Print(sessionHosts)
	}
	linkSession.SessionID = sessionID
	linkSession.ThisHost = relayAddress
	updateSessionHosts(sessionHosts)

	// start async go-routine to periodically check for new-hosts joining the session
	go func(ctx context.Context, interval time.Duration) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop() // Ensure ticker is stopped when done.

		for {
			select {
			case <-ctx.Done():
				fmt.Println("Context cancelled, stopping periodic task")
				return
			case t := <-ticker.C:
				fmt.Printf("Updating session info %v\n", t)
				updateSessionInfo()
			}
		}
	}(context.Background(), time.Minute) // TODO(jack): FIX magic-number

	return nil
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
	ping := DO_PING_TEST

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
	joinOrCreateSession(sessionID, relayConn.LocalAddr().String())

	// If you provided `-ping`, perform a ping test against the
	// relayConn we have just allocated.
	if ping {
		err = doPingTest(client, relayConn)
		if err != nil {
			log.Panicf("Failed to ping: %s", err)
		}
	}

	// TODO(jack): actually run "forever" but listen for kill/quit
	time.Sleep(time.Minute * time.Duration(15))
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
