package relay

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

	"ice-client/session"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"

	// Embed credentials.json
	_ "embed"
)

const (
	SECONDS_PER_DAY               = 86400
	TURN_TOKEN_ID                 = "0dcb3c9c553467f3ca69f05a6afd39ce"
	CLOUDFLARE_CREDENTIALS_URL    = "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate"
	CONTENT_TYPE_APPLICATION_JSON = "application/json"
	DO_PING_TEST                  = false
)

// Environment variable names for TURN configuration
const (
	ENV_TURN_SERVER             = "TURN_SERVER"             // e.g., "172.28.0.10:3478"
	ENV_TURN_USER               = "TURN_USER"               // e.g., "testuser"
	ENV_TURN_PASSWORD           = "TURN_PASSWORD"           // e.g., "testpassword"
	ENV_TURN_REALM              = "TURN_REALM"              // e.g., "test.local" (optional)
	ENV_CLOUDFLARE_BEARER_TOKEN = "CLOUDFLARE_BEARER_TOKEN" // Cloudflare API token (optional)
)

type TurnRelay struct {
	RelayConn    net.PacketConn
	UdpConn      net.PacketConn
	Session      *session.LinkSession
	FromRelay    chan []byte
	KillChannel  chan bool
	Credentials  *TurnCredentials
	TurnClient   *turn.Client
	SessionHosts []net.Addr
	sessionMutex sync.Mutex
	ThisHost     string
}

// IceServers holds the TURN/STUN server details.
type IceServers struct {
	Urls       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

// TurnCredentials wraps the iceServers object.
type TurnCredentials struct {
	IceServers IceServers `json:"iceServers"`
	Host       string
	Port       string
	User       string
	Cred       string
	Realm      string
}

type TurnCredentialsPostBody struct {
	TTL int `json:"ttl"`
}

func getHostPortUserCredRealm(creds *TurnCredentials) (host, port, user, cred, realm string) {
	hostAndPort := ""
	for _, tempHostPort := range creds.IceServers.Urls {
		if strings.HasPrefix(tempHostPort, "turn:") {
			hostAndPort = tempHostPort
			break
		}
	}
	host = strings.TrimPrefix(hostAndPort[0:strings.LastIndex(hostAndPort, ":")], "turn:")
	port = strings.TrimPrefix(strings.Split(hostAndPort[strings.LastIndex(hostAndPort, ":"):], "?")[0], ":")
	user = creds.IceServers.Username
	cred = creds.IceServers.Credential
	realm = ""
	return
}

// getTurnCredentialsFromEnv attempts to get TURN credentials from environment variables.
// Returns nil if environment variables are not set.
func getTurnCredentialsFromEnv() *TurnCredentials {
	turnServer := os.Getenv(ENV_TURN_SERVER)
	turnUser := os.Getenv(ENV_TURN_USER)
	turnPassword := os.Getenv(ENV_TURN_PASSWORD)
	turnRealm := os.Getenv(ENV_TURN_REALM)

	if turnServer == "" || turnUser == "" || turnPassword == "" {
		return nil
	}

	// Parse host:port
	host := turnServer
	port := "3478" // default TURN port
	if idx := strings.LastIndex(turnServer, ":"); idx != -1 {
		host = turnServer[:idx]
		port = turnServer[idx+1:]
	}

	fmt.Printf("Using TURN server from environment: %s:%s (user: %s)\n", host, port, turnUser)

	return &TurnCredentials{
		IceServers: IceServers{
			Urls:       []string{fmt.Sprintf("turn:%s:%s", host, port)},
			Username:   turnUser,
			Credential: turnPassword,
		},
		Host:  host,
		Port:  port,
		User:  turnUser,
		Cred:  turnPassword,
		Realm: turnRealm,
	}
}

// getTurnCredentialsFromCloudflare fetches credentials from Cloudflare TURN API
func getTurnCredentialsFromCloudflare(bearerToken string) (*TurnCredentials, error) {
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
	req.Header.Set("Authorization", "Bearer "+bearerToken)
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
	creds.Host, creds.Port, creds.User, creds.Cred, creds.Realm = getHostPortUserCredRealm(&creds)
	fmt.Printf("Using Cloudflare TURN with username: %s\n", creds.IceServers.Username)
	return &creds, nil
}

// getTurnCredentialsFromSessionServer fetches TURN credentials from the session server
func getTurnCredentialsFromSessionServer() (*TurnCredentials, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancelFunc()

	// Get session server config (reuse existing function from session package)
	sessionServer := os.Getenv(session.ENV_SESSION_SERVER)
	if sessionServer == "" {
		sessionServer = session.DEFAULT_SESSION_SERVER_HOST
	}

	sessionUser := os.Getenv(session.ENV_SESSION_USER)
	if sessionUser == "" {
		sessionUser = session.DEFAULT_SESSION_USER
	}

	sessionPass := os.Getenv(session.ENV_SESSION_PASSWORD)
	if sessionPass == "" {
		sessionPass = session.DEFAULT_SESSION_PASS
	}

	credentialsURL := fmt.Sprintf("%s/turn/credentials", sessionServer)
	fmt.Printf("Fetching TURN credentials from session server: %s\n", credentialsURL)

	req, err := http.NewRequestWithContext(ctx, "GET", credentialsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating session server request: %w", err)
	}
	req.SetBasicAuth(sessionUser, sessionPass)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed requesting credentials from session server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading session server response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("session server returned error (status=%d): %s", resp.StatusCode, string(body))
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from session server")
	}

	var creds TurnCredentials
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials from session server: %w", err)
	}
	creds.Host, creds.Port, creds.User, creds.Cred, creds.Realm = getHostPortUserCredRealm(&creds)
	fmt.Printf("Using TURN credentials from session server (username: %s)\n", creds.IceServers.Username)
	return &creds, nil
}

// getTurnCredentials gets TURN credentials from environment variables, Cloudflare, or session server
func getTurnCredentials() (*TurnCredentials, error) {
	// First, try environment variables (direct TURN server config)
	if creds := getTurnCredentialsFromEnv(); creds != nil {
		return creds, nil
	}

	// Check if Cloudflare bearer token is available
	bearerToken := os.Getenv(ENV_CLOUDFLARE_BEARER_TOKEN)
	if bearerToken != "" {
		fmt.Println("Using Cloudflare TURN API directly...")
		return getTurnCredentialsFromCloudflare(bearerToken)
	}

	// Fall back to session server
	fmt.Println("No TURN credentials in environment, fetching from session server...")
	return getTurnCredentialsFromSessionServer()
}

func (turnRelay *TurnRelay) Shutdown() {
	// all go-routines will get the kill message
	close(turnRelay.KillChannel)
	if closeErr := turnRelay.UdpConn.Close(); closeErr != nil {
		log.Panicf("Failed to close TURN connection: %s", closeErr.Error())
	}
	if turnRelay.TurnClient != nil {
		turnRelay.TurnClient.Close()
	}
}

// Set external/turn address of relay targets
func (turnRelay *TurnRelay) SetSessionHosts(hostStrings []string) error {
	turnRelay.sessionMutex.Lock()
	defer turnRelay.sessionMutex.Unlock()

	sessionHosts := []net.Addr{}
	for _, turnHost := range hostStrings {
		// Using net.ResolveTCPAddr (for TCP addresses)
		turnHostAddr, err := net.ResolveUDPAddr("udp", turnHost)
		if err != nil {
			return fmt.Errorf("error resolving UDP address: %w", err)
		}
		var netAddr net.Addr = turnHostAddr
		sessionHosts = append(sessionHosts, netAddr)
	}
	turnRelay.SessionHosts = sessionHosts
	return nil
}

/*
// TODO(jack): left-off, here
func (turnRelay *TurnRelay) RefreshLinkSession(hostString []string) error {
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-turnRelay.KillChannel:
			return
		case <-ticker.C:
			if turnRelay.Session == nil {
				continue
			}
			sessionHosts := []net.Addr{}
			// TODO(jack): panic is happening, here (below)
			turnRelay.Session.UpdateSessionInfo()
			for _, turnHost := range turnRelay.Session.GetSessionHosts() {
				// Using net.ResolveTCPAddr (for TCP addresses)
				turnHostAddr, err := net.ResolveUDPAddr("udp", turnHost)
				if err != nil {
					log.Fatalf("Error resolving UDP address: %s", err.Error())
				}
				var netAddr net.Addr = turnHostAddr
				sessionHosts = append(sessionHosts, netAddr)
			}
			turnRelay.SessionHosts = sessionHosts
		}
	}
}
*/

func StartTurnClient(fromRelay chan []byte, ctx context.Context) (*TurnRelay, error) { //nolint:cyclop
	// Create a channel to receive OS signals.
	//quit := make(chan os.Signal, 1)
	killChan := make(chan bool)
	turnRelay := &TurnRelay{FromRelay: fromRelay, KillChannel: killChan}
	var err error

	turnRelay.Credentials, err = getTurnCredentials()
	if err != nil {
		log.Fatalf("Error retrieving credentials: %v", err)
	}
	fmt.Printf("Using ICE servers with username: %s\n", turnRelay.Credentials.IceServers.Username)

	// TURN client won't create a local listening socket by itself.
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

	turnServerAddr := fmt.Sprintf("%s:%s", turnRelay.Credentials.Host, turnRelay.Credentials.Port)

	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           conn,
		Username:       turnRelay.Credentials.User,
		Password:       turnRelay.Credentials.Cred,
		Realm:          turnRelay.Credentials.Realm,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		log.Panicf("Failed to create TURN client: %s", err)
	}
	// THIS is now handled by Shutdown() function
	//defer client.Close()

	// Start listening on the conn provided.
	err = client.Listen()
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	turnRelay.RelayConn, err = client.Allocate()
	if err != nil {
		log.Panicf("Failed to allocate TURN relay connection: %s", err.Error())
	}
	log.Printf("relayed-address=%s", turnRelay.RelayConn.LocalAddr().String())
	turnRelay.ThisHost = turnRelay.RelayConn.LocalAddr().String()

	mappedAddr, err := client.SendBindingRequest()
	if err != nil {
		return nil, fmt.Errorf("error sending binding request: %w", err)
	}

	// This call opens a UDP packet connection using IPv4 on all local interfaces,
	// and by specifying port 0 the operating system chooses an available ephemeral port.
	// This connection can then be used to both send and receive UDP packets
	turnRelay.UdpConn, err = net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

	// Punch a UDP hole for the relayConn by sending a data to the mappedAddr.
	// This will trigger a TURN client to generate a permission request to the
	// TURN server. After this, packets from the IP address will be accepted by
	// the TURN server.
	_, err = turnRelay.RelayConn.WriteTo([]byte("Hello"), mappedAddr)
	if err != nil {
		log.Panicf("Failed to write initial packet to relay-connection: %s", err.Error())
	}

	go turnRelay.ReadFromRelay(ctx)
	//go turnRelay.WriteToRelay()

	return turnRelay, nil
}

func (turnRelay *TurnRelay) ReadFromRelay(ctx context.Context) error {
	buf := make([]byte, 1600)
	for {
		select {
		case <-ctx.Done():
			turnRelay.Shutdown()
			return nil
		default:
			n, from, readerErr := turnRelay.RelayConn.ReadFrom(buf)
			if readerErr != nil {
				fmt.Printf("error reading from relay: %s", readerErr.Error())
				continue
			}
			fmt.Printf("received %d bytes relay (from %+v)", n, from)
			// safe seond
			func(ch chan []byte, value []byte) (ok bool) {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("Recovered from panic during send: +%v", r)
						ok = false
					}
				}()
				ch <- value
				return true
			}(turnRelay.FromRelay, buf[:n])
		}
	}
}

/*
	func (turnRelay *TurnRelay) WriteToRelay() error {
		for {
			select {
			case msg := <-turnRelay.ToRelay:
				for _, netAddr := range turnRelay.SessionHosts {
					fmt.Printf("Write bytes to Host Addr: +%v", netAddr)
					_, err := turnRelay.RelayConn.WriteTo(msg, netAddr)
					if err != nil {
						fmt.Printf("Error writing bytes to Host Addr +%v: %s", netAddr, err.Error())
					}
				}
			case <-turnRelay.KillChannel:
				return nil
			default:
				fmt.Print("waiting to send")
			}
		}
		return nil,
	}
*/
func (turnRelay *TurnRelay) WriteToRelay(msg []byte) error {
	turnRelay.sessionMutex.Lock()
	hosts := make([]net.Addr, len(turnRelay.SessionHosts))
	copy(hosts, turnRelay.SessionHosts)
	turnRelay.sessionMutex.Unlock()

	for _, netAddr := range hosts {
		// CRITICAL FIX: Use RelayConn (the TURN-allocated relay connection), not UdpConn.
		// UdpConn is a local UDP socket that cannot reach peers behind NAT.
		// RelayConn sends data through the TURN server which relays it to the destination.
		n, err := turnRelay.RelayConn.WriteTo(msg, netAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %d bytes to Host Addr %v: %s\n", n, netAddr, err.Error())
		}
	}
	return nil
}
