package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	// Embed credentials.json
	_ "embed"
)

const (
	DEFAULT_SESSION_SERVER_HOST = "https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com"
	DEFAULT_SESSION_USER        = "admin"
	DEFAULT_SESSION_PASS        = "secret"
	HOST_REFRESH_INTERVAL       = time.Second * 15
)

// Environment variable names for session server configuration
const (
	ENV_SESSION_SERVER   = "SESSION_SERVER"   // e.g., "http://172.28.0.11:8082"
	ENV_SESSION_USER     = "SESSION_USER"     // e.g., "admin"
	ENV_SESSION_PASSWORD = "SESSION_PASSWORD" // e.g., "secret"
)

// getSessionServerConfig returns the session server URL and auth token from env or defaults
func getSessionServerConfig() (host, authToken string) {
	host = os.Getenv(ENV_SESSION_SERVER)
	if host == "" {
		host = DEFAULT_SESSION_SERVER_HOST
	}

	user := os.Getenv(ENV_SESSION_USER)
	if user == "" {
		user = DEFAULT_SESSION_USER
	}

	pass := os.Getenv(ENV_SESSION_PASSWORD)
	if pass == "" {
		pass = DEFAULT_SESSION_PASS
	}

	// Create base64 auth token
	authToken = base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return host, authToken
}

type LinkSession struct {
	SessionID      string
	Hosts          []string
	ThisHost       string
	HostsDataMutex sync.Mutex
}

type SessionEntry struct {
	Host string `json:"host"`
}

func (ls *LinkSession) UpdateSessionHosts(hosts []string) {
	ls.HostsDataMutex.Lock()
	defer ls.HostsDataMutex.Unlock()

	tempHosts := []string{}
	for _, host := range hosts {
		if host != ls.ThisHost {
			tempHosts = append(tempHosts, host)
		}
	}

	ls.Hosts = tempHosts
}

func (ls *LinkSession) GetSessionHosts() []string {
	ls.HostsDataMutex.Lock()
	defer ls.HostsDataMutex.Unlock()

	return ls.Hosts
}

func (ls *LinkSession) UpdateSessionInfo() error {
	sessionID := ls.SessionID
	sessionCtx, sessionCancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(5))
	defer sessionCancelFunc()

	host, authToken := getSessionServerConfig()
	sessionURL := fmt.Sprintf("%s/session/%s", host, sessionID)
	sessionReq, reqCreationErr := http.NewRequestWithContext(sessionCtx, http.MethodGet, sessionURL, http.NoBody)
	if reqCreationErr != nil {
		return fmt.Errorf("failed to create session request: %w", reqCreationErr)
	}
	sessionReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", authToken))

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
	fmt.Printf("SESSION HOSTS: %+v", hostsList)
	ls.UpdateSessionHosts(hostsList)
	return nil
}

// join or create an Link session. If successful, this will periodically monitor the session to
// update the list of hosts
func (ls *LinkSession) JoinOrCreateSession(sessionID, relayAddress string) (string, error) {
	sessionEntry := SessionEntry{Host: relayAddress}
	sessionEntryBytes, jsonErr := json.Marshal(sessionEntry)

	if jsonErr != nil {
		return "", fmt.Errorf("failed to marshal session entry %+v: %w", sessionEntry, jsonErr)
	}

	sessionCtx, sessionCancelFunc := context.WithTimeout(context.Background(), time.Minute*time.Duration(5))
	defer sessionCancelFunc()

	host, authToken := getSessionServerConfig()
	var httpMethod string
	var sessionURL string
	// we are joining an existing session
	if sessionID != "" {
		httpMethod = http.MethodPut
		sessionURL = fmt.Sprintf("%s/session/%s", host, sessionID)
	} else {
		// we are creation a new session
		sessionURL = fmt.Sprintf("%s/session", host)
		httpMethod = http.MethodPost
	}

	fmt.Printf("Session server: %s (method: %s)\n", sessionURL, httpMethod)

	sessionReq, reqCreationErr := http.NewRequestWithContext(sessionCtx, httpMethod, sessionURL, bytes.NewBuffer(sessionEntryBytes))
	if reqCreationErr != nil {
		return "", fmt.Errorf("failed to create session request: %w", reqCreationErr)
	}
	sessionReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", authToken))

	sessionClient := http.DefaultClient
	sessionResp, sessErr := sessionClient.Do(sessionReq)
	if sessErr != nil {
		return "", fmt.Errorf("failed session request: %w", sessErr)
	}
	defer sessionResp.Body.Close()

	if sessionResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad session response: %d", sessionResp.StatusCode)
	}
	bodyBytes, readErr := io.ReadAll(sessionResp.Body)
	if readErr != nil {
		return "", fmt.Errorf("failed reading session body-bytes: %w", readErr)
	} else if len(bodyBytes) == 0 {
		return "", fmt.Errorf("empty session body-bytes")
	}

	sessionHosts := []string{}
	if sessionID == "" {
		newSessionInfo := struct {
			Host      string `json:"host"`
			SessionID string `json:"session_id"`
		}{}
		unmarshalErr := json.Unmarshal(bodyBytes, &newSessionInfo)
		if unmarshalErr != nil {
			return "", fmt.Errorf("failed unmarshaling session POST response %s: %w", string(bodyBytes), unmarshalErr)
		}
		sessionID = newSessionInfo.SessionID
		//fmt.Print(newSessionInfo)
	} else {
		unmarshalErr := json.Unmarshal(bodyBytes, &sessionHosts)
		if unmarshalErr != nil {
			return "", fmt.Errorf("failed unmarshaling session PUT response %s: %s", string(bodyBytes), unmarshalErr)
		}
		//fmt.Print(sessionHosts)
	}
	ls.SessionID = sessionID
	ls.ThisHost = relayAddress
	ls.UpdateSessionHosts(sessionHosts)

	/*
		// start async go-routine to periodically check for new-hosts joining the session
		go func(ctx context.Context, interval time.Duration, ls *LinkSession) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop() // Ensure ticker is stopped when done.

			for {
				select {
				case <-ctx.Done():
					fmt.Println("Context cancelled, stopping periodic task")
					return
				case t := <-ticker.C:
					fmt.Printf("Updating session info %v\n", t)
					ls.UpdateSessionInfo()
				}
			}
		}(context.Background(), HOST_REFRESH_INTERVAL, ls) // TODO(jack): FIX magic-number
	*/
	return sessionID, nil
}
