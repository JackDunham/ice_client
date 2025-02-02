package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pion/ice/v2"
	"github.com/pion/stun"

	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
)

var stunServers = []string{
	`stun.l.google.com:19302`,
	`stun1.l.google.com:19302`,
	`stun2.l.google.com:19302`,
	`stun3.l.google.com:19302`,
	`stun4.l.google.com:19302`}

const (
	TurnServer       = `turn:openrelay.metered.ca:80`
	TurnUsername     = `openrelayproject`
	TurnCredential   = `openrelayproject`
	ServerListenPort = ":8082"
)

// Session holds the list of hosts for a session.
type Session struct {
	Hosts []string `json:"hosts"`
}

// sessions maps session IDs to their Session.
// A mutex is used to protect concurrent access.
var (
	sessions = make(map[string]*Session)
	mu       sync.RWMutex
)

// sessionIDRegex verifies that a session ID is a valid UUID v4.
var sessionIDRegex = regexp.MustCompile("^[a-fA-F0-9-]{36}$")

// HostRequest represents the JSON payload with a host.
type HostRequest struct {
	Host string `json:"host"`
}

// handleCreateSession handles POST /session requests.
// It expects a JSON body like {"host": "1.2.3.4:5678"}.
// A new session ID is generated, the host is saved, and the session ID is returned.
func handleCreateSession(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "Missing host in request", http.StatusBadRequest)
		return
	}

	sessionID := uuid.New().String()
	session := &Session{
		Hosts: []string{req.Host},
	}

	sessions[sessionID] = session

	response := map[string]string{"session_id": sessionID}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpdateSession handles PUT /session/<session-id> requests.
// It expects a JSON body like {"host": "1.2.3.4:5678"}.
// If the host is not already in the session's list, it is added.
func handleUpdateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL expected: /session/<session-id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[1] != "session" || !sessionIDRegex.MatchString(parts[2]) {
		http.Error(w, "Invalid session ID in URL", http.StatusBadRequest)
		return
	}
	sessionID := parts[2]

	var req HostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "Missing host in request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	session, ok := sessions[sessionID]
	if !ok {
		mu.Unlock()
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Check for duplicate; the duplicate check is on the full "<ip>:<port>" string.
	found := false
	for _, h := range session.Hosts {
		if h == req.Host {
			found = true
			break
		}
	}
	if !found {
		session.Hosts = append(session.Hosts, req.Host)
	}
	updatedHosts := session.Hosts
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedHosts)
}

// handleGetSession handles GET /session/<session-id> requests,
// returning the current list of hosts for that session.
func handleGetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL expected: /session/<session-id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[1] != "session" || !sessionIDRegex.MatchString(parts[2]) {
		http.Error(w, "Invalid session ID in URL", http.StatusBadRequest)
		return
	}
	sessionID := parts[2]

	mu.RLock()
	session, ok := sessions[sessionID]
	mu.RUnlock()
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session.Hosts)
}

func getExternalIP(stunServer string) (*net.UDPAddr, error) {
	// Dial UDP connection to the STUN server.
	conn, err := net.Dial("udp4", stunServer)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer conn.Close()

	// Set a deadline for the STUN transaction.
	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Build a STUN Binding Request.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Send the STUN request.
	_, err = conn.Write(message.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Read the STUN response.
	var buf [1500]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// Decode the response.
	var res stun.Message
	res.Raw = buf[:n]
	if err := res.Decode(); err != nil {
		return nil, fmt.Errorf("failed to decode STUN response: %w", err)
	}

	// Extract the XOR-MAPPED-ADDRESS attribute.
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(&res); err != nil {
		return nil, fmt.Errorf("failed to get XOR-MAPPED-ADDRESS: %w", err)
	}

	return &net.UDPAddr{
		IP:   xorAddr.IP,
		Port: xorAddr.Port,
	}, nil
}

func main() {
	fmt.Print("hello")
	extAddr, err := getExternalIP(stunServers[0])
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	fmt.Printf("External IP: %s\n", extAddr.String())

	// Configuration for the ICE agent
	config := &ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls: []*stun.URI{
			{
				Scheme: stun.SchemeTypeSTUN,
				Host:   "stun.l.google.com:19302",
			},
		},
	}

	// Create a new ICE agent
	agent, err := ice.NewAgent(config)
	if err != nil {
		log.Fatal(err)
	}

	// Callback to handle newly discovered candidates
	agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			log.Println("Finished gathering candidates")
			return
		}

		// Check if it's a server reflexive candidate
		if candidate.Type() == ice.CandidateTypeServerReflexive {
			fmt.Printf("External IP: %s\n", candidate.Address())
		} else {
			fmt.Printf("EH? %v\n", candidate)
		}
	})

	// Start gathering candidates
	err = agent.GatherCandidates()
	if err != nil {
		log.Fatalf("Failed to gather candidates: %v", err)
	}

	// Wait for gathering to complete (blocking for simplicity)
	//select {}
	// Further setup and event handling for the agent
	// We use a single handler for "/session" and "/session/<session-id>".
	http.HandleFunc("/session/", func(w http.ResponseWriter, r *http.Request) {
		// When the URL is exactly "/session", assume it's a session creation (POST).
		if r.Method == http.MethodPost && r.URL.Path == "/session" {
			handleCreateSession(w, r)
			return
		}

		// For paths like "/session/<session-id>", handle GET and PUT.
		if strings.HasPrefix(r.URL.Path, "/session/") {
			switch r.Method {
			case http.MethodGet:
				handleGetSession(w, r)
				return
			case http.MethodPut:
				handleUpdateSession(w, r)
				return
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}

		http.Error(w, "Not found", http.StatusNotFound)
	})

	// Also register POST /session (without trailing slash).
	http.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleCreateSession(w, r)
			return
		}
		http.Error(w, "Not found", http.StatusNotFound)
	})

	fmt.Printf("Server starting on %s\n", ServerListenPort)
	log.Fatal(http.ListenAndServe(ServerListenPort, nil))

}
