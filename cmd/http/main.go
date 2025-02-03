package main

import (
	"fmt"
	"log"

	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const (
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

func main() {
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
