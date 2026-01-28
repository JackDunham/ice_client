package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ServerListenPort = ":8082"

	// Session expiration duration.
	SessionExpiration = 8 * time.Hour

	// Cloudflare TURN API
	CloudflareTurnKeyID  = "0dcb3c9c553467f3ca69f05a6afd39ce"
	CloudflareTurnAPIURL = "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate"
)

// getAuthCredentials returns username and password from environment variables
// with fallback defaults for backward compatibility
func getAuthCredentials() (string, string) {
	user := os.Getenv("BASIC_AUTH_USER")
	if user == "" {
		user = "admin"
	}
	pass := os.Getenv("BASIC_AUTH_PASSWORD")
	if pass == "" {
		pass = "secret"
	}
	return user, pass
}

// Session holds the list of hosts for a session, plus the creation time.
type Session struct {
	Hosts     []string  `json:"hosts"`
	CreatedAt time.Time `json:"-"`
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

// basicAuthMiddleware enforces HTTP Basic Authentication.
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const basicPrefix = "Basic "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, basicPrefix) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Decode the base64 username:password.
		payload, err := base64.StdEncoding.DecodeString(auth[len(basicPrefix):])
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		pair := strings.SplitN(string(payload), ":", 2)
		expectedUser, expectedPass := getAuthCredentials()
		if len(pair) != 2 || pair[0] != expectedUser || pair[1] != expectedPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// healthCheckHandler provides an unauthenticated health-check endpoint at "/".
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle exact root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Return 200 OK with a simple response.
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// handleTurnCredentials proxies requests to Cloudflare TURN API
// GET /turn/credentials - returns fresh TURN credentials
func handleTurnCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get bearer token from environment
	bearerToken := os.Getenv("CLOUDFLARE_BEARER_TOKEN")
	if bearerToken == "" {
		http.Error(w, "TURN credentials not configured", http.StatusServiceUnavailable)
		log.Println("ERROR: CLOUDFLARE_BEARER_TOKEN environment variable not set")
		return
	}

	// Build Cloudflare API request
	apiURL := fmt.Sprintf(CloudflareTurnAPIURL, CloudflareTurnKeyID)
	reqBody := strings.NewReader(`{"ttl": 86400}`)

	req, err := http.NewRequest(http.MethodPost, apiURL, reqBody)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		log.Printf("ERROR: Failed to create Cloudflare request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	// Make request to Cloudflare
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch TURN credentials", http.StatusBadGateway)
		log.Printf("ERROR: Cloudflare API request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		log.Printf("ERROR: Failed to read Cloudflare response: %v", err)
		return
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Cloudflare API error: "+string(body), resp.StatusCode)
		log.Printf("ERROR: Cloudflare API returned %d: %s", resp.StatusCode, string(body))
		return
	}

	// Return the Cloudflare response as-is
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handleCreateSession handles POST /session requests.
// It expects a JSON body like {"host": "1.2.3.4:5678"}.
// A new session ID is generated, the host is saved, and the response returns
// a JSON object containing both the session_id and the host mapping.
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
		Hosts:     []string{req.Host},
		CreatedAt: time.Now(),
	}

	sessions[sessionID] = session

	// Return both session_id and the provided host mapping.
	response := map[string]string{
		"session_id": sessionID,
		"host":       req.Host,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpdateSession handles PUT /session/<session-id> requests.
// It expects a JSON body like {"host": "1.2.3.4:5678"}.
// If the session doesn't exist, it is created (upsert behavior).
// If the host is not already in the session's list, it is added, and the updated list is returned.
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
		// Create the session if it doesn't exist (upsert behavior)
		session = &Session{
			Hosts:     []string{},
			CreatedAt: time.Now(),
		}
		sessions[sessionID] = session
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

// purgeExpiredSessions periodically removes sessions older than SessionExpiration.
func purgeExpiredSessions() {
	ticker := time.NewTicker(30 * time.Minute)
	for {
		<-ticker.C
		mu.Lock()
		now := time.Now()
		for id, session := range sessions {
			if now.Sub(session.CreatedAt) > SessionExpiration {
				delete(sessions, id)
				log.Printf("Session %s expired and removed", id)
			}
		}
		mu.Unlock()
	}
}

func main() {
	// Start background goroutine to purge expired sessions.
	go purgeExpiredSessions()

	// Register an unauthenticated health-check at the root "/".
	http.HandleFunc("/", healthCheckHandler)

	// Register TURN credentials endpoint (authenticated)
	http.Handle("/turn/credentials", basicAuthMiddleware(http.HandlerFunc(handleTurnCredentials)))

	// Wrap the HTTP handlers with Basic Auth middleware for session endpoints.
	authenticatedHandler := basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Register endpoints for session creation and management with Basic Auth.
	http.Handle("/session", basicAuthMiddleware(http.HandlerFunc(handleCreateSession)))
	http.Handle("/session/", authenticatedHandler)

	fmt.Printf("Server starting on %s\n", ServerListenPort)
	log.Fatal(http.ListenAndServe(ServerListenPort, nil))
}
