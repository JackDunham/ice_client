#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }

PASS_COUNT=0
FAIL_COUNT=0

assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="$3"
    if [ "$expected" = "$actual" ]; then
        log_info "✓ PASS: $msg"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: $msg (expected: $expected, got: $actual)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if echo "$haystack" | grep -q "$needle"; then
        log_info "✓ PASS: $msg"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: $msg (expected to contain: $needle)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_gt() {
    local val="$1"
    local threshold="$2"
    local msg="$3"
    if [ "$val" -gt "$threshold" ]; then
        log_info "✓ PASS: $msg"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: $msg (expected > $threshold, got: $val)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

wait_for_service() {
    local host="$1"
    local port="$2"
    local timeout="${3:-30}"
    local start=$(date +%s)
    
    log_info "Waiting for $host:$port..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $(($(date +%s) - start)) -gt "$timeout" ]; then
            log_error "Timeout waiting for $host:$port"
            return 1
        fi
        sleep 1
    done
    log_info "$host:$port is available"
}

#############################################
# Test: Session Server Health
#############################################
test_session_server_health() {
    log_test "Testing session server health endpoint..."
    
    local response
    response=$(curl -s -w "\n%{http_code}" http://session_server:8082/)
    local body=$(echo "$response" | head -n -1)
    local status=$(echo "$response" | tail -n 1)
    
    assert_eq "200" "$status" "Session server returns 200 OK"
    assert_eq "OK" "$body" "Session server returns OK body"
}

#############################################
# Test: Session Creation and Retrieval
#############################################
test_session_crud() {
    log_test "Testing session CRUD operations..."
    
    # Create a session
    local create_response
    create_response=$(curl -s -X POST \
        -H "Authorization: Basic YWRtaW46c2VjcmV0" \
        -H "Content-Type: application/json" \
        -d '{"host": "192.168.1.100:12345"}' \
        http://session_server:8082/session)
    
    local session_id
    session_id=$(echo "$create_response" | jq -r '.session_id')
    
    assert_contains "$session_id" "-" "Session ID is UUID format"
    
    # Get the session
    local get_response
    get_response=$(curl -s -X GET \
        -H "Authorization: Basic YWRtaW46c2VjcmV0" \
        "http://session_server:8082/session/$session_id")
    
    assert_contains "$get_response" "192.168.1.100:12345" "Session contains original host"
    
    # Add another host
    local update_response
    update_response=$(curl -s -X PUT \
        -H "Authorization: Basic YWRtaW46c2VjcmV0" \
        -H "Content-Type: application/json" \
        -d '{"host": "192.168.1.101:12346"}' \
        "http://session_server:8082/session/$session_id")
    
    assert_contains "$update_response" "192.168.1.101:12346" "Session contains new host"
    assert_contains "$update_response" "192.168.1.100:12345" "Session still contains original host"
    
    echo "$session_id"
}

#############################################
# Test: TURN Server Connectivity
#############################################
test_turn_server() {
    log_test "Testing TURN server connectivity..."
    
    # Check TURN server is listening
    if nc -z turn_server 3478 2>/dev/null; then
        log_info "✓ PASS: TURN server is listening on port 3478"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: TURN server is not listening on port 3478"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

#############################################
# Test: Network Isolation
#############################################
test_network_isolation() {
    log_test "Testing network isolation..."
    
    # This test verifies that turn_net exists
    # host_a_net and host_b_net are only created when link containers start
    
    # Get network info (networks have project prefix like integration_test_)
    local networks
    networks=$(docker network ls --format '{{.Name}}' || true)
    
    # turn_net should exist since test_runner uses it
    if echo "$networks" | grep -q "turn_net"; then
        log_info "✓ PASS: turn_net network exists"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: turn_net network not found"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    # Note: host_a_net and host_b_net are created on-demand when link containers start
    # The real isolation test happens in test_link_synchronization
    log_info "Note: host_a_net and host_b_net created when link containers start"
}

#############################################
# Test: Exchange Bridge Connectivity (when started)
#############################################
test_exchange_connectivity() {
    log_test "Testing exchange bridge TURN connectivity..."
    
    # This would test that exchange_a and exchange_b can connect to TURN
    # and establish a relay connection
    
    # For now, just verify the session server sees them when they register
    log_warn "Exchange connectivity test requires running exchange containers"
    log_warn "Run: docker compose --profile exchange up -d"
}

#############################################
# Test: Link Synchronization (THE MAIN TEST)
# Verifies tempo propagation only works when exchanges are running
#############################################
test_link_synchronization() {
    log_test "Testing Link synchronization over WAN..."
    
    local project_name="${COMPOSE_PROJECT_NAME:-integration_test}"
    
    # Helper to get peer count from a link client (short-lived check)
    get_peer_count() {
        local container="$1"
        local result
        result=$(docker exec "$container" link_test_client -json -duration 3s 2>/dev/null | tail -1 | jq -r '.num_peers // 0' 2>/dev/null)
        echo "${result:-0}"
    }
    
    # Helper to get tempo from a link client (short-lived check)
    get_tempo() {
        local container="$1"
        local result
        result=$(docker exec "$container" link_test_client -json -duration 3s 2>/dev/null | tail -1 | jq -r '.tempo // 120' 2>/dev/null)
        echo "${result:-120}"
    }
    
    # Helper to set tempo on a link client
    set_tempo() {
        local container="$1"
        local tempo="$2"
        docker exec "$container" link_test_client -json -duration 3s -set-tempo "$tempo" 2>/dev/null | tail -1
    }
    
    # Helper to start persistent Link instance in background
    start_persistent_link() {
        local container="$1"
        local initial_tempo="${2:-120}"
        # Run in background, output to /tmp/link.log
        docker exec -d "$container" sh -c "link_test_client -json -duration 5m -interval 1s -initial-tempo $initial_tempo > /tmp/link.log 2>&1"
    }
    
    # Helper to get status from persistent Link instance
    get_persistent_status() {
        local container="$1"
        docker exec "$container" tail -1 /tmp/link.log 2>/dev/null
    }
    
    get_persistent_peer_count() {
        local container="$1"
        local result
        result=$(get_persistent_status "$container" | jq -r '.num_peers // 0' 2>/dev/null)
        echo "${result:-0}"
    }
    
    get_persistent_tempo() {
        local container="$1"
        local result
        result=$(get_persistent_status "$container" | jq -r '.tempo // 120' 2>/dev/null)
        echo "${result:-120}"
    }
    
    log_info "Phase 1: Starting Link clients on isolated networks..."
    
    # Start link clients (without exchanges) - use pre-built images
    docker compose --profile linktest up -d --no-build link_client_a link_client_b 2>/dev/null
    sleep 3  # Give them time to start
    
    # Verify clients are running
    if ! docker ps | grep -q link_client_a; then
        log_error "link_client_a failed to start"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return
    fi
    if ! docker ps | grep -q link_client_b; then
        log_error "link_client_b failed to start"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return
    fi
    log_info "Link clients started"
    
    log_info "Phase 2: Verifying network isolation (no peers without exchange)..."
    
    # Check that neither client sees the other
    local peers_a=$(get_peer_count "link_client_a")
    local peers_b=$(get_peer_count "link_client_b")
    
    assert_eq "0" "$peers_a" "link_client_a sees 0 peers (isolated)"
    assert_eq "0" "$peers_b" "link_client_b sees 0 peers (isolated)"
    
    log_info "Phase 3: Verifying tempo does NOT propagate without exchange..."
    
    # Set a unique tempo on A
    local test_tempo_1="142.5"
    set_tempo "link_client_a" "$test_tempo_1" >/dev/null
    sleep 2
    
    # Check B's tempo - should NOT have changed
    local tempo_b=$(get_tempo "link_client_b")
    # B should still be at default (120) or whatever it was, NOT 142.5
    if [ "$(echo "$tempo_b == $test_tempo_1" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        log_error "✗ FAIL: Tempo propagated without exchange running! (B has $tempo_b)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        log_info "✓ PASS: Tempo did NOT propagate without exchange (A=$test_tempo_1, B=$tempo_b)"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
    
    log_info "Phase 4: Starting exchange bridges and persistent Link instances..."
    
    # Start exchanges - use pre-built images
    docker compose --profile exchange up -d --no-build exchange_a exchange_b 2>/dev/null
    sleep 3  # Let exchanges initialize
    
    # Start persistent Link instances in both containers
    # These will run in background and continuously broadcast/receive
    log_info "Starting persistent Link instances..."
    start_persistent_link "link_client_a" 120
    start_persistent_link "link_client_b" 120
    
    # Wait for exchanges to relay traffic and Link instances to discover each other
    log_info "Waiting for peer discovery via relay (up to 45s)..."
    local max_wait=45
    local waited=0
    while [ "$waited" -lt "$max_wait" ]; do
        local peers_a=$(get_persistent_peer_count "link_client_a")
        if [ "$peers_a" -gt 0 ]; then
            log_info "Peer discovered after ${waited}s"
            break
        fi
        sleep 3
        waited=$((waited + 3))
    done
    
    log_info "Phase 5: Verifying peer discovery with exchange..."
    
    # Debug: show exchange packet counts
    log_info "Exchange A packet counts:"
    docker logs exchange_a 2>&1 | grep -E "In count|Out count" | tail -2 || true
    log_info "Exchange B packet counts:"
    docker logs exchange_b 2>&1 | grep -E "In count|Out count" | tail -2 || true
    
    # Debug: show link client status
    log_info "Link client A status:"
    get_persistent_status "link_client_a" || echo "(no status)"
    log_info "Link client B status:"
    get_persistent_status "link_client_b" || echo "(no status)"
    
    local peers_a=$(get_persistent_peer_count "link_client_a")
    local peers_b=$(get_persistent_peer_count "link_client_b")
    
    if [ "$peers_a" -gt 0 ]; then
        log_info "✓ PASS: link_client_a sees $peers_a peer(s)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: link_client_a still sees 0 peers after exchange started"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    if [ "$peers_b" -gt 0 ]; then
        log_info "✓ PASS: link_client_b sees $peers_b peer(s)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: link_client_b still sees 0 peers after exchange started"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    log_info "Phase 6: Verifying tempo DOES propagate with exchange..."
    
    # Set a unique tempo using docker exec (will sync with persistent instance)
    local test_tempo_2="87.3"
    set_tempo "link_client_a" "$test_tempo_2" >/dev/null
    sleep 5  # Give time for tempo to propagate through relay
    
    # Check B's tempo from persistent instance - should have changed to match
    local tempo_b=$(get_persistent_tempo "link_client_b")
    local tempo_diff
    tempo_diff=$(echo "scale=2; $tempo_b - $test_tempo_2" | bc -l 2>/dev/null | tr -d '-' || echo "999")
    
    # Allow small floating point tolerance (< 0.5 BPM)
    if [ "$(echo "$tempo_diff < 0.5" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        log_info "✓ PASS: Tempo propagated correctly (A set $test_tempo_2, B has $tempo_b)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: Tempo did NOT propagate (A set $test_tempo_2, B has $tempo_b)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    log_info "Phase 7: Cleanup..."
    
    # Stop containers
    docker compose --profile linktest --profile exchange stop link_client_a link_client_b exchange_a exchange_b 2>/dev/null
    
    log_info "Link synchronization test complete"
}

#############################################
# Main test execution
#############################################
main() {
    log_info "Starting Link-over-WAN Integration Tests"
    log_info "========================================"
    
    # Wait for services to be ready
    wait_for_service "session_server" 8082 30
    wait_for_service "turn_server" 3478 30
    
    log_info ""
    log_info "Running tests..."
    log_info ""
    
    # Run tests
    test_session_server_health
    echo ""
    
    test_session_crud
    echo ""
    
    test_turn_server
    echo ""
    
    test_network_isolation
    echo ""
    
    # This is the main test - only run if link_client image is built
    if docker images --format '{{.Repository}}' | grep -q 'link_client'; then
        test_link_synchronization
        echo ""
    else
        log_warn "Skipping Link synchronization test (link_test_client not built)"
        log_warn "Build with: docker compose --profile linktest build"
    fi
    
    # Summary
    log_info "========================================"
    log_info "Test Summary"
    log_info "========================================"
    log_info "Passed: $PASS_COUNT"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        log_error "Failed: $FAIL_COUNT"
        exit 1
    else
        log_info "Failed: $FAIL_COUNT"
        log_info ""
        log_info "All tests passed!"
        exit 0
    fi
}

main "$@"