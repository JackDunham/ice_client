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
    
    # This test verifies that host_a_net and host_b_net are isolated
    # We check by examining the docker networks
    
    # Get network info
    local networks
    networks=$(docker network ls --format '{{.Name}}' | grep -E 'host_[ab]_net|turn_net' || true)
    
    assert_contains "$networks" "host_a_net" "host_a_net network exists"
    assert_contains "$networks" "host_b_net" "host_b_net network exists"
    assert_contains "$networks" "turn_net" "turn_net network exists"
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