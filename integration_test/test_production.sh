#!/bin/bash
# test_production.sh - Test with REAL Cloudflare TURN and AWS session server
#
# REQUIRED: Set CLOUDFLARE_BEARER_TOKEN environment variable
#   export CLOUDFLARE_BEARER_TOKEN="your-api-token"
#   ./test_production.sh [--keep] [--no-rebuild]
#
# This test validates:
# - Real Cloudflare STUN/TURN connectivity
# - Real AWS Lightsail session server
# - End-to-end peer discovery across isolated networks via production infrastructure

set -e

KEEP_RUNNING=false
SKIP_REBUILD=false
TEST_DURATION=60  # Longer timeout for real network latency

# Parse arguments
for arg in "$@"; do
    case $arg in
        --keep)
            KEEP_RUNNING=true
            shift
            ;;
        --no-rebuild)
            SKIP_REBUILD=true
            shift
            ;;
    esac
done

echo "=============================================="
echo "Production Infrastructure Test"
echo "=============================================="
echo "Using: Cloudflare TURN + AWS Lightsail Session Server"
echo "Options: KEEP_RUNNING=$KEEP_RUNNING, SKIP_REBUILD=$SKIP_REBUILD"
echo ""

# Step 1: Check for required environment variable
echo "[1/9] Checking for CLOUDFLARE_BEARER_TOKEN..."
if [ -z "$CLOUDFLARE_BEARER_TOKEN" ]; then
    echo "ERROR: CLOUDFLARE_BEARER_TOKEN environment variable is not set."
    echo ""
    echo "To get your token:"
    echo "  1. Go to Cloudflare dashboard > Calls > TURN"
    echo "  2. Copy your API token"
    echo "  3. Run: export CLOUDFLARE_BEARER_TOKEN=\"your-token\""
    echo ""
    exit 1
fi
echo "    CLOUDFLARE_BEARER_TOKEN is set."

# Step 2: Generate Cloudflare TURN credentials
echo "[2/9] Generating Cloudflare TURN credentials..."
CLOUDFLARE_TURN_KEY_ID="0dcb3c9c553467f3ca69f05a6afd39ce"

CREDS_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $CLOUDFLARE_BEARER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ttl": 86400}' \
    "https://rtc.live.cloudflare.com/v1/turn/keys/${CLOUDFLARE_TURN_KEY_ID}/credentials/generate")

# Check for error
if echo "$CREDS_RESPONSE" | grep -q "error"; then
    echo "ERROR: Failed to generate TURN credentials:"
    echo "$CREDS_RESPONSE"
    exit 1
fi

# Extract username and credential
export TURN_USER=$(echo "$CREDS_RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
export TURN_PASSWORD=$(echo "$CREDS_RESPONSE" | grep -o '"credential":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TURN_USER" ] || [ -z "$TURN_PASSWORD" ]; then
    echo "ERROR: Failed to parse TURN credentials from response:"
    echo "$CREDS_RESPONSE"
    exit 1
fi

echo "    TURN credentials generated (valid for 24 hours)"
echo "    Username: ${TURN_USER:0:20}..."

# Step 3: Set up environment variables
echo "[3/9] Configuring environment..."
export TURN_SERVER="turn.cloudflare.com:3478"
export SESSION_SERVER="https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com"
export SESSION_USER="admin"
export SESSION_PASSWORD="secret"
export SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "    TURN_SERVER: $TURN_SERVER"
echo "    SESSION_SERVER: $SESSION_SERVER"
echo "    SESSION_ID: $SESSION_ID"

# Step 4: Hard teardown - clean up ALL test containers
echo "[4/9] Cleaning up ALL existing test containers..."
# Stop local test containers
docker compose -f docker-compose.yml down 2>/dev/null || true
# Stop production test containers
docker compose -f docker-compose.prod.yml down 2>/dev/null || true
# Force remove any stragglers
docker rm -f exchange_a exchange_b link_client_a link_client_b \
    exchange_a_prod exchange_b_prod link_client_a_prod link_client_b_prod \
    turn_server session_server link_a link_b 2>/dev/null || true
# Clean up networks (both local and prod)
docker network rm integration_test_turn_net integration_test_host_a_net integration_test_host_b_net 2>/dev/null || true
docker network rm integration_test_internet_a_net integration_test_internet_b_net 2>/dev/null || true
echo "    Cleanup complete."

# Step 5: Build images
if [ "$SKIP_REBUILD" = false ]; then
    echo "[5/9] Building Docker images..."
    docker compose -f docker-compose.prod.yml --profile build --profile exchange --profile linktest build
else
    echo "[5/9] Skipping build (--no-rebuild)"
    # Verify images exist
    if ! docker images | grep -q "ice_client_exchange_prod"; then
        echo "ERROR: ice_client_exchange_prod image not found. Run without --no-rebuild."
        exit 1
    fi
fi

# Step 6: Start exchanges
echo "[6/9] Starting exchanges (connecting to Cloudflare TURN)..."
docker compose -f docker-compose.prod.yml --profile exchange up -d
sleep 5

# Verify exchanges are running
if ! docker ps | grep -q "exchange_a_prod"; then
    echo "ERROR: exchange_a_prod not running"
    docker compose -f docker-compose.prod.yml logs exchange_a
    exit 1
fi
if ! docker ps | grep -q "exchange_b_prod"; then
    echo "ERROR: exchange_b_prod not running"
    docker compose -f docker-compose.prod.yml logs exchange_b
    exit 1
fi

# Check TURN connection
echo "    Waiting for TURN relay allocation..."
sleep 5
RELAY_A=$(docker compose -f docker-compose.prod.yml logs exchange_a 2>&1 | grep "relayed-address" | tail -1)
RELAY_B=$(docker compose -f docker-compose.prod.yml logs exchange_b 2>&1 | grep "relayed-address" | tail -1)

if [ -z "$RELAY_A" ] || [ -z "$RELAY_B" ]; then
    echo "WARNING: TURN relay addresses not found in logs yet. Continuing..."
else
    echo "    Exchange A: $RELAY_A"
    echo "    Exchange B: $RELAY_B"
fi

# Step 7: Start link test clients
echo "[7/9] Starting Link test client containers..."
docker compose -f docker-compose.prod.yml --profile linktest up -d
sleep 2

# Step 8: Start Link instances
echo "[8/9] Starting Link instances..."
docker exec -d link_client_a_prod sh -c "link_test_client -json -duration 3m > /tmp/link.log 2>&1"
sleep 1
docker exec -d link_client_b_prod sh -c "link_test_client -json -duration 3m > /tmp/link.log 2>&1"
sleep 2

# Step 9: Wait for peer discovery
echo "[9/9] Waiting for peer discovery via Cloudflare TURN (up to ${TEST_DURATION}s)..."
echo ""

START_TIME=$(date +%s)
PEERS_A=0
PEERS_B=0

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    # Get current peer counts
    PEERS_A=$(docker exec link_client_a_prod cat /tmp/link.log 2>/dev/null | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2 || echo "0")
    PEERS_B=$(docker exec link_client_b_prod cat /tmp/link.log 2>/dev/null | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2 || echo "0")
    
    PEERS_A=${PEERS_A:-0}
    PEERS_B=${PEERS_B:-0}
    
    printf "\r    [%3ds] Client A peers: %s, Client B peers: %s" "$ELAPSED" "$PEERS_A" "$PEERS_B"
    
    # Success condition
    if [ "$PEERS_A" -gt 0 ] && [ "$PEERS_B" -gt 0 ]; then
        echo ""
        echo ""
        echo "=============================================="
        echo "SUCCESS! Peers discovered via Cloudflare TURN!"
        echo "=============================================="
        echo "  Session ID: $SESSION_ID"
        echo "  Client A sees $PEERS_A peer(s)"
        echo "  Client B sees $PEERS_B peer(s)"
        
        echo ""
        echo "=== Exchange A TURN info ==="
        docker compose -f docker-compose.prod.yml logs exchange_a 2>&1 | grep -E "relayed-address|Session" | head -5
        
        echo ""
        echo "=== Client A last 5 entries ==="
        docker exec link_client_a_prod cat /tmp/link.log | tail -5
        
        echo ""
        echo "=== Client B last 5 entries ==="
        docker exec link_client_b_prod cat /tmp/link.log | tail -5
        
        if [ "$KEEP_RUNNING" = false ]; then
            echo ""
            echo "Tearing down containers..."
            docker compose -f docker-compose.prod.yml down
        else
            echo ""
            echo "Containers left running (--keep flag)"
            echo "To tear down: docker compose -f docker-compose.prod.yml down"
        fi
        exit 0
    fi
    
    # Timeout
    if [ "$ELAPSED" -ge "$TEST_DURATION" ]; then
        echo ""
        echo ""
        echo "=============================================="
        echo "TIMEOUT - No peers discovered after ${TEST_DURATION}s"
        echo "=============================================="
        
        echo ""
        echo "=== Exchange A logs ==="
        docker compose -f docker-compose.prod.yml logs exchange_a 2>&1 | tail -20
        
        echo ""
        echo "=== Exchange B logs ==="
        docker compose -f docker-compose.prod.yml logs exchange_b 2>&1 | tail -20
        
        echo ""
        echo "=== Client A log ==="
        docker exec link_client_a_prod cat /tmp/link.log 2>/dev/null | tail -5 || echo "No log"
        
        echo ""
        echo "=== Client B log ==="
        docker exec link_client_b_prod cat /tmp/link.log 2>/dev/null | tail -5 || echo "No log"
        
        if [ "$KEEP_RUNNING" = false ]; then
            echo ""
            echo "Tearing down containers..."
            docker compose -f docker-compose.prod.yml down
        else
            echo ""
            echo "Containers left running for debugging (--keep flag)"
            echo ""
            echo "Debug commands:"
            echo "  docker compose -f docker-compose.prod.yml logs exchange_a"
            echo "  docker compose -f docker-compose.prod.yml logs exchange_b"
            echo "  docker exec link_client_a_prod cat /tmp/link.log"
        fi
        exit 1
    fi
    
    sleep 1
done