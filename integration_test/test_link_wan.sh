#!/bin/bash
# test_link_wan.sh - Complete test runner for Link-over-WAN
# Usage: ./test_link_wan.sh [--keep] [--no-rebuild]
#   --keep: Leave containers running after test
#   --no-rebuild: Skip docker build (use existing images)

set -e

KEEP_RUNNING=false
SKIP_REBUILD=false
TEST_DURATION=30  # seconds to wait for peers

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
echo "Link-over-WAN Integration Test"
echo "=============================================="
echo "Options: KEEP_RUNNING=$KEEP_RUNNING, SKIP_REBUILD=$SKIP_REBUILD"
echo ""

# Step 1: Hard teardown
echo "[1/8] Hard teardown - killing all containers..."
docker rm -f $(docker ps -aq) 2>/dev/null || true

# Step 2: Clean images and rebuild (unless --no-rebuild)
if [ "$SKIP_REBUILD" = false ]; then
    echo "[2/8] Cleaning Docker images and cache..."
    docker system prune -a --volumes -f
    
    echo "[3/8] Building all images..."
    docker compose --profile build --profile exchange --profile linktest build
else
    echo "[2/8] Skipping image cleanup (--no-rebuild)"
    # Verify required images exist
    if ! docker images | grep -q "ice_client_exchange"; then
        echo "ERROR: ice_client_exchange image not found. Run without --no-rebuild or run 'docker compose build' first."
        exit 1
    fi
    if ! docker images | grep -q "integration_test-link_client"; then
        echo "ERROR: link_client images not found. Run without --no-rebuild or run 'docker compose build' first."
        exit 1
    fi
    echo "[3/8] Skipping build (--no-rebuild) - images verified"
fi

# Step 3: Start infrastructure
echo "[4/8] Starting infrastructure (TURN server, session server)..."
docker compose up -d turn_server session_server
echo "    Waiting for health checks (up to 30s)..."

# Wait for health checks with timeout
for i in {1..30}; do
    TURN_HEALTHY=$(docker ps --filter "name=turn_server" --filter "health=healthy" -q)
    SESSION_HEALTHY=$(docker ps --filter "name=session_server" --filter "health=healthy" -q)
    
    if [ -n "$TURN_HEALTHY" ] && [ -n "$SESSION_HEALTHY" ]; then
        echo "    Infrastructure healthy after ${i}s."
        break
    fi
    
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Infrastructure not healthy after 30s"
        docker compose logs turn_server | tail -20
        docker compose logs session_server | tail -20
        exit 1
    fi
    
    sleep 1
done

# Step 4: Start exchanges
echo "[5/8] Starting exchanges..."
docker compose --profile exchange up -d
sleep 3

# Verify exchanges are running
if ! docker ps | grep -q "exchange_a"; then
    echo "ERROR: exchange_a not running"
    docker compose logs exchange_a
    exit 1
fi
if ! docker ps | grep -q "exchange_b"; then
    echo "ERROR: exchange_b not running"
    docker compose logs exchange_b
    exit 1
fi
echo "    Exchanges running."

# Step 5: Start link test clients
echo "[6/8] Starting link test client containers..."
docker compose --profile linktest up -d
sleep 2

# Step 6: Start persistent Link instances
echo "[7/8] Starting Link instances in background..."
docker exec -d link_client_a sh -c "link_test_client -json -duration 3m > /tmp/link.log 2>&1"
sleep 1
docker exec -d link_client_b sh -c "link_test_client -json -duration 3m > /tmp/link.log 2>&1"
sleep 2

# Step 7: Wait and poll for peers
echo "[8/8] Waiting for peer discovery (up to ${TEST_DURATION}s)..."
echo ""

START_TIME=$(date +%s)
PEERS_A=0
PEERS_B=0

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    # Get current peer counts
    PEERS_A=$(docker exec link_client_a cat /tmp/link.log 2>/dev/null | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2 || echo "0")
    PEERS_B=$(docker exec link_client_b cat /tmp/link.log 2>/dev/null | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2 || echo "0")
    
    # Default to 0 if empty
    PEERS_A=${PEERS_A:-0}
    PEERS_B=${PEERS_B:-0}
    
    printf "\r    [%3ds] Client A peers: %s, Client B peers: %s" "$ELAPSED" "$PEERS_A" "$PEERS_B"
    
    # Success condition: both see at least 1 peer
    if [ "$PEERS_A" -gt 0 ] && [ "$PEERS_B" -gt 0 ]; then
        echo ""
        echo ""
        echo "=============================================="
        echo "SUCCESS! Peers discovered!"
        echo "=============================================="
        echo "  Client A sees $PEERS_A peer(s)"
        echo "  Client B sees $PEERS_B peer(s)"
        
        # Show some logs
        echo ""
        echo "=== Client A last 5 entries ==="
        docker exec link_client_a cat /tmp/link.log | tail -5
        echo ""
        echo "=== Client B last 5 entries ==="
        docker exec link_client_b cat /tmp/link.log | tail -5
        
        if [ "$KEEP_RUNNING" = false ]; then
            echo ""
            echo "Tearing down containers..."
            docker compose down
        else
            echo ""
            echo "Containers left running (--keep flag)"
            echo "To tear down: docker compose down"
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
        
        # Debug info
        echo ""
        echo "=== Exchange A status ==="
        docker compose logs exchange_a 2>&1 | grep -E "In count|Out count|DEBUG|ERROR" | tail -10
        
        echo ""
        echo "=== Exchange B status ==="
        docker compose logs exchange_b 2>&1 | grep -E "In count|Out count|DEBUG|ERROR" | tail -10
        
        echo ""
        echo "=== Client A log ==="
        docker exec link_client_a cat /tmp/link.log | tail -5
        
        echo ""
        echo "=== Client B log ==="
        docker exec link_client_b cat /tmp/link.log | tail -5
        
        if [ "$KEEP_RUNNING" = false ]; then
            echo ""
            echo "Tearing down containers..."
            docker compose down
        else
            echo ""
            echo "Containers left running for debugging (--keep flag)"
            echo "Useful commands:"
            echo "  docker compose logs exchange_a"
            echo "  docker exec link_client_a tcpdump -i eth0 udp port 20808"
            echo "  docker exec exchange_a sh -c \"echo TEST | nc -u -w1 224.76.78.75 20808\""
        fi
        exit 1
    fi
    
    sleep 1
done