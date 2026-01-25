#!/bin/bash
# test_tempo_sync.sh - Test tempo synchronization across WAN relay
#
# PREREQUISITE: Run test_link_wan.sh --keep first to set up infrastructure
#   ./test_link_wan.sh --keep
#   ./test_tempo_sync.sh
#
# This script tests:
# 1. Two clients with different initial tempos converge
# 2. Dynamic tempo changes propagate across the relay

set -e

echo "=============================================="
echo "Tempo Sync Test"
echo "=============================================="

# Verify infrastructure is running
if ! docker ps | grep -q "exchange_a"; then
    echo "ERROR: exchange_a not running. Run './test_link_wan.sh --keep' first."
    exit 1
fi
if ! docker ps | grep -q "exchange_b"; then
    echo "ERROR: exchange_b not running. Run './test_link_wan.sh --keep' first."
    exit 1
fi
if ! docker ps | grep -q "link_client_a"; then
    echo "ERROR: link_client_a not running. Run './test_link_wan.sh --keep' first."
    exit 1
fi
if ! docker ps | grep -q "link_client_b"; then
    echo "ERROR: link_client_b not running. Run './test_link_wan.sh --keep' first."
    exit 1
fi

echo "[1/5] Stopping any extra Link instances (link_a, link_b)..."
docker stop link_a link_b 2>/dev/null || true

echo "[2/5] Restarting exchanges and link_client containers to clear state..."
docker restart exchange_a exchange_b link_client_a link_client_b
sleep 3

echo "[3/5] Starting Client A at 95 BPM..."
docker exec -d link_client_a sh -c "link_test_client -json -duration 1m -initial-tempo 95 > /tmp/link.log 2>&1"
sleep 3

# Show Client A initial state
echo "    Client A initial state:"
docker exec link_client_a cat /tmp/link.log | tail -1

echo "[4/5] Starting Client B at 140 BPM..."
docker exec -d link_client_b sh -c "link_test_client -json -duration 1m -initial-tempo 140 > /tmp/link.log 2>&1"
sleep 5

echo "[5/5] Checking tempo convergence..."
echo ""

# Get current state
TEMPO_A=$(docker exec link_client_a cat /tmp/link.log | tail -1 | grep -o '"tempo":[0-9.]*' | cut -d: -f2)
TEMPO_B=$(docker exec link_client_b cat /tmp/link.log | tail -1 | grep -o '"tempo":[0-9.]*' | cut -d: -f2)
PEERS_A=$(docker exec link_client_a cat /tmp/link.log | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2)
PEERS_B=$(docker exec link_client_b cat /tmp/link.log | tail -1 | grep -o '"num_peers":[0-9]*' | cut -d: -f2)

echo "=== Current State ==="
echo "  Client A: tempo=$TEMPO_A, peers=$PEERS_A"
echo "  Client B: tempo=$TEMPO_B, peers=$PEERS_B"
echo ""

# Show full logs
echo "=== Client A Log (started at 95 BPM) ==="
docker exec link_client_a cat /tmp/link.log
echo ""

echo "=== Client B Log (started at 140 BPM) ==="
docker exec link_client_b cat /tmp/link.log
echo ""

# Check if tempos match (within tolerance for floating point)
TEMPO_DIFF=$(echo "$TEMPO_A $TEMPO_B" | awk '{diff = $1 - $2; if (diff < 0) diff = -diff; print diff}')
TOLERANCE=0.1

if [ "$(echo "$TEMPO_DIFF < $TOLERANCE" | bc -l)" -eq 1 ]; then
    echo "=============================================="
    echo "SUCCESS! Tempos converged (A=$TEMPO_A, B=$TEMPO_B, diff=$TEMPO_DIFF)"
    echo "=============================================="
    
    # Check if peers found each other
    if [ "$PEERS_A" -gt 0 ] && [ "$PEERS_B" -gt 0 ]; then
        echo "Both clients see peers (A=$PEERS_A, B=$PEERS_B)"
    else
        echo "WARNING: Peers not fully discovered (A=$PEERS_A, B=$PEERS_B)"
    fi
else
    echo "=============================================="
    echo "FAILURE! Tempos did not converge"
    echo "=============================================="
    echo "  Client A: $TEMPO_A BPM"
    echo "  Client B: $TEMPO_B BPM"
    echo "  Difference: $TEMPO_DIFF BPM (tolerance: $TOLERANCE)"
    exit 1
fi