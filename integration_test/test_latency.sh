#!/bin/bash
# test_latency.sh - Measure relay latency between exchanges
#
# PREREQUISITE: Run test_link_wan.sh --keep first to set up infrastructure
#   ./test_link_wan.sh --keep
#   ./test_latency.sh
#
# This script measures:
# 1. Network RTT between containers
# 2. Relay throughput (packets/second)

set -e

echo "=============================================="
echo "Latency & Throughput Test"
echo "=============================================="

# Verify infrastructure is running
if ! docker ps | grep -q "exchange_a"; then
    echo "ERROR: exchange_a not running. Run './test_link_wan.sh --keep' first."
    exit 1
fi

echo "[1/6] Cleaning up and restarting containers..."
docker stop link_a link_b 2>/dev/null || true
docker restart exchange_a exchange_b link_client_a link_client_b
sleep 3

echo "[2/6] Starting Link clients to generate traffic..."
docker exec -d link_client_a sh -c "link_test_client -json -duration 1m > /tmp/link.log 2>&1"
docker exec -d link_client_b sh -c "link_test_client -json -duration 1m > /tmp/link.log 2>&1"
sleep 5

echo "[3/6] Measuring network RTT (exchange_a → TURN server)..."
docker exec exchange_a ping -c 5 172.28.0.10 2>/dev/null || echo "ping not available"

echo ""
echo "[4/6] Measuring network RTT (exchange_a → exchange_b via TURN)..."
# Get exchange_b's TURN address
TURN_B=$(docker compose logs exchange_b 2>&1 | grep "relayed-address" | tail -1 | grep -o '[0-9.]*:[0-9]*')
echo "    Exchange B TURN address: $TURN_B"

echo ""
echo "[5/6] Checking relay packet throughput..."
# Get packet counts
sleep 2
STATS_A1=$(docker compose logs exchange_a 2>&1 | grep "In count:" | tail -1)
STATS_B1=$(docker compose logs exchange_b 2>&1 | grep "In count:" | tail -1)
echo "    Initial: A: $STATS_A1 | B: $STATS_B1"

sleep 5
STATS_A2=$(docker compose logs exchange_a 2>&1 | grep "In count:" | tail -1)
STATS_B2=$(docker compose logs exchange_b 2>&1 | grep "In count:" | tail -1)
echo "    After 5s: A: $STATS_A2 | B: $STATS_B2"

# Extract counts and calculate rate
IN_A1=$(echo "$STATS_A1" | grep -o 'In count: [0-9]*' | grep -o '[0-9]*')
IN_A2=$(echo "$STATS_A2" | grep -o 'In count: [0-9]*' | grep -o '[0-9]*')
IN_B1=$(echo "$STATS_B1" | grep -o 'In count: [0-9]*' | grep -o '[0-9]*')
IN_B2=$(echo "$STATS_B2" | grep -o 'In count: [0-9]*' | grep -o '[0-9]*')

if [ -n "$IN_A1" ] && [ -n "$IN_A2" ]; then
    RATE_A=$(( (IN_A2 - IN_A1) / 5 ))
    echo "    Exchange A receive rate: ~$RATE_A packets/sec"
fi
if [ -n "$IN_B1" ] && [ -n "$IN_B2" ]; then
    RATE_B=$(( (IN_B2 - IN_B1) / 5 ))
    echo "    Exchange B receive rate: ~$RATE_B packets/sec"
fi

echo ""
echo "[6/6] Checking for relay errors..."
ERRORS_A=$(docker compose logs exchange_a 2>&1 | grep -i "error" | grep -v "CONFIG:" | tail -5)
ERRORS_B=$(docker compose logs exchange_b 2>&1 | grep -i "error" | grep -v "CONFIG:" | tail -5)

if [ -z "$ERRORS_A" ] && [ -z "$ERRORS_B" ]; then
    echo "    No errors found in exchange logs."
else
    echo "    Exchange A errors:"
    echo "$ERRORS_A"
    echo "    Exchange B errors:"
    echo "$ERRORS_B"
fi

echo ""
echo "=============================================="
echo "Latency Test Complete"
echo "=============================================="
echo ""
echo "Notes:"
echo "  - In Docker, network latency is minimal (<1ms)"
echo "  - Real WAN latency depends on geographic distance"
echo "  - Link tolerates ~50-100ms RTT for tempo sync"
echo "  - Higher latency may cause tempo drift"

