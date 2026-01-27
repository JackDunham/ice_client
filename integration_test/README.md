# Link-over-WAN Integration Tests

This directory contains Docker-based integration tests for the Link-over-WAN relay system.

## Quick Start - Running Tests

### 1. Basic Connectivity Test (Local Infrastructure)

```bash
# Full test with rebuild (use after code changes)
./test_link_wan.sh --keep

# Quick test (skip rebuild if images exist)
./test_link_wan.sh --no-rebuild --keep
```

**Options:**
- `--keep`: Leave containers running after test (for subsequent tests or debugging)
- `--no-rebuild`: Skip Docker image rebuild (faster, requires images to exist)

**What it tests:**
- TURN server and session server startup
- Exchange relay connectivity
- Link peer discovery across isolated networks

### 2. Tempo Sync Test

```bash
# Requires: ./test_link_wan.sh --keep (run first)
./test_tempo_sync.sh
```

**What it tests:**
- Two Link clients start with different tempos (95 vs 140 BPM)
- Verifies they converge to the same tempo via WAN relay
- Uses 0.1 BPM tolerance for floating-point comparison

### 3. Latency & Throughput Test

```bash
# Requires: ./test_link_wan.sh --keep (run first)
./test_latency.sh
```

**What it tests:**
- Network RTT to TURN server
- Relay packet throughput (packets/sec)
- Checks for unexpected errors in exchange logs

### 4. Production Infrastructure Test

Tests with REAL Cloudflare TURN servers and AWS Lightsail session server:

```bash
# Set your Cloudflare API token first
export CLOUDFLARE_BEARER_TOKEN="your-cloudflare-api-token"

# Run production test
./test_production.sh --keep
```

**Requires:**
- `CLOUDFLARE_BEARER_TOKEN` environment variable (get from Cloudflare dashboard > Calls > TURN)
- Internet connectivity to Cloudflare and AWS

**What it tests:**
- Real Cloudflare STUN/TURN server connectivity
- Real AWS Lightsail session server
- End-to-end peer discovery via production infrastructure
- Real-world network latency

**Files:**
- `test_production.sh` - Test script
- `docker-compose.prod.yml` - Docker compose with isolated networks, no local TURN/session server

## Typical Test Workflow

### Local Testing (Development)

```bash
# 1. Run full connectivity test (builds images, starts everything)
./test_link_wan.sh --keep

# 2. Run tempo sync test
./test_tempo_sync.sh

# 3. Run latency test
./test_latency.sh

# 4. Clean up when done
docker compose down
```

### Production Validation

```bash
# 1. Set Cloudflare credentials
export CLOUDFLARE_BEARER_TOKEN="your-token"

# 2. Run production test
./test_production.sh --keep

# 3. Clean up
docker compose -f docker-compose.prod.yml down
```

## Re-running Tests

Both `test_tempo_sync.sh` and `test_latency.sh` clean up after themselves by restarting containers. You can run them repeatedly without re-running `test_link_wan.sh`:

```bash
./test_tempo_sync.sh   # Can run multiple times
./test_latency.sh      # Can run multiple times
```

To start fresh (e.g., after code changes):

```bash
./test_link_wan.sh --keep   # Rebuilds everything
```

## Architecture

The test setup creates isolated network environments to simulate two separate LANs that can only communicate via a TURN relay:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           turn_net (172.28.0.0/24)                      │
│                                                                         │
│    ┌─────────────┐           ┌─────────────────┐                        │
│    │ TURN Server │           │ Session Server  │                        │
│    │ 172.28.0.10 │           │  172.28.0.11    │                        │
│    └─────────────┘           └─────────────────┘                        │
│          │                           │                                  │
│          │                           │                                  │
│    ┌─────┴───────────────────────────┴─────┐                            │
│    │                                       │                            │
└────┼───────────────────────────────────────┼────────────────────────────┘
     │                                       │
┌────┴────────────────────┐    ┌─────────────┴────────────────┐
│  host_a_net             │    │  host_b_net                  │
│  (172.28.1.0/24)        │    │  (172.28.2.0/24)             │
│                         │    │                              │
│  ┌──────────┐           │    │           ┌──────────┐       │
│  │ link_a   │◄──────────┼────┼──────────►│ link_b   │       │
│  │ (LinkHut)│  BLOCKED  │    │  BLOCKED  │ (LinkHut)│       │
│  └────┬─────┘           │    │           └────┬─────┘       │
│       │                 │    │                │             │
│       │ multicast       │    │      multicast │             │
│       ▼                 │    │                ▼             │
│  ┌──────────┐           │    │           ┌──────────┐       │
│  │exchange_a│───────────┼────┼───────────│exchange_b│       │
│  │172.28.1.10           │    │           │172.28.2.10       │
│  └──────────┘           │    │           └──────────┘       │
│       │                 │    │                │             │
└───────┼─────────────────┘    └────────────────┼─────────────┘
        │                                       │
        └───────────── via TURN ────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- Make (optional, for convenience commands)

### Run Infrastructure Only

Start the TURN server and session server:

```bash
docker compose up -d turn_server session_server
```

### Run Link Clients (without bridges)

Start the Link clients on isolated networks:

```bash
docker compose up -d link_a link_b
```

At this point, `link_a` and `link_b` **cannot see each other** because they're on isolated networks.

### Start Exchange Bridges

Start the exchange bridges to enable WAN relay:

```bash
docker compose --profile exchange up -d exchange_a exchange_b
```

Now `link_a` and `link_b` should discover each other via the TURN relay!

### Run Automated Tests

```bash
docker compose --profile test up test_runner
```

### Clean Up

```bash
docker compose --profile exchange --profile test down -v
```

## Manual Testing

### Interactive LinkHut Sessions

Connect to the LinkHut containers:

```bash
# Terminal 1 - Host A
docker exec -it link_a linkhut

# Terminal 2 - Host B  
docker exec -it link_b linkhut
```

In LinkHut:
- Press `space` to toggle play
- Press `up/down` arrows to change tempo
- Watch the "peers" count

### Verify Network Isolation

From `link_a`, you should NOT be able to ping `link_b`:

```bash
docker exec link_a ping -c 1 172.28.2.10  # Should fail
```

But `exchange_a` should be able to reach the TURN server:

```bash
docker exec exchange_a ping -c 1 172.28.0.10  # Should succeed
```

## Environment Variables

The exchange bridge supports these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `TURN_SERVER` | TURN server address (host:port) | Cloudflare TURN |
| `TURN_USER` | TURN username | (from Cloudflare API) |
| `TURN_PASSWORD` | TURN password | (from Cloudflare API) |
| `TURN_REALM` | TURN realm | (empty) |
| `SESSION_SERVER` | Session server URL | AWS Lightsail |
| `SESSION_USER` | Session server username | admin |
| `SESSION_PASSWORD` | Session server password | secret |

## Test Cases

### TC1: Network Isolation
- **Given**: Link clients on separate networks without exchange bridges
- **When**: Client A changes tempo
- **Then**: Client B should NOT see the tempo change
- **Then**: Both clients should show 0 peers

### TC2: TURN Relay Connectivity
- **Given**: Exchange bridges started and connected to TURN
- **When**: Both bridges join the same session
- **Then**: Both clients should discover each other (1 peer)
- **Then**: Tempo changes should propagate

### TC3: Session Server
- **Given**: Session server running
- **When**: Create a session with Host A
- **Then**: Session ID is returned
- **When**: Join session with Host B
- **Then**: Both hosts are listed in the session

## Troubleshooting

### Exchange bridge can't connect to TURN

Check that the TURN server is healthy:

```bash
docker compose logs turn_server
```

Verify connectivity:

```bash
docker exec exchange_a nc -zv 172.28.0.10 3478
```

### LinkHut shows 0 peers

1. Verify both exchange bridges are running
2. Check that they're in the same session:
   ```bash
   docker exec exchange_a cat /current_session_id
   docker exec exchange_b cat /current_session_id
   ```
3. Check exchange logs:
   ```bash
   docker compose logs exchange_a exchange_b
   ```

### Multicast not working

Ensure the containers have multicast enabled:

```bash
docker exec link_a ip maddr show
```

Should show `224.76.78.75` in the list.