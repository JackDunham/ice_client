# Link-over-WAN

Extends Ableton Link protocol to work across wide area networks, enabling geographically separated Ableton Live instances to synchronize tempo over the internet.

## Overview

Ableton Link is designed for LAN-only communication using UDP multicast on `224.76.78.75:20808`. This project bridges that limitation by relaying Link traffic through TURN servers, allowing peers on different networks to discover each other and sync.

## Quick Start

### 1. Build the Exchange

```bash
# Build for your current architecture
./build_exchange.sh

# Or build for specific platforms
./build_exchange.sh arm64    # Apple Silicon
./build_exchange.sh amd64    # Intel Mac
./build_exchange.sh all      # All platforms
```

### 2. Run the Exchange

**Person A** (creates session):
```bash
./exchange-darwin-arm64 \
  --session-server https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com \
  --session-user admin \
  --session-password <password>
```

This outputs a session ID and writes it to `current_session_id`.

**Person B** (joins session):
```bash
./exchange-darwin-arm64 \
  --session-server https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com \
  --session-user admin \
  --session-password <password> \
  --session <session-id-from-person-a>
```

### 3. Start Ableton Live

Launch Ableton Live (or any Link-enabled app) on both computers. They should discover each other through the exchange bridge.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                           │
│                                                                                 │
│                    ┌─────────────────────────┐                                  │
│                    │   Cloudflare TURN       │                                  │
│                    │   (relay server)        │                                  │
│                    └───────────┬─────────────┘                                  │
│                                │                                                │
│              ┌─────────────────┼─────────────────┐                              │
│              │                 │                 │                              │
│              ▼                 │                 ▼                              │
│     ┌─────────────────┐       │        ┌─────────────────┐                     │
│     │ Session Server  │◄──────┴───────►│ Session Server  │                     │
│     │ (AWS Lightsail) │                │ (peer discovery)│                     │
│     └─────────────────┘                └─────────────────┘                     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
        │                                                       │
        │ UDP relay                                             │ UDP relay
        ▼                                                       ▼
┌───────────────────┐                                 ┌───────────────────┐
│   Network A       │                                 │   Network B       │
│                   │                                 │                   │
│  ┌─────────────┐  │                                 │  ┌─────────────┐  │
│  │  Exchange   │  │                                 │  │  Exchange   │  │
│  │  (bridge)   │  │                                 │  │  (bridge)   │  │
│  └──────┬──────┘  │                                 │  └──────┬──────┘  │
│         │         │                                 │         │         │
│    multicast      │                                 │    multicast      │
│    224.76.78.75   │                                 │    224.76.78.75   │
│         │         │                                 │         │         │
│  ┌──────┴──────┐  │                                 │  ┌──────┴──────┐  │
│  │ Ableton Live│  │                                 │  │ Ableton Live│  │
│  │ (Link peer) │  │                                 │  │ (Link peer) │  │
│  └─────────────┘  │                                 │  └─────────────┘  │
└───────────────────┘                                 └───────────────────┘
```

## How It Works

### Packet Flow

The exchange bridge handles two types of Link packets:

#### 1. Discovery Packets (Multicast)
- **Header**: `_asdp_v` (107 bytes typical)
- **Direction**: Link peer → Exchange → TURN relay → Remote Exchange → Remote Link peer
- **Contains**: MEP4 (Measurement Endpoint) with IP:port for clock sync
- **Processing**: Exchange rewrites MEP4 to its local IP so remote peers can respond

#### 2. Measurement Packets (Unicast)
- **Header**: `_link_v` (25 bytes typical)  
- **Direction**: Link peer → Exchange MEP4 address → TURN relay → Remote peer
- **Purpose**: Clock synchronization via ping/pong timing
- **Processing**: Exchange captures unicast packets on port 20808 and forwards through relay with source address wrapper

### Session Discovery

1. Exchange connects to TURN server, gets relay address (e.g., `104.30.145.5:21687`)
2. Exchange registers relay address with Session Server under a shared Session ID
3. Session Server returns list of all relay addresses in the session
4. Exchanges send packets to each other's relay addresses via TURN

## Exchange CLI Reference

```
Usage: exchange [options]

Options:
  -session string
        Session ID to join, or blank to create a new session
  -session-server string
        Session server URL (overrides SESSION_SERVER env)
  -session-user string
        Session server username (overrides SESSION_USER env)
  -session-password string
        Session server password (overrides SESSION_PASSWORD env)

Environment Variables (used if flags not provided):
  SESSION_SERVER      Session server URL
  SESSION_USER        Session server username  
  SESSION_PASSWORD    Session server password
  SESSION_ID          Session ID to join
  CLOUDFLARE_BEARER_TOKEN   Cloudflare API token (for direct TURN credential fetch)
  TURN_SERVER         Direct TURN server address (bypasses credential fetch)
  TURN_USER           Direct TURN username
  TURN_PASSWORD       Direct TURN password
```

### Credential Resolution Order

The exchange fetches TURN credentials in this order:
1. **Environment variables**: If `TURN_SERVER`, `TURN_USER`, `TURN_PASSWORD` are all set
2. **Cloudflare direct**: If `CLOUDFLARE_BEARER_TOKEN` is set, calls Cloudflare API
3. **Session server proxy**: Falls back to `SESSION_SERVER/turn/credentials`

## Components

### Exchange (`cmd/exchange/`)
The bridge application that:
- Listens for Link multicast packets on the local network
- Rewrites MEP4 endpoints to local IP for proper routing
- Forwards packets through TURN relay to remote exchanges
- Captures unicast measurement packets and relays them
- Periodically syncs peer list with Session Server

### Session Server (`cmd/http/`)
HTTP API for peer discovery:
- `GET /` - Health check
- `GET /turn/credentials` - Proxy to Cloudflare TURN API (returns fresh credentials)
- `POST /session` - Create new session, returns session ID
- `PUT /session/<uuid>` - Join session (upsert), returns list of peers
- `GET /session/<uuid>` - Get session peers

### Link Test Client (`integration_test/link_test_client/`)
Go wrapper around Ableton Link C++ library for testing:
- Reports peer count and tempo as JSON
- Supports setting initial tempo and runtime tempo changes

## Deployment

### Session Server (AWS Lightsail)

1. Create `.env` file in `cmd/http/`:
   ```
   CLOUDFLARE_BEARER_TOKEN=your-cloudflare-api-token
   BASIC_AUTH_USER=admin
   BASIC_AUTH_PASSWORD=your-secure-password
   ```

2. Deploy:
   ```bash
   cd cmd/http
   ./deploy_session_server.sh
   ```

3. Verify:
   ```bash
   # Health check
   curl https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com/
   
   # Get TURN credentials
   curl -u admin:password https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com/turn/credentials
   ```

## Integration Tests

Tests are in `integration_test/`. They use Docker to create isolated networks simulating WAN conditions.

### Prerequisites
- Docker and Docker Compose v2

### Running Tests

```bash
cd integration_test

# Create .env file with Cloudflare token
echo "CLOUDFLARE_BEARER_TOKEN=your-token" > .env

# 1. Basic connectivity test (builds images, starts infrastructure)
./test_link_wan.sh --keep

# 2. Tempo synchronization test
./test_tempo_sync.sh

# 3. Latency and throughput test  
./test_latency.sh

# 4. Production infrastructure test (real Cloudflare + AWS)
./test_production.sh --keep

# 5. Production test with TURN credential proxy
./test_production.sh --proxy-turn --keep

# Clean up
docker compose down
```

### Test Options
- `--keep` - Leave containers running after test
- `--no-rebuild` - Skip Docker image rebuild
- `--hard-clean` - Remove all containers, networks, images before starting
- `--proxy-turn` - Fetch TURN credentials via session server instead of direct Cloudflare

### Test Network Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           turn_net (172.28.0.0/24)                      │
│    ┌─────────────┐           ┌─────────────────┐                        │
│    │ TURN Server │           │ Session Server  │                        │
│    │ 172.28.0.10 │           │  172.28.0.11    │                        │
│    └─────────────┘           └─────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────┘
        │                                       │
┌───────┴───────────────────┐    ┌──────────────┴──────────────┐
│  host_a_net (172.28.1.0)  │    │  host_b_net (172.28.2.0)    │
│  ┌──────────┐             │    │             ┌──────────┐    │
│  │ link_a   │ ◄─BLOCKED─► │    │ ◄─BLOCKED─► │ link_b   │    │
│  └────┬─────┘             │    │             └────┬─────┘    │
│       │ multicast         │    │       multicast  │          │
│  ┌────┴─────┐             │    │             ┌────┴─────┐    │
│  │exchange_a│─────────────┼────┼─────────────│exchange_b│    │
│  └──────────┘  via TURN   │    │   via TURN  └──────────┘    │
└───────────────────────────┘    └─────────────────────────────┘
```

## Development

### Building

```bash
# Build exchange for current platform
./build_exchange.sh

# Build for all platforms
./build_exchange.sh all

# Build session server Docker image
cd cmd/http
./build.sh
```

### Vendoring

The project uses vendored dependencies:
```bash
go mod vendor
```

### Key Files

```
├── cmd/
│   ├── exchange/          # Main bridge application
│   │   └── exchange.go
│   └── http/              # Session server
│       ├── main.go
│       ├── deploy_session_server.sh
│       └── .env           # (create from .env.example)
├── integration_test/
│   ├── .env               # CLOUDFLARE_BEARER_TOKEN (create this)
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── test_link_wan.sh
│   ├── test_tempo_sync.sh
│   ├── test_latency.sh
│   └── test_production.sh
├── multicast/             # Multicast packet handling
│   └── multicast.go
├── relay/                 # TURN relay management
│   └── relay.go
├── session/               # Session server client
│   └── session.go
├── build_exchange.sh      # Build script for exchange binary
└── Dockerfile.webserver   # Session server container
```

## Protocol Details

### Link Packet Structure

**Discovery packet (multicast, 107 bytes):**
```
Offset 0x00: "_asdp_v" header
Offset 0x80: MEP4 (6 bytes) - IP:port for measurement endpoint
```

**Measurement packet (unicast, 25 bytes):**
```
Offset 0x00: "_link_v" header  
Contains: "__ht" (host time) for clock synchronization
```

### MEP4 Rewrite

The exchange rewrites the MEP4 field in discovery packets:
- Original: Peer's LAN IP (e.g., `192.168.1.50:20808`)
- Rewritten: Exchange's LAN IP (e.g., `172.28.1.10:20808`)

This ensures measurement packets from remote peers arrive at the exchange, which then forwards them through the relay.

## Limitations

- **Latency**: WAN latency affects sync tightness. Best results with <100ms RTT.
- **NAT**: Requires TURN relay (direct P2P via STUN not yet implemented)
- **Single session**: Exchange joins one session at a time

## Resources

- [Ableton Link](https://www.ableton.com/en/link/)
- [Cloudflare TURN](https://developers.cloudflare.com/calls/turn/)
- [AWS Lightsail Containers](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-container-services.html)