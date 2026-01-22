.PHONY: all build up down test clean infra links exchanges logs

# Default target
all: infra

# Build all images
build:
	docker compose build

# Start infrastructure only (TURN + session server)
infra:
	docker compose up -d turn_server session_server
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@echo "Infrastructure ready!"
	@echo "  TURN server:    172.28.0.10:3478"
	@echo "  Session server: http://localhost:8082"

# Start Link clients (without exchange bridges)
links: infra
	docker compose up -d link_a link_b
	@echo "Link clients started (isolated networks)"
	@echo "  link_a: docker exec -it link_a linkhut"
	@echo "  link_b: docker exec -it link_b linkhut"

# Start exchange bridges (enables WAN relay)
exchanges: infra
	docker compose --profile exchange up -d exchange_a exchange_b
	@echo "Exchange bridges started"
	@sleep 3
	@echo "Session IDs:"
	@docker exec exchange_a cat /home/claude/current_session_id 2>/dev/null || echo "  exchange_a: (starting...)"
	@docker exec exchange_b cat /home/claude/current_session_id 2>/dev/null || echo "  exchange_b: (starting...)"

# Start everything
up: links exchanges
	@echo ""
	@echo "Full system running!"
	@echo "Link clients should now be able to see each other."

# Run automated tests
test: build
	docker compose --profile test up --abort-on-container-exit test_runner

# View logs
logs:
	docker compose --profile exchange logs -f

# Stop everything
down:
	docker compose --profile exchange --profile test down

# Clean up everything including volumes and images
clean: down
	docker compose --profile exchange --profile test down -v --rmi local
	docker network prune -f

# Show status
status:
	@echo "=== Containers ==="
	docker compose --profile exchange ps
	@echo ""
	@echo "=== Networks ==="
	docker network ls | grep -E 'host_[ab]_net|turn_net'
	@echo ""
	@echo "=== Session Server Health ==="
	@curl -s http://localhost:8082/ || echo "(not running)"

# Shell into containers
shell-a:
	docker exec -it link_a /bin/sh

shell-b:
	docker exec -it link_b /bin/sh

shell-exchange-a:
	docker exec -it exchange_a /bin/sh

shell-exchange-b:
	docker exec -it exchange_b /bin/sh

# Watch exchange status
watch-a:
	docker exec -it exchange_a watch -n1 cat status

watch-b:
	docker exec -it exchange_b watch -n1 cat status