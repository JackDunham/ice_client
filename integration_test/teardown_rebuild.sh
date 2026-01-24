#!/bin/sh


# Nuclear teardown
docker rm -f $(docker ps -aq) 2>/dev/null
docker system prune -a --volumes -f

# Rebuild ALL images
docker compose build

