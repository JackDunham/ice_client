#!/bin/sh

docker compose --profile exchange down -v
docker compose down -v
docker network prune -f
make up

