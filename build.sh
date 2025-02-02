#!/bin/bash

docker build -f Dockerfile.webserver -t linkwebserver:latest .
docker run -p 8082:8082 linkwebserver:1

