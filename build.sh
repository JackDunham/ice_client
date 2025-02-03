#!/bin/bash
# TARGET linux/amd64/v4
#docker build -f Dockerfile.webserver -t linkwebserver:latest .
docker buildx build -f Dockerfile.webserver --platform linux/amd64 -t session-server:latest --load .

#docker run -p 8082:8082 linkwebserver:1
#docker images
#docker save -o session_server.tar 5d1332269f0a

