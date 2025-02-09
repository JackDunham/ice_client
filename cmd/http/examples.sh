#!/bin/bash

AUTH_USER=admin;
AUTH_PASS=secret;
AUTH_VALUE=$(echo -n "${AUTH_USER}:${AUTH_PASS}" | base64);
AUTH_HEADER="Authorization: Basic ${AUTH_VALUE}";
SESSION_HOST="https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com"
__SESSION_HOST="http://loclhost:8082"

# curl -s -X POST -u admin:secret -H "Content-Type: application/json" -d '{"host": "1.2.3.4:5678"}' http://localhost:8082/session | jq .session_id
SESSION_ID=$(curl -s -X POST -H "${AUTH_HEADER}" -H "Content-Type: application/json" -d '{"host": "1.2.3.4:5678"}' "${SESSION_HOST}/session" | jq .session_id | tr -d '"')

curl -X PUT -H "${AUTH_HEADER}" -H "Content-Type: application/json" -d '{"host": "2.3.4.5:6789"}' "http://localhost:8082/session/${SESSION_ID}"

curl -X GET -H "${AUTH_HEADER}" "http://localhost:8082/session/${SESSION_ID}"

