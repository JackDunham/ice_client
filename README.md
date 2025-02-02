- Current State
  - Have working link listener
  - Able to connect to cloudflare turn server and get receive packet
  - Have webserver which can register hosts for a session
  - Have Dockerfile for session-server

- Next steps
  - Host the session-server image...somewhere
  - Make a link-proxy app:

- Main app flow:
  - Setup TURN client
  - Get TURN relay address
  - Register TURN relay address on session-server
    - Either create new session ID or use a cli-provide session ID
    - (Periodically) Gather hosts/IPs in the session
  - Start local Link-packet listener
    - How to ignore duplicates/already-seen?
    - Forward Link packets to over host in session.Hosts
  - Start TURN relay listener
    - Adjust remote packets: frame/timeframe -- anything else
    - Send remote packets over all eligible remote interfaces


https://developers.cloudflare.com/calls/turn/generate-credentials/
