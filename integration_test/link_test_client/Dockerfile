# Build stage for Link test client
# Uses essaim.dev/al which provides Go bindings for Ableton Link via CGo
FROM golang:1.23-bookworm AS builder

# Install build dependencies for Link C++ library
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libasound2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy go module files
COPY go.mod ./

# Download the essaim.dev/al module (includes vendored Link C++ code)
RUN go mod download essaim.dev/al || true

# Copy source
COPY . .

# Build with CGO enabled
RUN CGO_ENABLED=1 go build -o /link_test_client .

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libasound2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /link_test_client /usr/local/bin/link_test_client

ENTRYPOINT ["link_test_client"]