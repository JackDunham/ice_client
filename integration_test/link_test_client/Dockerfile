# Build stage for Link test client
# Uses essaim.dev/al which provides Go bindings for Ableton Link via CGo
FROM golang:1.23-bookworm AS builder

# Use container's Go version, don't download toolchain
ENV GOTOOLCHAIN=local

# Install build dependencies for Link C++ library
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libasound2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clone Ableton Link for the C++ headers
RUN git clone --recursive https://github.com/Ableton/link.git /opt/link

WORKDIR /app

# Copy source files
COPY . .

# Get dependencies - essaim.dev/al vendors the Link C++ code
RUN go mod tidy && go mod download

# Build with CGO enabled, pointing to Link headers
# Link includes its own copy of ASIO in modules/asio-standalone/asio/include
# Link requires C++11 or higher
ENV CGO_CXXFLAGS="-std=c++11 -I/opt/link/include -I/opt/link/modules/asio-standalone/asio/include"
ENV CGO_CFLAGS="-I/opt/link/include"
RUN CGO_ENABLED=1 go build -o /link_test_client .

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libasound2 \
    ca-certificates \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /link_test_client /usr/local/bin/link_test_client

ENTRYPOINT ["link_test_client"]