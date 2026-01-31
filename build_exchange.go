#!/bin/bash
# build_exchange.sh - Build exchange binary for macOS
#
# Usage:
#   ./build_exchange.sh           # Build for current architecture
#   ./build_exchange.sh all       # Build for both arm64 and amd64
#   ./build_exchange.sh arm64     # Build for Apple Silicon only
#   ./build_exchange.sh amd64     # Build for Intel Mac only

set -e

cd "$(dirname "$0")"

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

build_arm64() {
    echo "Building for macOS ARM64 (Apple Silicon)..."
    GOOS=darwin GOARCH=arm64 go build -ldflags "${LDFLAGS}" -o exchange-darwin-arm64 ./cmd/exchange
    echo "  -> exchange-darwin-arm64"
}

build_amd64() {
    echo "Building for macOS AMD64 (Intel)..."
    GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o exchange-darwin-amd64 ./cmd/exchange
    echo "  -> exchange-darwin-amd64"
}

build_linux_amd64() {
    echo "Building for Linux AMD64..."
    GOOS=linux GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o exchange-linux-amd64 ./cmd/exchange
    echo "  -> exchange-linux-amd64"
}

case "${1:-current}" in
    all)
        build_arm64
        build_amd64
        build_linux_amd64
        ;;
    arm64)
        build_arm64
        ;;
    amd64)
        build_amd64
        ;;
    linux)
        build_linux_amd64
        ;;
    current)
        echo "Building for current architecture..."
        go build -ldflags "${LDFLAGS}" -o exchange ./cmd/exchange
        echo "  -> exchange"
        ;;
    *)
        echo "Usage: $0 [all|arm64|amd64|linux|current]"
        exit 1
        ;;
esac

echo ""
echo "Build complete! Version: ${VERSION}"

