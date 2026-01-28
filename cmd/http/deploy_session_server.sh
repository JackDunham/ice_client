#!/bin/sh
# deploy_session_server.sh - Build and deploy session server to AWS Lightsail
#
# Usage:
#   1. Create a .env file with:
#      CLOUDFLARE_BEARER_TOKEN=your-token
#      BASIC_AUTH_USER=admin
#      BASIC_AUTH_PASSWORD=your-password
#
#   2. Run: ./deploy_session_server.sh
#
# Prerequisites:
#   - AWS CLI configured with appropriate credentials
#   - lightsailctl plugin installed
#   - Docker installed

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=============================================="
echo "Session Server Deployment"
echo "=============================================="

# Load .env file if it exists
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading configuration from .env file..."
    . "$ENV_FILE"
else
    echo "No .env file found at $ENV_FILE"
    echo "Checking environment variables..."
fi

# Check for required token
if [ -z "$CLOUDFLARE_BEARER_TOKEN" ]; then
    echo "ERROR: CLOUDFLARE_BEARER_TOKEN not set"
    echo ""
    echo "Create a .env file in $SCRIPT_DIR with:"
    echo "  CLOUDFLARE_BEARER_TOKEN=your-cloudflare-api-token"
    echo "  BASIC_AUTH_USER=admin"
    echo "  BASIC_AUTH_PASSWORD=your-password"
    exit 1
fi

# Set defaults for auth if not provided
BASIC_AUTH_USER="${BASIC_AUTH_USER:-admin}"
BASIC_AUTH_PASSWORD="${BASIC_AUTH_PASSWORD:-secret}"

# Configuration
SERVICE_NAME="link-session-service"
IMAGE_LABEL="session-server-img-3"
REGION="us-west-2"

# Get short git SHA for tagging
GIT_SHA=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD)
IMAGE_TAG="session-server:${GIT_SHA}"

echo "[1/4] Building Docker image ($IMAGE_TAG)..."
cd "$PROJECT_ROOT"
docker buildx build -f Dockerfile.webserver --platform linux/amd64 -t "$IMAGE_TAG" --load .

echo "[2/4] Pushing image to Lightsail..."
aws lightsail push-container-image \
    --region "$REGION" \
    --service-name "$SERVICE_NAME" \
    --label "$IMAGE_LABEL" \
    --image "$IMAGE_TAG"

# Get the full image name from Lightsail
echo "[3/4] Getting image reference..."
IMAGE_REF=$(aws lightsail get-container-images \
    --region "$REGION" \
    --service-name "$SERVICE_NAME" \
    --query "containerImages[?contains(image, '$IMAGE_LABEL')]|[0].image" \
    --output text)

if [ -z "$IMAGE_REF" ] || [ "$IMAGE_REF" = "None" ]; then
    echo "ERROR: Could not find pushed image"
    exit 1
fi
echo "    Image reference: $IMAGE_REF"

echo "[4/4] Deploying to Lightsail..."
aws lightsail create-container-service-deployment \
    --region "$REGION" \
    --service-name "$SERVICE_NAME" \
    --containers "{\"link-session-service\": {\"image\": \"$IMAGE_REF\", \"command\": [], \"environment\": {\"CLOUDFLARE_BEARER_TOKEN\": \"$CLOUDFLARE_BEARER_TOKEN\", \"BASIC_AUTH_USER\": \"$BASIC_AUTH_USER\", \"BASIC_AUTH_PASSWORD\": \"$BASIC_AUTH_PASSWORD\"}, \"ports\": {\"8082\": \"HTTP\"}}}" \
    --public-endpoint file://"$SCRIPT_DIR/public-endpoint.json"

echo ""
echo "=============================================="
echo "Deployment initiated!"
echo "=============================================="
echo ""
echo "Auth configured as: $BASIC_AUTH_USER / ********"
echo ""
echo "Monitor status with:"
echo "  aws lightsail get-container-services --service-name $SERVICE_NAME --region $REGION"
echo ""
echo "Service URL:"
echo "  https://link-session-service.nrr4m2c4w38qw.us-west-2.cs.amazonlightsail.com/"
echo ""
echo "Endpoints:"
echo "  GET  /                    - Health check (no auth)"
echo "  GET  /turn/credentials    - Get Cloudflare TURN credentials (basic auth)"
echo "  POST /session             - Create session (basic auth)"
echo "  PUT  /session/<uuid>      - Join/update session (basic auth)"
echo "  GET  /session/<uuid>      - Get session hosts (basic auth)"