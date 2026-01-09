#!/bin/bash
# Container remediation: Remove /var/run/docker.sock mount
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required"
    exit 1
fi

echo "🔄 Container remediation: Remove /var/run/docker.sock mount for container: $CONTAINER_NAME"

# Kiểm tra container tồn tại
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "❌ Container $CONTAINER_NAME not found"
    exit 1
fi

# Chỉ log cấu hình và hướng dẫn, KHÔNG auto chạy docker run
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo "")

echo ""
echo "📋 Current container image: $CONTAINER_IMAGE"
echo ""
echo "⚠️ AUTO-ACTION DISABLED"
echo "This script does NOT automatically restart the container anymore."
echo ""
echo "👉 Manual steps to remove /var/run/docker.sock mount:"
echo "1) Stop and remove current container:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo ""
echo "2) Start a new container WITHOUT docker.sock mount, for example:"
echo "   docker run -d --name $CONTAINER_NAME \\"
echo "     <PORTS_AND_VOLUMES_WITHOUT_DOCKER_SOCK> \\"
echo "     $CONTAINER_IMAGE"
echo ""
echo "Ensure that you REMOVE any '-v /var/run/docker.sock:/var/run/docker.sock' from your docker run command."
echo ""
echo "✅ Remediation script finished (instructions only, no changes applied)."
exit 0
