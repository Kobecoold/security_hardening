#!/bin/bash
# Container remediation: Enable read-only root filesystem
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required"
    exit 1
fi

echo "🔄 Container remediation: Enable read-only root filesystem for container: $CONTAINER_NAME"

# Kiểm tra container tồn tại
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "❌ Container $CONTAINER_NAME not found"
    exit 1
fi

# Lấy thông tin container hiện tại
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo "")
if [ -z "$CONTAINER_IMAGE" ]; then
    echo "❌ Cannot get container image"
    exit 1
fi

# Lấy ports, volumes, env
PORTS=$(docker port "$CONTAINER_NAME" 2>/dev/null | awk '{print $1}' | cut -d: -f1 | sort -u | head -1 || echo "")
ENV_VARS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || echo "")

# Build docker run command với --read-only và tmpfs
NEW_CONTAINER_NAME="${CONTAINER_NAME}_fixed_$(date +%s)"

echo "📋 Creating new container with read-only root filesystem..."

DOCKER_CMD="docker run -d --name $NEW_CONTAINER_NAME"
DOCKER_CMD="$DOCKER_CMD --read-only"
DOCKER_CMD="$DOCKER_CMD --tmpfs /tmp:rw,noexec,nosuid,nodev"
DOCKER_CMD="$DOCKER_CMD --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev"
DOCKER_CMD="$DOCKER_CMD --tmpfs /var/run:rw,noexec,nosuid,nodev"
DOCKER_CMD="$DOCKER_CMD --tmpfs /var/log/nginx:rw,noexec,nosuid,nodev"

# Thêm ports nếu có
if [ -n "$PORTS" ]; then
    DOCKER_CMD="$DOCKER_CMD -p $PORTS:$PORTS"
fi

# Thêm env vars nếu có
if [ -n "$ENV_VARS" ]; then
    while IFS= read -r env_line; do
        [ -n "$env_line" ] && DOCKER_CMD="$DOCKER_CMD -e \"$env_line\""
    done <<< "$ENV_VARS"
fi

DOCKER_CMD="$DOCKER_CMD $CONTAINER_IMAGE"

echo "🚀 Executing: $DOCKER_CMD"
eval "$DOCKER_CMD" || {
    echo "❌ Failed to create new container"
    exit 1
}

echo "✅ New container $NEW_CONTAINER_NAME created with read-only root filesystem"
echo "⚠️  Please stop old container and rename new one:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo "   docker rename $NEW_CONTAINER_NAME $CONTAINER_NAME"
echo ""
echo "✅ Remediation completed - new container created with read-only root filesystem"
exit 0
