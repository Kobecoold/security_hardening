#!/bin/bash
# Container remediation: Enable no-new-privileges security option
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

# Force output to stdout và stderr (không buffer)
# Đảm bảo tất cả output đều được gửi ra stdout/stderr
exec >&1 2>&1

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required" >&2
    exit 1
fi

echo "=========================================="
echo "🔄 Container Remediation Script"
echo "Rule: container-linux-2.5 (no-new-privileges)"
echo "Container: $CONTAINER_NAME"
echo "=========================================="
echo ""

# Kiểm tra container tồn tại
echo "📋 Step 1: Checking if container exists..."
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "❌ Container $CONTAINER_NAME not found"
    exit 1
fi
echo "✅ Container $CONTAINER_NAME found"
echo ""

# Lấy thông tin container hiện tại
echo "📋 Step 2: Gathering container information..."
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo "")
if [ -z "$CONTAINER_IMAGE" ]; then
    echo "❌ Cannot get container image"
    exit 1
fi
echo "✅ Container image: $CONTAINER_IMAGE"

# Lấy ports, volumes, env, và các options khác
echo "📋 Step 3: Extracting container configuration..."
PORTS=$(docker port "$CONTAINER_NAME" 2>/dev/null | awk '{print $1}' | cut -d: -f1 | sort -u | head -1 || echo "")
ENV_VARS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || echo "")
VOLUMES=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{println .Source}}:{{println .Destination}}{{end}}' 2>/dev/null || echo "")

if [ -n "$PORTS" ]; then
    echo "✅ Port mapping: $PORTS"
else
    echo "ℹ️  No port mapping found"
fi

# Build docker run command với no-new-privileges
NEW_CONTAINER_NAME="${CONTAINER_NAME}_fixed_$(date +%s)"
echo ""
echo "📋 Step 4: Creating new container with no-new-privileges enabled..."
echo "   New container name: $NEW_CONTAINER_NAME"

# Build command
DOCKER_CMD="docker run -d --name $NEW_CONTAINER_NAME"
DOCKER_CMD="$DOCKER_CMD --security-opt no-new-privileges:true"

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

echo ""
echo "🚀 Step 5: Executing docker run command..."
echo "   Command: $DOCKER_CMD"
echo ""

# Execute và capture output
if eval "$DOCKER_CMD" 2>&1; then
    NEW_CONTAINER_ID=$(docker ps -a --filter "name=$NEW_CONTAINER_NAME" --format "{{.ID}}" | head -1)
    echo ""
    echo "✅ SUCCESS: New container created!"
    echo "   Container ID: $NEW_CONTAINER_ID"
    echo "   Container name: $NEW_CONTAINER_NAME"
    echo ""
    echo "=========================================="
    echo "⚠️  NEXT STEPS (Manual):"
    echo "=========================================="
    echo "1. Stop the old container:"
    echo "   docker stop $CONTAINER_NAME"
    echo ""
    echo "2. Remove the old container:"
    echo "   docker rm $CONTAINER_NAME"
    echo ""
    echo "3. Rename the new container:"
    echo "   docker rename $NEW_CONTAINER_NAME $CONTAINER_NAME"
    echo ""
    echo "4. Start the new container:"
    echo "   docker start $CONTAINER_NAME"
    echo ""
    echo "=========================================="
    echo "✅ Remediation script completed successfully!"
    echo "=========================================="
    exit 0
else
    echo ""
    echo "❌ FAILED: Could not create new container"
    echo "   Please check Docker permissions and container configuration"
    exit 1
fi
