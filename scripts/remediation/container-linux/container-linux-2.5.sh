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

echo "📋 Step 2: Gathering container information (read-only)..."
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo "")
PORTS_RAW=$(docker port "$CONTAINER_NAME" 2>/dev/null || echo "")
ENV_VARS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || echo "")
VOLUMES=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{println .Source}} -> {{println .Destination}}{{end}}' 2>/dev/null || echo "")

echo "✅ Container image: $CONTAINER_IMAGE"
echo ""
echo "📋 Port mappings:"
echo "$PORTS_RAW"
echo ""
echo "📋 Volumes:"
echo "$VOLUMES"
echo ""
echo "📋 Environment variables:"
echo "$ENV_VARS"
echo ""
echo "> Tự động sửa (auto remediation): Thêm --security-opt no-new-privileges:true"
echo "This script now ONLY prints configuration and a sample command."
echo ""
echo "👉 Manual remediation steps for enabling no-new-privileges:"
echo "1) Stop and remove current container:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo ""
echo "2) Start a new container with no-new-privileges, for example:"
echo "   docker run -d --name $CONTAINER_NAME \\"
echo "     --security-opt no-new-privileges:true \\"
echo "     <PORTS> \\"
echo "     <VOLUMES> \\"
echo "     <ENV_VARS> \\"
echo "     $CONTAINER_IMAGE"
echo ""
echo "Fill <PORTS>, <VOLUMES>, <ENV_VARS> from the configuration printed above."
echo ""
echo "=========================================="
echo "✅ Remediation script finished (instructions only, no changes applied)."
echo "=========================================="
exit 0
