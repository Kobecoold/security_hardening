#!/bin/bash
# Container remediation: Remove dangerous capabilities (SYS_ADMIN, NET_ADMIN)
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required"
    exit 1
fi

echo "🔄 Container remediation: Remove dangerous capabilities for container: $CONTAINER_NAME"

# Kiểm tra container tồn tại
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "❌ Container $CONTAINER_NAME not found"
    exit 1
fi

# === LẤY THÔNG TIN CONTAINER CŨ ===
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}')
PORTS=$(docker port "$CONTAINER_NAME" | awk '{printf "-p %s ", $1}')
ENVS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{printf "-e \"%s\" " .}}{{end}}')
VOLUMES=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{printf "-v %s:%s " .Source .Destination}}{{end}}')

# === XÓA CONTAINER CŨ ===
echo "> Dừng & xoá container cũ..."
docker stop "$CONTAINER_NAME"
docker rm "$CONTAINER_NAME"

# === RUN LAI VỚI --cap-drop ===
echo "> Tạo lại container với --cap-drop SYS_ADMIN --cap-drop NET_ADMIN ..."
docker run -d --name "$CONTAINER_NAME" --cap-drop SYS_ADMIN --cap-drop NET_ADMIN $PORTS $ENVS $VOLUMES $CONTAINER_IMAGE

if [ $? -eq 0 ]; then
  echo "✅ Đã tạo lại container đã drop SYS_ADMIN/NET_ADMIN."
  exit 0
else
  echo "❌ Lỗi khi tạo lại container."
  exit 1
fi

CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}' 2>/dev/null || echo "")

echo ""
echo "📋 Current container image: $CONTAINER_IMAGE"
echo ""
echo "⚠️ AUTO-ACTION DISABLED"
echo "This script does NOT automatically restart the container anymore."
echo ""
echo "👉 Manual steps to drop dangerous capabilities (SYS_ADMIN, NET_ADMIN):"
echo "1) Stop and remove current container:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo ""
echo "2) Start a new container with --cap-drop flags, for example:"
echo "   docker run -d --name $CONTAINER_NAME \\"
echo "     --cap-drop SYS_ADMIN --cap-drop NET_ADMIN \\"
echo "     <OTHER_OPTIONS> \\"
echo "     $CONTAINER_IMAGE"
echo ""
echo "Replace <OTHER_OPTIONS> with your actual port/volume/env options."
echo ""
echo "✅ Remediation script finished (instructions only, no changes applied)."
exit 0
