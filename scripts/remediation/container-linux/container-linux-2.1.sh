#!/bin/bash
# Container remediation: Remove privileged mode
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required"
    exit 1
fi

echo "🔄 Container remediation: Remove privileged mode for container: $CONTAINER_NAME"

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

# === RUN LAI KHÔNG privileged ===
echo "> Tạo lại container không --privileged..."
docker run -d --name "$CONTAINER_NAME" $PORTS $ENVS $VOLUMES $CONTAINER_IMAGE

if [ $? -eq 0 ]; then
  echo "✅ Đã tạo lại container không có đặc quyền (no privileged)."
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
echo "👉 Manual steps to remove privileged mode:"
echo "1) Stop and remove current container:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo ""
echo "2) Start a new container WITHOUT --privileged flag, for example:"
echo "   docker run -d --name $CONTAINER_NAME \\"
echo "     <PORT_MAPPING> \\"
echo "     <VOLUMES> \\"
echo "     $CONTAINER_IMAGE"
echo ""
echo "Replace <PORT_MAPPING> and <VOLUMES> with your actual docker run options."
echo ""
echo "✅ Remediation script finished (instructions only, no changes applied)."
exit 0
