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

# === LẤY THÔNG TIN CONTAINER CŨ ===
CONTAINER_IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}')
PORTS=$(docker port "$CONTAINER_NAME" | awk '{printf "-p %s ", $1}')
ENVS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{printf "-e \"%s\" " .}}{{end}}')
VOLUMES=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{if and (ne .Destination "/tmp") (ne .Destination "/var/cache/nginx") (ne .Destination "/var/run") (ne .Destination "/var/log/nginx")}}{{printf "-v %s:%s " .Source .Destination}}{{end}}{{end}}')

# === XÓA CONTAINER CŨ ===
echo "> Dừng & xoá container cũ..."
docker stop "$CONTAINER_NAME"
docker rm "$CONTAINER_NAME"

# === RUN LAI VỚI --read-only & tmpfs ===
echo "> Tạo lại container với --read-only (và đủ tmpfs cho nginx)..."
docker run -d --name "$CONTAINER_NAME" --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev \
  --tmpfs /var/run:rw,noexec,nosuid,nodev \
  --tmpfs /var/log/nginx:rw,noexec,nosuid,nodev $PORTS $ENVS $VOLUMES $CONTAINER_IMAGE

if [ $? -eq 0 ]; then
  echo "✅ Đã tạo lại container --read-only."
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
echo "👉 Manual steps to enable read-only root filesystem:"
echo "1) Stop and remove current container:"
echo "   docker stop $CONTAINER_NAME"
echo "   docker rm $CONTAINER_NAME"
echo ""
echo "2) Start a new container with --read-only and tmpfs for writable dirs, for example:"
echo "   docker run -d --name $CONTAINER_NAME \\"
echo "     --read-only \\"
echo "     --tmpfs /tmp:rw,noexec,nosuid,nodev \\"
echo "     --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev \\"
echo "     --tmpfs /var/run:rw,noexec,nosuid,nodev \\"
echo "     --tmpfs /var/log/nginx:rw,noexec,nosuid,nodev \\"
echo "     <OTHER_OPTIONS> \\"
echo "     $CONTAINER_IMAGE"
echo ""
echo "Replace <OTHER_OPTIONS> with your actual port/volume/env options."
echo ""
echo "✅ Remediation script finished (instructions only, no changes applied)."
exit 0
