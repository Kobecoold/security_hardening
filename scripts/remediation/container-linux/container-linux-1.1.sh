#!/bin/bash
# Remediation: Ensure container not running as root user (container-linux-1.1)
# Script chạy trên HOST (không phải trong container)
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-}"
if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ CONTAINER_NAME environment variable is required"
    exit 1
fi

echo "🔄 Remediating: Ensure container is NOT running as root (UID 0)"

# Kiểm tra container tồn tại
if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "❌ Container $CONTAINER_NAME not found"
    exit 1
fi

# Lấy lại cấu hình container cũ
IMAGE=$(docker inspect "$CONTAINER_NAME" --format '{{.Config.Image}}')
PORTS=$(docker port "$CONTAINER_NAME" | awk '{printf "-p %s ", $1}')
ENVS=$(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{printf "-e \"%s\" " .}}{{end}}')
VOLUMES=$(docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{printf "-v %s:%s " .Source .Destination}}{{end}}')

# Xoá container cũ
docker stop "$CONTAINER_NAME"
docker rm "$CONTAINER_NAME"

echo "> Tạo lại container với user non-root (65534:65534/nobody) ..."
docker run -d --name "$CONTAINER_NAME" --user 65534:65534 $PORTS $ENVS $VOLUMES $IMAGE

if [ $? -eq 0 ]; then
    echo "✅ Đã tạo lại container KHÔNG chạy bằng root user."
    exit 0
else
    echo "❌ Lỗi khi tạo lại container."
    exit 1
fi
