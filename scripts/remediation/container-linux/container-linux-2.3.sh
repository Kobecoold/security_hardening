#!/bin/bash
# Container remediation: Enable read-only root filesystem
# NOTE: This requires restarting the container with --read-only flag
set -euo pipefail

echo "⚠️ Container remediation: Enable read-only root filesystem"
echo ""
echo "This remediation requires restarting the container with --read-only flag."
echo ""
echo "Steps to fix:"
echo "1. Stop the current container: docker stop <container_name>"
echo "2. Remove the container: docker rm <container_name>"
echo "3. Start a new container with --read-only flag and tmpfs for writable dirs:"
echo "   docker run -d --name <container_name> --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev <other-options> <image>"
echo ""
echo "❌ Cannot fix automatically - container must be restarted with correct flags"
echo "   Current container root filesystem is writable"
exit 1
