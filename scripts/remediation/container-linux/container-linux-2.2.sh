#!/bin/bash
# Container remediation: Remove dangerous capabilities (SYS_ADMIN, NET_ADMIN)
# NOTE: This requires restarting the container with --cap-drop flags
set -euo pipefail

echo "⚠️ Container remediation: Remove dangerous capabilities"
echo ""
echo "This remediation requires restarting the container with --cap-drop flags."
echo ""
echo "Steps to fix:"
echo "1. Stop the current container: docker stop <container_name>"
echo "2. Remove the container: docker rm <container_name>"
echo "3. Start a new container with --cap-drop flags:"
echo "   docker run -d --name <container_name> --cap-drop SYS_ADMIN --cap-drop NET_ADMIN <other-options> <image>"
echo ""
echo "❌ Cannot fix automatically - container must be restarted with correct flags"
echo "   Current container has dangerous capabilities"
exit 1
