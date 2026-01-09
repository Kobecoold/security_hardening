#!/bin/bash
# Container remediation: Enable no-new-privileges security option
# NOTE: This requires restarting the container with --security-opt no-new-privileges:true
set -euo pipefail

echo "⚠️ Container remediation: Enable no-new-privileges"
echo ""
echo "This remediation requires restarting the container with --security-opt flag."
echo ""
echo "Steps to fix:"
echo "1. Stop the current container: docker stop <container_name>"
echo "2. Remove the container: docker rm <container_name>"
echo "3. Start a new container with --security-opt no-new-privileges:true:"
echo "   docker run -d --name <container_name> --security-opt no-new-privileges:true <other-options> <image>"
echo ""
echo "❌ Cannot fix automatically - container must be restarted with correct flags"
echo "   Current container does not have no-new-privileges enabled"
exit 1
