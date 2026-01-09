#!/bin/bash
# Container remediation: Remove /var/run/docker.sock mount
# NOTE: This requires restarting the container without docker.sock mount
set -euo pipefail

echo "⚠️ Container remediation: Remove /var/run/docker.sock mount"
echo ""
echo "This remediation requires restarting the container without docker.sock mount."
echo ""
echo "Steps to fix:"
echo "1. Stop the current container: docker stop <container_name>"
echo "2. Remove the container: docker rm <container_name>"
echo "3. Start a new container WITHOUT -v /var/run/docker.sock:/var/run/docker.sock:"
echo "   docker run -d --name <container_name> <other-options> <image>"
echo "   (Remove any -v /var/run/docker.sock mount from your docker run command)"
echo ""
echo "❌ Cannot fix automatically - container must be restarted without docker.sock mount"
echo "   Current container has /var/run/docker.sock mounted"
exit 1
