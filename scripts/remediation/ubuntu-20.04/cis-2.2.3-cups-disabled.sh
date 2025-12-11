#!/bin/bash
# CIS 2.2.3 - Ensure CUPS is not installed
set -euo pipefail

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

# Wait for apt lock (max 30s)
wait_for_apt() {
    local max_wait=30
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -ge $max_wait ]; then
            echo "⚠️ apt lock timeout after ${max_wait}s"
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 0
}

# Stop and disable CUPS (with timeout)
timeout 30 systemctl stop cups 2>/dev/null || true
timeout 30 systemctl disable cups 2>/dev/null || true

# Remove if installed (with timeout and lock check)
if dpkg -s cups >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 60 apt-get remove -y cups || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq cups 2>/dev/null || true
    }
    echo "✅ CUPS removed"
else
    echo "ℹ️ CUPS is not installed (service disabled)"
fi

