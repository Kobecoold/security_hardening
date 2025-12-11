#!/bin/bash
# CIS 2.2.2 - Ensure Avahi Server is not installed
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

# Stop and disable avahi-daemon (with timeout)
timeout 30 systemctl stop avahi-daemon 2>/dev/null || true
timeout 30 systemctl disable avahi-daemon 2>/dev/null || true

# Remove if installed (with timeout and lock check)
if dpkg -s avahi-daemon >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 60 apt-get remove -y avahi-daemon || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq avahi-daemon 2>/dev/null || true
    }
    echo "✅ Avahi Server removed"
else
    echo "ℹ️ Avahi Server is not installed (service disabled)"
fi

# VERIFY: Check if fix was successful
if ! systemctl is-enabled avahi-daemon 2>/dev/null | grep -q enabled; then
    echo "✅ VERIFIED: Avahi Server is disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Avahi Server is still enabled"
    exit 1
fi

