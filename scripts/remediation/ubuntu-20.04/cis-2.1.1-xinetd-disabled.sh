#!/bin/bash
# CIS 2.1.1 - Ensure xinetd is not installed
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

# Remove xinetd if installed (with timeout and lock check)
if dpkg -s xinetd >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 60 apt-get remove -y xinetd || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq xinetd 2>/dev/null || true
    }
    echo "✅ xinetd removed"
else
    echo "ℹ️ xinetd is not installed"
fi

# VERIFY: Check if fix was successful
if ! dpkg -s xinetd 2>/dev/null | grep -q "Status: install"; then
    echo "✅ VERIFIED: xinetd is not installed - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: xinetd is still installed"
    exit 1
fi

