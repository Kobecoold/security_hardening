#!/bin/bash
# CIS 2.2.1 - Ensure X Window System is not installed
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

# Remove X11 packages if installed (with timeout and lock check)
if dpkg -l | grep -E "^ii\s+xserver-xorg" >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 120 apt-get remove -y xserver-xorg* || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq xserver-xorg* 2>/dev/null || true
    }
    echo "✅ X Window System removed"
else
    echo "ℹ️ X Window System is not installed"
fi

# VERIFY: Check if fix was successful
if ! dpkg -l | grep -E "^ii\s+xserver-xorg" | grep -q xserver; then
    echo "✅ VERIFIED: X Window System is not installed - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: X Window System is still installed"
    exit 1
fi

