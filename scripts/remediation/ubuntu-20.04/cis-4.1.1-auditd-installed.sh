#!/bin/bash
# CIS 4.1.1 - Ensure auditd is installed
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

# Install auditd if not installed (with timeout and lock check)
if ! dpkg -s auditd >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 120 apt-get update || echo "⚠️ apt-get update timeout"
    timeout 120 apt-get install -y auditd || {
        echo "⚠️ apt-get install timeout or error"
        exit 1
    }
    echo "✅ auditd installed"
else
    echo "ℹ️ auditd is already installed"
fi

# VERIFY: Check if fix was successful
if dpkg -s auditd 2>/dev/null | grep -q "Status: install"; then
    echo "✅ VERIFIED: auditd is installed - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: auditd is not installed"
    exit 1
fi

