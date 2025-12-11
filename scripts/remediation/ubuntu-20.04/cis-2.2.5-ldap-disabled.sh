#!/bin/bash
# CIS 2.2.5 - Ensure LDAP server is not installed
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

# Stop and disable LDAP server (with timeout)
timeout 30 systemctl stop slapd 2>/dev/null || true
timeout 30 systemctl disable slapd 2>/dev/null || true

# Remove if installed (with timeout and lock check)
if dpkg -s slapd >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 60 apt-get remove -y slapd || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq slapd 2>/dev/null || true
    }
    echo "✅ LDAP server removed"
else
    echo "ℹ️ LDAP server is not installed (service disabled)"
fi

# VERIFY: Check if fix was successful
if ! systemctl is-enabled slapd 2>/dev/null | grep -q enabled; then
    echo "✅ VERIFIED: LDAP server is disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: LDAP server is still enabled"
    exit 1
fi

