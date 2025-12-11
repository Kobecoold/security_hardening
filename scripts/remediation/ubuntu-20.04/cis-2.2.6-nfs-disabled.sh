#!/bin/bash
# CIS 2.2.6 - Ensure NFS is not installed
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

# Stop and disable NFS server (with timeout)
timeout 30 systemctl stop nfs-server 2>/dev/null || true
timeout 30 systemctl disable nfs-server 2>/dev/null || true

# Remove if installed (with timeout and lock check)
if dpkg -s nfs-kernel-server >/dev/null 2>&1; then
    wait_for_apt || exit 1
    timeout 60 apt-get remove -y nfs-kernel-server || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq nfs-kernel-server 2>/dev/null || true
    }
    echo "✅ NFS server removed"
else
    echo "ℹ️ NFS server is not installed (service disabled)"
fi

