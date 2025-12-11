#!/bin/bash
# CIS 2.2.6 - Ensure NFS is not installed
set -euo pipefail

# Stop and disable NFS server
systemctl stop nfs-server 2>/dev/null || true
systemctl disable nfs-server 2>/dev/null || true

# Remove if installed
if dpkg -s nfs-kernel-server >/dev/null 2>&1; then
    apt-get remove -y nfs-kernel-server
    echo "✅ NFS server removed"
else
    echo "ℹ️ NFS server is not installed (service disabled)"
fi

