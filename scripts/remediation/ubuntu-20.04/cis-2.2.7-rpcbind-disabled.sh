#!/bin/bash
# CIS 2.2.7 - Ensure rpcbind is not installed
set -euo pipefail

# Stop and disable rpcbind
systemctl stop rpcbind 2>/dev/null || true
systemctl disable rpcbind 2>/dev/null || true

# Remove if installed
if dpkg -s rpcbind >/dev/null 2>&1; then
    apt-get remove -y rpcbind
    echo "✅ rpcbind removed"
else
    echo "ℹ️ rpcbind is not installed (service disabled)"
fi

