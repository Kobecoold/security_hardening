#!/bin/bash
# CIS 2.2.3 - Ensure CUPS is not installed
set -euo pipefail

# Stop and disable CUPS
systemctl stop cups 2>/dev/null || true
systemctl disable cups 2>/dev/null || true

# Remove if installed
if dpkg -s cups >/dev/null 2>&1; then
    apt-get remove -y cups
    echo "✅ CUPS removed"
else
    echo "ℹ️ CUPS is not installed (service disabled)"
fi

