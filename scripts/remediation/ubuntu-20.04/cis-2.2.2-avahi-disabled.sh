#!/bin/bash
# CIS 2.2.2 - Ensure Avahi Server is not installed
set -euo pipefail

# Stop and disable avahi-daemon
systemctl stop avahi-daemon 2>/dev/null || true
systemctl disable avahi-daemon 2>/dev/null || true

# Remove if installed
if dpkg -s avahi-daemon >/dev/null 2>&1; then
    apt-get remove -y avahi-daemon
    echo "✅ Avahi Server removed"
else
    echo "ℹ️ Avahi Server is not installed (service disabled)"
fi

