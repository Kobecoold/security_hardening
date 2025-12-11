#!/bin/bash
# CIS 2.2.4 - Ensure DHCP Server is not installed
set -euo pipefail

# Stop and disable DHCP server
systemctl stop isc-dhcp-server 2>/dev/null || true
systemctl disable isc-dhcp-server 2>/dev/null || true

# Remove if installed
if dpkg -s isc-dhcp-server >/dev/null 2>&1; then
    apt-get remove -y isc-dhcp-server
    echo "✅ DHCP Server removed"
else
    echo "ℹ️ DHCP Server is not installed (service disabled)"
fi

