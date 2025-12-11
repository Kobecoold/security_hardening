#!/bin/bash
# CIS 3.1.1 - Disable IP forwarding
set -euo pipefail

# Set sysctl parameter
sysctl -w net.ipv4.ip_forward=0

# Make it persistent
if ! grep -q "net.ipv4.ip_forward = 0" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ IP forwarding disabled"

