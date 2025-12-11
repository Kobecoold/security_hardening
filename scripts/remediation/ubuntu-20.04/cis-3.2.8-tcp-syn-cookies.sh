#!/bin/bash
# CIS 3.2.8 - Ensure TCP SYN Cookies is enabled
set -euo pipefail

# Set sysctl parameter
sysctl -w net.ipv4.tcp_syncookies=1

# Make it persistent
if ! grep -q "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ TCP SYN Cookies enabled"

