#!/bin/bash
# CIS 3.2.7 - Ensure Reverse Path Filtering is enabled
set -euo pipefail

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Make it persistent
if ! grep -q "net.ipv4.conf.all.rp_filter = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.rp_filter = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Reverse Path Filtering enabled"

