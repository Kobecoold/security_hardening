#!/bin/bash
# CIS 3.2.5 - Ensure broadcast ICMP requests are ignored
set -euo pipefail

# Set sysctl parameter
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

# Make it persistent
if ! grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Broadcast ICMP requests ignored"

