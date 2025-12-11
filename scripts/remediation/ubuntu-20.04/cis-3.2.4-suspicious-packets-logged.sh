#!/bin/bash
# CIS 3.2.4 - Ensure suspicious packets are logged
set -euo pipefail

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# Make it persistent
if ! grep -q "net.ipv4.conf.all.log_martians = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.log_martians = 1" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Suspicious packets logging enabled"

