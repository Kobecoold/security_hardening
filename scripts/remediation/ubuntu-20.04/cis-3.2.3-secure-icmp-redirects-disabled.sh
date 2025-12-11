#!/bin/bash
# CIS 3.2.3 - Ensure secure ICMP redirects are not accepted
set -euo pipefail

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0

# Make it persistent
if ! grep -q "net.ipv4.conf.all.secure_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.secure_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Secure ICMP redirects disabled"

