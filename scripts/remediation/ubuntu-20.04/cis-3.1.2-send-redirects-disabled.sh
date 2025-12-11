#!/bin/bash
# CIS 3.1.2 - Disable send packet redirects
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.conf.all.send_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.send_redirects = 0"; then
    echo "✅ Send packet redirects are already disabled - FIXED"
    exit 0
fi

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# Make it persistent
if ! grep -q "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.conf.all.send_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.send_redirects = 0"; then
    echo "✅ VERIFIED: Send packet redirects are disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Send packet redirects are not disabled"
    exit 1
fi

