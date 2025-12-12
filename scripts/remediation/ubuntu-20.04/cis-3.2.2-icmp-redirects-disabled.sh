#!/bin/bash
# CIS 3.2.2 - Ensure ICMP redirects are not accepted
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.accept_redirects = 0"; then
    echo "✅ ICMP redirects are already disabled - FIXED"
    exit 0
fi

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# Make it persistent
if ! grep -q "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.accept_redirects = 0"; then
    echo "✅ VERIFIED: ICMP redirects are disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: ICMP redirects are not disabled"
    exit 1
fi

