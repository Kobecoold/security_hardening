#!/bin/bash
# CIS 3.2.3 - Ensure secure ICMP redirects are not accepted
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.secure_redirects = 0"; then
    echo "✅ Secure ICMP redirects are already disabled - FIXED"
    exit 0
fi

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

# VERIFY: Check if fix was successful
if sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null | grep -q "net.ipv4.conf.all.secure_redirects = 0"; then
    echo "✅ VERIFIED: Secure ICMP redirects are disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Secure ICMP redirects are not disabled"
    exit 1
fi

