#!/bin/bash
# CIS 3.2.4 - Ensure suspicious packets are logged
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q "net.ipv4.conf.all.log_martians = 1"; then
    echo "✅ Suspicious packets logging is already enabled - FIXED"
    exit 0
fi

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

# VERIFY: Check if fix was successful
if sysctl net.ipv4.conf.all.log_martians 2>/dev/null | grep -q "net.ipv4.conf.all.log_martians = 1"; then
    echo "✅ VERIFIED: Suspicious packets logging is enabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Suspicious packets logging is not enabled"
    exit 1
fi

