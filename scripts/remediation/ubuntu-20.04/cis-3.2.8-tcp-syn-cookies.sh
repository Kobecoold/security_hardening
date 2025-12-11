#!/bin/bash
# CIS 3.2.8 - Ensure TCP SYN Cookies is enabled
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "net.ipv4.tcp_syncookies = 1"; then
    echo "✅ TCP SYN Cookies is already enabled - FIXED"
    exit 0
fi

# Set sysctl parameter
sysctl -w net.ipv4.tcp_syncookies=1

# Make it persistent
if ! grep -q "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "net.ipv4.tcp_syncookies = 1"; then
    echo "✅ VERIFIED: TCP SYN Cookies is enabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: TCP SYN Cookies is not enabled"
    exit 1
fi

