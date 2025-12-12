#!/bin/bash
# CIS 3.2.7 - Ensure Reverse Path Filtering is enabled
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.conf.all.rp_filter 2>/dev/null | grep -q "net.ipv4.conf.all.rp_filter = 1"; then
    echo "✅ Reverse Path Filtering is already enabled - FIXED"
    exit 0
fi

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

# VERIFY: Check if fix was successful
if sysctl net.ipv4.conf.all.rp_filter 2>/dev/null | grep -q "net.ipv4.conf.all.rp_filter = 1"; then
    echo "✅ VERIFIED: Reverse Path Filtering is enabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Reverse Path Filtering is not enabled"
    exit 1
fi

