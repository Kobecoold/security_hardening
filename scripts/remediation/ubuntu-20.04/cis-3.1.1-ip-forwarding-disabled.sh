#!/bin/bash
# CIS 3.1.1 - Disable IP forwarding
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "net.ipv4.ip_forward = 0"; then
    echo "✅ IP forwarding is already disabled - FIXED"
    exit 0
fi

# Set sysctl parameter
sysctl -w net.ipv4.ip_forward=0

# Make it persistent
if ! grep -q "net.ipv4.ip_forward = 0" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "net.ipv4.ip_forward = 0"; then
    echo "✅ VERIFIED: IP forwarding is disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: IP forwarding is not disabled"
    exit 1
fi

