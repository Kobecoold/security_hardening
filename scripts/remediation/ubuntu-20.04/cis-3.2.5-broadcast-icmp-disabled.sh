#!/bin/bash
# CIS 3.2.5 - Ensure broadcast ICMP requests are ignored
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null | grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1"; then
    echo "✅ Broadcast ICMP requests are already ignored - FIXED"
    exit 0
fi

# Set sysctl parameter
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

# Make it persistent
if ! grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null | grep -q "net.ipv4.icmp_echo_ignore_broadcasts = 1"; then
    echo "✅ VERIFIED: Broadcast ICMP requests are ignored - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Broadcast ICMP requests are not ignored"
    exit 1
fi

