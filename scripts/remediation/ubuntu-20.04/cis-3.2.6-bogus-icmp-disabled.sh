#!/bin/bash
# CIS 3.2.6 - Ensure bogus ICMP responses are ignored
set -euo pipefail

# Check if already fixed
if sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null | grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1"; then
    echo "✅ Bogus ICMP responses are already ignored - FIXED"
    exit 0
fi

# Set sysctl parameter
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# Make it persistent
if ! grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

# VERIFY: Check if fix was successful
if sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null | grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1"; then
    echo "✅ VERIFIED: Bogus ICMP responses are ignored - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Bogus ICMP responses are not ignored"
    exit 1
fi

