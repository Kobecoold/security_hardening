#!/bin/bash
# CIS 3.2.6 - Ensure bogus ICMP responses are ignored
set -euo pipefail

# Set sysctl parameter
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# Make it persistent
if ! grep -q "net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf; then
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Bogus ICMP responses ignored"

