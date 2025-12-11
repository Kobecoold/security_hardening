#!/bin/bash
# CIS 3.2.1 - Ensure source routed packets are not accepted
set -euo pipefail

# Set sysctl parameters
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# Make it persistent
if ! grep -q "net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf; then
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

# Apply sysctl
sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

echo "✅ Source routed packets disabled"

