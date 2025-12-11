#!/bin/bash
# CIS 1.7.1 - Ensure message of the day is configured properly
set -euo pipefail

# Create /etc/motd if it doesn't exist
if [ ! -f /etc/motd ]; then
    touch /etc/motd
fi

# Set permissions
chmod 644 /etc/motd
chown root:root /etc/motd

echo "✅ MOTD permissions configured"

