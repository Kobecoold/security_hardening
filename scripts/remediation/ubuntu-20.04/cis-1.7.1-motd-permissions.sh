#!/bin/bash
# CIS 1.7.1 - Ensure message of the day is configured properly
set -euo pipefail

# Check if already fixed
if [ -f /etc/motd ] && stat -L -c "%a %u %g" /etc/motd 2>/dev/null | grep -qE "^644 0 0$"; then
    echo "✅ MOTD permissions are already configured - FIXED"
    exit 0
fi

# Create /etc/motd if it doesn't exist
if [ ! -f /etc/motd ]; then
    touch /etc/motd
fi

# Set permissions
chmod 644 /etc/motd
chown root:root /etc/motd

# VERIFY: Check if fix was successful
if [ -f /etc/motd ] && stat -L -c "%a %u %g" /etc/motd 2>/dev/null | grep -qE "^644 0 0$"; then
    echo "✅ VERIFIED: MOTD permissions are configured - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: MOTD permissions are not configured correctly"
    exit 1
fi

