#!/bin/bash
# CIS 5.3.4 - Disable X11Forwarding
set -euo pipefail

# Check if already fixed
if sshd -T 2>/dev/null | grep -i '^x11forwarding' | grep -qi 'no'; then
    echo "✅ SSH X11Forwarding is already disabled - FIXED"
    exit 0
fi

# Backup config before making changes
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Update config
if ! grep -qE '^X11Forwarding' /etc/ssh/sshd_config; then
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
else
    sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
fi

# Reload service (with timeout)
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

# VERIFY: Check if fix was successful
if sshd -T 2>/dev/null | grep -i '^x11forwarding' | grep -qi 'no'; then
    echo "✅ VERIFIED: SSH X11Forwarding is disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: SSH X11Forwarding is not disabled"
    exit 1
fi

