#!/bin/bash
# CIS 5.2.4 - Disable SSH Root Login
set -euo pipefail

# Check if already fixed
if sshd -T 2>/dev/null | grep -i '^permitrootlogin' | grep -qi 'no'; then
    echo "✅ SSH Root Login is already disabled - FIXED"
    exit 0
fi

# Backup config before making changes
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Update config
if ! grep -qE '^PermitRootLogin' /etc/ssh/sshd_config; then
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
else
    sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
fi

# Reload service (with timeout)
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

# VERIFY: Check if fix was successful
if sshd -T 2>/dev/null | grep -i '^permitrootlogin' | grep -qi 'no'; then
    echo "✅ VERIFIED: SSH Root Login is disabled - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: SSH Root Login is not disabled"
    exit 1
fi

