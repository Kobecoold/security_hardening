#!/bin/bash
# CIS 5.3.5 - SSH LogLevel INFO
set -euo pipefail

# Check if already fixed
if sshd -T 2>/dev/null | grep -i '^loglevel' | grep -qE '^(INFO|VERBOSE)$'; then
    echo "✅ SSH LogLevel is already set to INFO or VERBOSE - FIXED"
    exit 0
fi

# Backup config before making changes
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Update config
if ! grep -qE '^LogLevel' /etc/ssh/sshd_config; then
    echo "LogLevel INFO" >> /etc/ssh/sshd_config
else
    sed -i 's/^LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
fi

# Reload service (with timeout)
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

# VERIFY: Check if fix was successful
if sshd -T 2>/dev/null | grep -i '^loglevel' | grep -qE '^(INFO|VERBOSE)$'; then
    echo "✅ VERIFIED: SSH LogLevel is set to INFO or VERBOSE - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: SSH LogLevel is not set to INFO or VERBOSE"
    exit 1
fi

