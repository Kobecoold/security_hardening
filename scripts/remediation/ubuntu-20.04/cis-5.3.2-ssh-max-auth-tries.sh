#!/bin/bash
# CIS 5.3.2 - MaxAuthTries 4
set -euo pipefail

# Check if already fixed (value <= 4)
current_value=$(sshd -T 2>/dev/null | grep -i '^maxauthtries' | awk '{print $2}' || echo "")
if [ -n "$current_value" ] && [ "$current_value" -le 4 ] 2>/dev/null; then
    echo "✅ SSH MaxAuthTries is already set to $current_value (<= 4) - FIXED"
    exit 0
fi

# Backup config before making changes
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Update config
if ! grep -qE '^MaxAuthTries' /etc/ssh/sshd_config; then
    echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
else
    sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
fi

# Reload service (with timeout)
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

# VERIFY: Check if fix was successful
verify_value=$(sshd -T 2>/dev/null | grep -i '^maxauthtries' | awk '{print $2}' || echo "")
if [ -n "$verify_value" ] && [ "$verify_value" -le 4 ] 2>/dev/null; then
    echo "✅ VERIFIED: SSH MaxAuthTries is set to $verify_value (<= 4) - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: SSH MaxAuthTries is not set to 4 or less (current: $verify_value)"
    exit 1
fi

