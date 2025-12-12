#!/bin/bash
# CIS 5.3.1 - SSH Protocol 2
set -euo pipefail

# Check if already fixed
if sshd -T 2>/dev/null | grep -i '^protocol' | grep -qi '2'; then
    echo "✅ SSH Protocol is already set to 2 - FIXED"
    exit 0
fi

# Backup config before making changes
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Update config
if ! grep -qE '^Protocol' /etc/ssh/sshd_config; then
    echo "Protocol 2" >> /etc/ssh/sshd_config
else
    sed -i 's/^Protocol .*/Protocol 2/' /etc/ssh/sshd_config
fi

# Reload service (with timeout)
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

# VERIFY: Check if fix was successful
if sshd -T 2>/dev/null | grep -i '^protocol' | grep -qi '2'; then
    echo "✅ VERIFIED: SSH Protocol is set to 2 - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: SSH Protocol is not set to 2"
    exit 1
fi

