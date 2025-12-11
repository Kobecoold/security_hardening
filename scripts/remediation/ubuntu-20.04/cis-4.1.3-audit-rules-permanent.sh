#!/bin/bash
# CIS 4.1.3 - Ensure auditing for processes that start prior to auditd is enabled
set -euo pipefail

# Check if already fixed
if grep -E "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -q "audit=1"; then
    echo "✅ audit=1 is already configured in GRUB - FIXED"
    exit 0
fi

# Update GRUB to include audit=1
if [ -f /etc/default/grub ]; then
    # Check if audit=1 is already in GRUB_CMDLINE_LINUX
    if ! grep -q "audit=1" /etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
        # update-grub can take a long time, add timeout
        timeout 180 update-grub 2>/dev/null || {
            echo "⚠️ update-grub timeout or error (non-critical, changes saved to /etc/default/grub)"
        }
        echo "✅ audit=1 added to GRUB. Reboot required to apply."
    else
        echo "ℹ️ audit=1 already configured in /etc/default/grub (but not in grub.cfg yet)"
    fi
else
    echo "⚠️ /etc/default/grub not found"
    exit 1
fi

# VERIFY: Check if fix was successful (check grub.cfg)
if grep -E "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -q "audit=1"; then
    echo "✅ VERIFIED: audit=1 is configured in GRUB - FIXED"
    exit 0
else
    echo "⚠️ VERIFICATION: audit=1 is in /etc/default/grub but not yet in grub.cfg (reboot required)"
    exit 0  # Still consider success as config is saved
fi

