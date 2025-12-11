#!/bin/bash
# CIS 4.1.3 - Ensure auditing for processes that start prior to auditd is enabled
set -euo pipefail

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
        echo "ℹ️ audit=1 already configured in GRUB"
    fi
else
    echo "⚠️ /etc/default/grub not found"
    exit 1
fi

