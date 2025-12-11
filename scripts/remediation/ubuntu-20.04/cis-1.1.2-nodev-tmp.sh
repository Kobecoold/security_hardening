#!/bin/bash
# CIS 1.1.2 - Ensure nodev option set on /tmp partition
set -euo pipefail

# Check if already fixed
if mount | grep -E '\s/tmp\s' | grep -q nodev; then
    echo "✅ /tmp already has nodev option - FIXED"
    exit 0
fi

# Check if /tmp is a separate partition
if mount | grep -qE '\s/tmp\s'; then
    # Backup /etc/fstab before making changes
    cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Remount with nodev option (with timeout)
    if timeout 30 mount -o remount,nodev /tmp 2>/dev/null; then
        echo "✅ /tmp remounted with nodev option"
    else
        echo "⚠️ mount remount failed, attempting to update /etc/fstab"
        # Update /etc/fstab to make nodev persistent
        if grep -qE '\s/tmp\s' /etc/fstab; then
            # Update existing entry
            sed -i.tmp 's|\(.*\s/tmp\s.*\)|\1,nodev|' /etc/fstab
            # Remove duplicate nodev if exists
            sed -i.tmp 's/,nodev,nodev/,nodev/g' /etc/fstab
            sed -i.tmp 's/,nodev,/,/g' /etc/fstab
            rm -f /etc/fstab.tmp
            echo "✅ Updated /etc/fstab - nodev will be applied on next reboot"
        else
            echo "⚠️ /tmp not found in /etc/fstab, cannot make persistent"
            exit 1
        fi
    fi
    
    # VERIFY: Check if fix was successful
    if mount | grep -E '\s/tmp\s' | grep -q nodev; then
        echo "✅ VERIFIED: /tmp has nodev option - FIXED"
        exit 0
    else
        echo "❌ VERIFICATION FAILED: /tmp does not have nodev option"
        exit 1
    fi
else
    echo "⚠️ /tmp is not a separate partition. Consider creating one."
    exit 1
fi

