#!/bin/bash
# CIS 1.1.8 - Ensure nodev option set on /var/tmp partition
set -euo pipefail

# Check if already fixed
if mount | grep -E '\s/var/tmp\s' | grep -q nodev; then
    echo "✅ /var/tmp already has nodev option - FIXED"
    exit 0
fi

# Check if /var/tmp is a separate partition
if mount | grep -qE '\s/var/tmp\s'; then
    # Backup /etc/fstab before making changes
    cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Remount with nodev option (with timeout)
    if timeout 30 mount -o remount,nodev /var/tmp 2>/dev/null; then
        echo "✅ /var/tmp remounted with nodev option"
    else
        echo "⚠️ mount remount failed, attempting to update /etc/fstab"
        # Update /etc/fstab to make nodev persistent
        if grep -qE '\s/var/tmp\s' /etc/fstab; then
            sed -i.tmp 's|\(.*\s/var/tmp\s.*\)|\1,nodev|' /etc/fstab
            sed -i.tmp 's/,nodev,nodev/,nodev/g' /etc/fstab
            sed -i.tmp 's/,nodev,/,/g' /etc/fstab
            rm -f /etc/fstab.tmp
            echo "✅ Updated /etc/fstab - nodev will be applied on next reboot"
        else
            echo "⚠️ /var/tmp not found in /etc/fstab, cannot make persistent"
            exit 1
        fi
    fi
    
    # VERIFY: Check if fix was successful
    if mount | grep -E '\s/var/tmp\s' | grep -q nodev; then
        echo "✅ VERIFIED: /var/tmp has nodev option - FIXED"
        exit 0
    else
        echo "❌ VERIFICATION FAILED: /var/tmp does not have nodev option"
        exit 1
    fi
else
    # If /var/tmp is part of /var, remount /var with nodev
    if mount | grep -qE '\s/var\s'; then
        cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        
        if timeout 30 mount -o remount,nodev /var 2>/dev/null; then
            echo "✅ /var remounted with nodev option (affects /var/tmp)"
        else
            echo "⚠️ mount remount failed, attempting to update /etc/fstab"
            if grep -qE '\s/var\s' /etc/fstab; then
                sed -i.tmp 's|\(.*\s/var\s.*\)|\1,nodev|' /etc/fstab
                sed -i.tmp 's/,nodev,nodev/,nodev/g' /etc/fstab
                sed -i.tmp 's/,nodev,/,/g' /etc/fstab
                rm -f /etc/fstab.tmp
                echo "✅ Updated /etc/fstab - nodev will be applied on next reboot"
            else
                echo "⚠️ /var not found in /etc/fstab, cannot make persistent"
                exit 1
            fi
        fi
        
        # VERIFY
        if mount | grep -E '\s/var\s' | grep -q nodev; then
            echo "✅ VERIFIED: /var has nodev option (affects /var/tmp) - FIXED"
            exit 0
        else
            echo "❌ VERIFICATION FAILED: /var does not have nodev option"
            exit 1
        fi
    else
        echo "⚠️ /var/tmp is not a separate partition. Consider creating one."
        exit 1
    fi
fi

