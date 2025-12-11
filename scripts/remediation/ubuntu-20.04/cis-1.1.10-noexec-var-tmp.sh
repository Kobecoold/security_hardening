#!/bin/bash
# CIS 1.1.10 - Ensure noexec option set on /var/tmp partition
set -euo pipefail

# Check if already fixed
if mount | grep -E '\s/var/tmp\s' | grep -q noexec; then
    echo "✅ /var/tmp already has noexec option - FIXED"
    exit 0
fi

# Check if /var/tmp is a separate partition
if mount | grep -qE '\s/var/tmp\s'; then
    # Backup /etc/fstab before making changes
    cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Remount with noexec option (with timeout)
    if timeout 30 mount -o remount,noexec /var/tmp 2>/dev/null; then
        echo "✅ /var/tmp remounted with noexec option"
    else
        echo "⚠️ mount remount failed, attempting to update /etc/fstab"
        # Update /etc/fstab to make noexec persistent
        if grep -qE '\s/var/tmp\s' /etc/fstab; then
            sed -i.tmp 's|\(.*\s/var/tmp\s.*\)|\1,noexec|' /etc/fstab
            sed -i.tmp 's/,noexec,noexec/,noexec/g' /etc/fstab
            sed -i.tmp 's/,noexec,/,/g' /etc/fstab
            rm -f /etc/fstab.tmp
            echo "✅ Updated /etc/fstab - noexec will be applied on next reboot"
        else
            echo "⚠️ /var/tmp not found in /etc/fstab, cannot make persistent"
            exit 1
        fi
    fi
    
    # VERIFY: Check if fix was successful
    if mount | grep -E '\s/var/tmp\s' | grep -q noexec; then
        echo "✅ VERIFIED: /var/tmp has noexec option - FIXED"
        exit 0
    else
        echo "❌ VERIFICATION FAILED: /var/tmp does not have noexec option"
        exit 1
    fi
else
    # If /var/tmp is part of /var, remount /var with noexec
    if mount | grep -qE '\s/var\s'; then
        cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        
        if timeout 30 mount -o remount,noexec /var 2>/dev/null; then
            echo "✅ /var remounted with noexec option (affects /var/tmp)"
        else
            echo "⚠️ mount remount failed, attempting to update /etc/fstab"
            if grep -qE '\s/var\s' /etc/fstab; then
                sed -i.tmp 's|\(.*\s/var\s.*\)|\1,noexec|' /etc/fstab
                sed -i.tmp 's/,noexec,noexec/,noexec/g' /etc/fstab
                sed -i.tmp 's/,noexec,/,/g' /etc/fstab
                rm -f /etc/fstab.tmp
                echo "✅ Updated /etc/fstab - noexec will be applied on next reboot"
            else
                echo "⚠️ /var not found in /etc/fstab, cannot make persistent"
                exit 1
            fi
        fi
        
        # VERIFY
        if mount | grep -E '\s/var\s' | grep -q noexec; then
            echo "✅ VERIFIED: /var has noexec option (affects /var/tmp) - FIXED"
            exit 0
        else
            echo "❌ VERIFICATION FAILED: /var does not have noexec option"
            exit 1
        fi
    else
        echo "⚠️ /var/tmp is not a separate partition. Consider creating one."
        exit 1
    fi
fi

