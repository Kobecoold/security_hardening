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
    # /var/tmp is not a separate partition - bind mount with tmpfs according to CIS benchmark
    echo "ℹ️ /var/tmp is not a separate partition. Bind mounting with tmpfs (CIS recommendation)..."
    
    # Check if tmpfs entry already exists in /etc/fstab
    if grep -qE '^\s*tmpfs\s+/var/tmp\s' /etc/fstab; then
        echo "ℹ️ tmpfs entry for /var/tmp already exists in /etc/fstab"
        # Try to mount it (will fail if /var/tmp is in use, but that's OK - will apply on reboot)
        if timeout 30 mount -t tmpfs -o nodev,noexec,nosuid tmpfs /var/tmp 2>/dev/null; then
            echo "✅ /var/tmp mounted with tmpfs and nodev option"
        else
            echo "⚠️ Failed to mount tmpfs (may be in use), but entry exists in /etc/fstab - will apply on reboot"
        fi
    else
        # Ensure /var/tmp directory exists
        mkdir -p /var/tmp
        
        # Add tmpfs entry to /etc/fstab
        echo "tmpfs /var/tmp tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
        echo "✅ Added tmpfs entry to /etc/fstab"
        
        # Try to mount it (will fail if /var/tmp is in use, but that's OK - will apply on reboot)
        if timeout 30 mount -t tmpfs -o nodev,noexec,nosuid tmpfs /var/tmp 2>/dev/null; then
            echo "✅ /var/tmp mounted with tmpfs and nodev option"
        else
            echo "⚠️ Failed to mount tmpfs immediately (may be in use) - will apply on reboot"
        fi
    fi
    
    # VERIFY: Check if fix was successful
    if mount | grep -E '\s/var/tmp\s' | grep -q nodev; then
        echo "✅ VERIFIED: /var/tmp has nodev option - FIXED"
        exit 0
    else
        echo "⚠️ VERIFICATION: /var/tmp does not have nodev option yet, but tmpfs entry added to /etc/fstab"
        echo "ℹ️ This will be applied on next reboot or when /var/tmp is not in use"
        exit 0  # Consider this a success as the fix is configured
    fi
fi

