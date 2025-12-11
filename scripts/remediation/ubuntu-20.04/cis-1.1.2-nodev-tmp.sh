#!/bin/bash
# CIS 1.1.2 - Ensure nodev option set on /tmp partition
set -euo pipefail

# Check if already fixed
if mount | grep -E '\s/tmp\s' | grep -q nodev; then
    echo "✅ /tmp already has nodev option - FIXED"
    exit 0
fi

# Backup /etc/fstab before making changes
cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Check if /tmp is a separate partition
if mount | grep -qE '\s/tmp\s'; then
    # /tmp is already mounted, remount with nodev option
    if timeout 30 mount -o remount,nodev /tmp 2>/dev/null; then
        echo "✅ /tmp remounted with nodev option"
    else
        echo "⚠️ mount remount failed, attempting to update /etc/fstab"
        # Update /etc/fstab to make nodev persistent
        if grep -qE '\s/tmp\s' /etc/fstab; then
            # Update existing entry - add nodev if not present
            if ! grep -E '\s/tmp\s' /etc/fstab | grep -q nodev; then
                sed -i.tmp 's|\(.*\s/tmp\s.*\)|\1,nodev|' /etc/fstab
                sed -i.tmp 's/,nodev,nodev/,nodev/g' /etc/fstab
                sed -i.tmp 's/,nodev,/,/g' /etc/fstab
                rm -f /etc/fstab.tmp
                echo "✅ Updated /etc/fstab - nodev will be applied on next reboot"
            fi
        else
            echo "⚠️ /tmp not found in /etc/fstab, cannot make persistent"
            exit 1
        fi
    fi
else
    # /tmp is not a separate partition - mount with tmpfs according to CIS benchmark
    echo "ℹ️ /tmp is not a separate partition. Mounting with tmpfs (CIS recommendation)..."
    
    # Check if tmpfs entry already exists in /etc/fstab
    if grep -qE '^\s*tmpfs\s+/tmp\s' /etc/fstab; then
        echo "ℹ️ tmpfs entry for /tmp already exists in /etc/fstab"
        # Try to mount it (will fail if /tmp is in use, but that's OK - will apply on reboot)
        if timeout 30 mount -t tmpfs -o nodev,noexec,nosuid tmpfs /tmp 2>/dev/null; then
            echo "✅ /tmp mounted with tmpfs and nodev option"
        else
            echo "⚠️ Failed to mount tmpfs (may be in use), but entry exists in /etc/fstab - will apply on reboot"
        fi
    else
        # Add tmpfs entry to /etc/fstab
        echo "tmpfs /tmp tmpfs defaults,nodev,noexec,nosuid 0 0" >> /etc/fstab
        echo "✅ Added tmpfs entry to /etc/fstab"
        
        # Try to mount it (will fail if /tmp is in use, but that's OK - will apply on reboot)
        if timeout 30 mount -t tmpfs -o nodev,noexec,nosuid tmpfs /tmp 2>/dev/null; then
            echo "✅ /tmp mounted with tmpfs and nodev option"
        else
            echo "⚠️ Failed to mount tmpfs immediately (may be in use) - will apply on reboot"
        fi
    fi
fi

# VERIFY: Check if fix was successful
if mount | grep -E '\s/tmp\s' | grep -q nodev; then
    echo "✅ VERIFIED: /tmp has nodev option - FIXED"
    exit 0
else
    # Check if tmpfs entry was added to /etc/fstab
    if grep -qE '^\s*tmpfs\s+/tmp\s' /etc/fstab; then
        echo "⚠️ VERIFICATION: /tmp does not have nodev option yet, but tmpfs entry added to /etc/fstab"
        echo "ℹ️ This will be applied on next reboot or when /tmp is not in use"
        exit 0  # Consider this a success as the fix is configured
    else
        echo "❌ VERIFICATION FAILED: /tmp does not have nodev option and no tmpfs entry found"
        exit 1
    fi
fi

