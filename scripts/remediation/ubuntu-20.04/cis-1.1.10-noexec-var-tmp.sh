#!/bin/bash
# CIS 1.1.10 - Ensure noexec option set on /var/tmp partition
set -euo pipefail

# Check if /var/tmp is a separate partition
if mount | grep -qE '\s/var/tmp\s'; then
    # Remount with noexec option (with timeout)
    timeout 30 mount -o remount,noexec /var/tmp 2>/dev/null || {
        echo "⚠️ mount remount timeout or error"
        exit 1
    }
    echo "✅ /var/tmp remounted with noexec option"
else
    # If /var/tmp is part of /var, remount /var with noexec
    if mount | grep -qE '\s/var\s'; then
        timeout 30 mount -o remount,noexec /var 2>/dev/null || {
            echo "⚠️ mount remount timeout or error"
            exit 1
        }
        echo "✅ /var remounted with noexec option (affects /var/tmp)"
    else
        echo "⚠️ /var/tmp is not a separate partition. Consider creating one."
        exit 1
    fi
fi

