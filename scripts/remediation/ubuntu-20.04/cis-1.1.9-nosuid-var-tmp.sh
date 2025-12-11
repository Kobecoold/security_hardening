#!/bin/bash
# CIS 1.1.9 - Ensure nosuid option set on /var/tmp partition
set -euo pipefail

# Check if /var/tmp is a separate partition
if mount | grep -qE '\s/var/tmp\s'; then
    # Remount with nosuid option (with timeout)
    timeout 30 mount -o remount,nosuid /var/tmp 2>/dev/null || {
        echo "⚠️ mount remount timeout or error"
        exit 1
    }
    echo "✅ /var/tmp remounted with nosuid option"
else
    # If /var/tmp is part of /var, remount /var with nosuid
    if mount | grep -qE '\s/var\s'; then
        timeout 30 mount -o remount,nosuid /var 2>/dev/null || {
            echo "⚠️ mount remount timeout or error"
            exit 1
        }
        echo "✅ /var remounted with nosuid option (affects /var/tmp)"
    else
        echo "⚠️ /var/tmp is not a separate partition. Consider creating one."
        exit 1
    fi
fi

