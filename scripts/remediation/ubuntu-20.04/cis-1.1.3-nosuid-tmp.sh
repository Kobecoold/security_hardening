#!/bin/bash
# CIS 1.1.3 - Ensure nosuid option set on /tmp partition
set -euo pipefail

# Check if /tmp is a separate partition
if mount | grep -qE '\s/tmp\s'; then
    # Remount with nosuid option (with timeout)
    timeout 30 mount -o remount,nosuid /tmp 2>/dev/null || {
        echo "⚠️ mount remount timeout or error"
        exit 1
    }
    echo "✅ /tmp remounted with nosuid option"
else
    echo "⚠️ /tmp is not a separate partition. Consider creating one."
    exit 1
fi

