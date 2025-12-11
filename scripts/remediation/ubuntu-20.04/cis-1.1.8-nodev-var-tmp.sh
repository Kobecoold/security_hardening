#!/bin/bash
# CIS 1.1.8 - Ensure nodev option set on /var/tmp partition
set -euo pipefail

# Check if /var/tmp is a separate partition
if mount | grep -qE '\s/var/tmp\s'; then
    # Remount with nodev option
    mount -o remount,nodev /var/tmp
    echo "✅ /var/tmp remounted with nodev option"
else
    # If /var/tmp is part of /var, remount /var with nodev
    if mount | grep -qE '\s/var\s'; then
        mount -o remount,nodev /var
        echo "✅ /var remounted with nodev option (affects /var/tmp)"
    else
        echo "⚠️ /var/tmp is not a separate partition. Consider creating one."
        exit 1
    fi
fi

