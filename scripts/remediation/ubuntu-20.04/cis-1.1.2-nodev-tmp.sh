#!/bin/bash
# CIS 1.1.2 - Ensure nodev option set on /tmp partition
set -euo pipefail

# Check if /tmp is a separate partition
if mount | grep -qE '\s/tmp\s'; then
    # Remount with nodev option
    mount -o remount,nodev /tmp
    echo "✅ /tmp remounted with nodev option"
else
    echo "⚠️ /tmp is not a separate partition. Consider creating one."
    exit 1
fi

