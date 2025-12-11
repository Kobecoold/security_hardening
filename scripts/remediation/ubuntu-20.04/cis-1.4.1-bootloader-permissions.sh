#!/bin/bash
# CIS 1.4.1 - Ensure bootloader password is set
set -euo pipefail

# Check if already fixed
if stat -L -c "%a %u %g" /boot/grub/grub.cfg 2>/dev/null | grep -qE "^600 0 0$"; then
    echo "✅ Bootloader permissions are already configured - FIXED"
    exit 0
fi

# Set permissions on grub.cfg
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg

# VERIFY: Check if fix was successful
if stat -L -c "%a %u %g" /boot/grub/grub.cfg 2>/dev/null | grep -qE "^600 0 0$"; then
    echo "✅ VERIFIED: Bootloader permissions are configured - FIXED"
    exit 0
else
    echo "❌ VERIFICATION FAILED: Bootloader permissions are not configured correctly"
    exit 1
fi

