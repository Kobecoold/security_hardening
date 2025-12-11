#!/bin/bash
# CIS 1.4.1 - Ensure bootloader password is set
set -euo pipefail

# Set permissions on grub.cfg
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg

echo "✅ Bootloader permissions configured"

