#!/bin/bash
# CIS 2.2.1 - Ensure X Window System is not installed
set -euo pipefail

# Remove X11 packages if installed
if dpkg -l | grep -E "^ii\s+xserver-xorg" >/dev/null 2>&1; then
    apt-get remove -y xserver-xorg*
    echo "✅ X Window System removed"
else
    echo "ℹ️ X Window System is not installed"
fi

