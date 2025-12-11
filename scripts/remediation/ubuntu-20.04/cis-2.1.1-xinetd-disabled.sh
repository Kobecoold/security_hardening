#!/bin/bash
# CIS 2.1.1 - Ensure xinetd is not installed
set -euo pipefail

# Remove xinetd if installed
if dpkg -s xinetd >/dev/null 2>&1; then
    apt-get remove -y xinetd
    echo "✅ xinetd removed"
else
    echo "ℹ️ xinetd is not installed"
fi

