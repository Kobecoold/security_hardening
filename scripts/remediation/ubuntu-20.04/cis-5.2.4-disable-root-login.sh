#!/bin/bash
# CIS 5.2.4 - Disable SSH Root Login
set -euo pipefail

sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
# systemctl reload can hang, add timeout
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

