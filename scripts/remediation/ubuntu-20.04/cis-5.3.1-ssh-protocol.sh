#!/bin/bash
# CIS 5.3.1 - SSH Protocol 2
set -euo pipefail

sed -i 's/^Protocol .*/Protocol 2/' /etc/ssh/sshd_config
# systemctl reload can hang, add timeout
timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
    echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
}

