#!/bin/bash
# CIS 5.2.4 - Disable SSH Root Login
set -euo pipefail

sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

