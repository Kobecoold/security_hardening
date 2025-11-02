#!/bin/bash
# CIS 5.3.3 - Disable Empty Passwords
set -euo pipefail

sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

