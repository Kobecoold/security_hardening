#!/bin/bash
# CIS 5.3.2 - MaxAuthTries 4
set -euo pipefail

sed -i 's/^MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

