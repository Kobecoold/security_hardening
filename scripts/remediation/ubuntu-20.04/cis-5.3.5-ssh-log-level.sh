#!/bin/bash
# CIS 5.3.5 - SSH LogLevel INFO
set -euo pipefail

sed -i 's/^LogLevel.*/LogLevel INFO/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

