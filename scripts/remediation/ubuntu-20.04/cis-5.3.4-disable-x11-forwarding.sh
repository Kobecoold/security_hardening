#!/bin/bash
# CIS 5.3.4 - Disable X11Forwarding
set -euo pipefail

sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

