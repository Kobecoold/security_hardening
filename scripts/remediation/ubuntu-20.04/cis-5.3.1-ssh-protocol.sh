#!/bin/bash
# CIS 5.3.1 - SSH Protocol 2
set -euo pipefail

sed -i 's/^Protocol .*/Protocol 2/' /etc/ssh/sshd_config
systemctl reload ssh || systemctl reload sshd || true

