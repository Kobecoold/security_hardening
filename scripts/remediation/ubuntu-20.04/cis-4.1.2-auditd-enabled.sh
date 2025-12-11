#!/bin/bash
# CIS 4.1.2 - Ensure auditd service is enabled
set -euo pipefail

# Install auditd if not installed
if ! dpkg -s auditd >/dev/null 2>&1; then
    apt-get update
    apt-get install -y auditd
fi

# Enable and start auditd
systemctl enable auditd
systemctl start auditd

echo "✅ auditd service enabled and started"

