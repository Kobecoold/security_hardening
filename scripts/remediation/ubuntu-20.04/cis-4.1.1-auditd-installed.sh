#!/bin/bash
# CIS 4.1.1 - Ensure auditd is installed
set -euo pipefail

# Install auditd if not installed
if ! dpkg -s auditd >/dev/null 2>&1; then
    apt-get update
    apt-get install -y auditd
    echo "✅ auditd installed"
else
    echo "ℹ️ auditd is already installed"
fi

