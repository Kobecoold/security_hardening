#!/bin/bash
# CIS 2.2.5 - Ensure LDAP server is not installed
set -euo pipefail

# Stop and disable LDAP server
systemctl stop slapd 2>/dev/null || true
systemctl disable slapd 2>/dev/null || true

# Remove if installed
if dpkg -s slapd >/dev/null 2>&1; then
    apt-get remove -y slapd
    echo "✅ LDAP server removed"
else
    echo "ℹ️ LDAP server is not installed (service disabled)"
fi

