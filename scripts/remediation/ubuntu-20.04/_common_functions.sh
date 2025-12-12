#!/bin/bash
# Common functions for all remediation scripts
# Source this file in scripts: source _common_functions.sh

# Wait for apt lock (max 30s)
wait_for_apt_lock() {
    local max_wait=30
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -ge $max_wait ]; then
            echo "⚠️ apt lock timeout after ${max_wait}s"
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 0
}

# Safe apt-get remove with lock checking
safe_apt_remove() {
    local package=$1
    wait_for_apt_lock || return 1
    timeout 60 apt-get remove -y "$package" || {
        echo "⚠️ apt-get timeout or error, trying force remove"
        dpkg --remove --force-remove-reinstreq "$package" 2>/dev/null || true
    }
}

# Safe apt-get install with lock checking
safe_apt_install() {
    local package=$1
    wait_for_apt_lock || return 1
    timeout 120 apt-get update || echo "⚠️ apt-get update timeout"
    timeout 120 apt-get install -y "$package" || {
        echo "⚠️ apt-get install timeout or error"
        return 1
    }
}

# Safe systemctl operations with timeout
safe_systemctl_stop() {
    local service=$1
    timeout 30 systemctl stop "$service" 2>/dev/null || true
}

safe_systemctl_disable() {
    local service=$1
    timeout 30 systemctl disable "$service" 2>/dev/null || true
}

safe_systemctl_reload() {
    timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null || {
        echo "⚠️ systemctl reload timeout (config updated but service not reloaded)"
    }
}

