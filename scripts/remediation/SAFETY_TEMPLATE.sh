#!/bin/bash
# TEMPLATE: Safe remediation script với timeout và error handling
# Copy template này khi tạo script mới

set -euo pipefail

# ========== SAFETY SETTINGS ==========
# Set non-interactive mode (tránh prompts)
export DEBIAN_FRONTEND=noninteractive

# Global timeout cho toàn bộ script (5 phút)
SCRIPT_TIMEOUT=300

# Function để chạy command với timeout
run_with_timeout() {
    local timeout=$1
    shift
    timeout "$timeout" "$@" || {
        echo "⚠️ Command timeout after ${timeout}s: $*"
        return 124
    }
}

# Function để check và wait apt lock
wait_for_apt_lock() {
    local max_wait=30
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -ge $max_wait ]; then
            echo "⚠️ apt lock timeout after ${max_wait}s"
            return 1
        fi
        echo "⏳ Waiting for apt lock... ($waited/${max_wait}s)"
        sleep 2
        waited=$((waited + 2))
    done
    return 0
}

# ========== MAIN SCRIPT ==========
# Wrap toàn bộ script trong timeout
(
    # Your remediation commands here
    # Example:
    # wait_for_apt_lock || exit 1
    # run_with_timeout 60 apt-get remove -y package-name
    
    echo "✅ Remediation completed"
) &
SCRIPT_PID=$!

# Wait với timeout
if wait $SCRIPT_PID; then
    exit 0
else
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        echo "❌ Script timeout after ${SCRIPT_TIMEOUT}s"
        kill $SCRIPT_PID 2>/dev/null || true
        exit 124
    fi
    exit $EXIT_CODE
fi

