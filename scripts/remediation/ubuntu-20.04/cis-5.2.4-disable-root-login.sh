#!/bin/bash
# CIS 5.2.4 - Disable SSH Root Login
# This script MUST be run with sudo privileges
set -euo pipefail

# Function to check if running with sudo
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "❌ ERROR: This script must be run with sudo privileges"
        echo "   Please run with: sudo $0"
        exit 1
    fi
}

# Check if already fixed
check_current_status() {
    if sshd -T 2>/dev/null | grep -i '^permitrootlogin' | grep -qi 'no'; then
        echo "✅ SSH Root Login is already disabled - FIXED"
        exit 0
    fi
}

# Backup config before making changes
backup_config() {
    BACKUP_FILE="/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
    if cp /etc/ssh/sshd_config "$BACKUP_FILE" 2>/dev/null; then
        echo "✅ Config backed up to: $BACKUP_FILE"
    else
        echo "⚠️ Warning: Could not create backup (continuing anyway)"
    fi
}

# Update config file
update_config() {
    CONFIG_FILE="/etc/ssh/sshd_config"
    
    # Check if file is writable
    if [ ! -w "$CONFIG_FILE" ]; then
        echo "❌ ERROR: Cannot write to $CONFIG_FILE (permission denied)"
        exit 1
    fi
    
    # Remove any existing PermitRootLogin lines (case insensitive)
    sed -i '/^[[:space:]]*[Pp][Ee][Rr][Mm][Ii][Tt][Rr][Oo][Oo][Tt][Ll][Oo][Gg][Ii][Nn]/d' "$CONFIG_FILE"
    
    # Add the correct setting
    echo "PermitRootLogin no" >> "$CONFIG_FILE"
    
    # Verify the change was written
    if grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+no' "$CONFIG_FILE"; then
        echo "✅ Config file updated: PermitRootLogin no"
    else
        echo "❌ ERROR: Failed to update config file"
        exit 1
    fi
}

# Reload SSH service
reload_service() {
    echo "🔄 Reloading SSH service..."
    
    # Try reload first (graceful)
    if timeout 30 systemctl reload ssh 2>/dev/null || timeout 30 systemctl reload sshd 2>/dev/null; then
        echo "✅ SSH service reloaded successfully"
        # Wait a moment for service to apply changes
        sleep 2
        return 0
    else
        echo "⚠️ Reload failed, trying restart..."
        # Fallback to restart if reload fails
        if timeout 60 systemctl restart ssh 2>/dev/null || timeout 60 systemctl restart sshd 2>/dev/null; then
            echo "✅ SSH service restarted successfully"
            sleep 3
            return 0
        else
            echo "❌ ERROR: Failed to reload/restart SSH service"
            echo "   Config file was updated but service was not reloaded"
            exit 1
        fi
    fi
}

# Verify the fix
verify_fix() {
    echo "🔍 Verifying fix..."
    
    # Check 1: Verify config file has the setting
    if ! grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config; then
        echo "❌ VERIFICATION FAILED: Config file does not contain 'PermitRootLogin no'"
        exit 1
    fi
    
    # Check 2: Verify sshd -T shows the correct setting
    if sshd -T 2>/dev/null | grep -i '^permitrootlogin' | grep -qi 'no'; then
        echo "✅ VERIFIED: SSH Root Login is disabled"
        echo "   Config file: OK"
        echo "   Running config: OK"
        return 0
    else
        echo "❌ VERIFICATION FAILED: sshd -T does not show 'PermitRootLogin no'"
        echo "   Config file was updated but service may not have reloaded properly"
        exit 1
    fi
}

# Main execution
main() {
    echo "🔧 Starting remediation for CIS 5.2.4 - Disable SSH Root Login"
    
    # Check sudo (script should be run with sudo from backend)
    # Note: Backend will run with sudo if Use_sudo=true
    # check_sudo  # Commented out - backend handles sudo
    
    # Check current status
    check_current_status
    
    # Backup config
    backup_config
    
    # Update config
    update_config
    
    # Reload service
    reload_service
    
    # Verify fix
    verify_fix
    
    echo "✅ Remediation completed successfully - SSH Root Login is now disabled"
    exit 0
}

# Run main function
main "$@"

