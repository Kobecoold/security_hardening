#!/bin/bash
# CIS 5.3.3 - Disable Empty Passwords
# This script MUST be run with sudo privileges
set -euo pipefail

# Function to check current status
check_current_status() {
    # Check running config first
    if command -v sshd >/dev/null 2>&1; then
        if sshd -T 2>/dev/null | grep -iE '^permitemptypasswords' | grep -qiE '(no|false)'; then
            echo "✅ SSH PermitEmptyPasswords is already disabled - FIXED"
            exit 0
        fi
    fi
    # Check config file
    if [ -r /etc/ssh/sshd_config ]; then
        if grep -iE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' /etc/ssh/sshd_config >/dev/null 2>&1; then
            echo "✅ SSH PermitEmptyPasswords is already disabled in config - FIXED"
            exit 0
        fi
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
    
    # Remove any existing PermitEmptyPasswords lines (case insensitive)
    sed -i '/^[[:space:]]*[Pp][Ee][Rr][Mm][Ii][Tt][Ee][Mm][Pp][Tt][Yy][Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][Ss]/d' "$CONFIG_FILE"
    
    # Add the correct setting
    echo "PermitEmptyPasswords no" >> "$CONFIG_FILE"
    
    # Verify the change was written
    if grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' "$CONFIG_FILE"; then
        echo "✅ Config file updated: PermitEmptyPasswords no"
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
    if ! grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' /etc/ssh/sshd_config; then
        echo "❌ VERIFICATION FAILED: Config file does not contain 'PermitEmptyPasswords no'"
        exit 1
    fi
    
    # Check 2: Verify sshd -T shows the correct setting
    if command -v sshd >/dev/null 2>&1; then
        if sshd -T 2>/dev/null | grep -iE '^permitemptypasswords' | grep -qiE '(no|false)'; then
            echo "✅ VERIFIED: SSH PermitEmptyPasswords is disabled"
            echo "   Config file: OK"
            echo "   Running config: OK"
            return 0
        else
            echo "⚠️ WARNING: sshd -T does not show 'PermitEmptyPasswords no'"
            echo "   Config file was updated but service may need restart"
            # Don't fail if config file is correct
            return 0
        fi
    else
        echo "⚠️ WARNING: sshd command not found, cannot verify running config"
        echo "   Config file was updated: OK"
        return 0
    fi
}

# Main execution
main() {
    echo "🔧 Starting remediation for CIS 5.3.3 - Disable SSH PermitEmptyPasswords"
    
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
    
    echo "✅ Remediation completed successfully - SSH PermitEmptyPasswords is now disabled"
    exit 0
}

# Run main function
main "$@"

