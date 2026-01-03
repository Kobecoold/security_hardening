#!/bin/bash
# CIS 1.4.1 - Ensure bootloader permissions are configured
# This script MUST be run with sudo privileges
set -euo pipefail

# Function to check current status
check_current_status() {
    if [ ! -f /boot/grub/grub.cfg ]; then
        echo "⚠️ Warning: /boot/grub/grub.cfg not found"
        exit 1
    fi
    
    perms=$(stat -L -c "%a %u %g" /boot/grub/grub.cfg 2>/dev/null || echo "")
    if [ -z "$perms" ]; then
        echo "⚠️ Warning: Cannot read permissions of /boot/grub/grub.cfg"
        exit 1
    fi
    
    # Check if already fixed (600 or 400 are both acceptable)
    if echo "$perms" | grep -qE "^(600|400) 0 0$"; then
    echo "✅ Bootloader permissions are already configured - FIXED"
        echo "   Current permissions: $perms"
    exit 0
fi
    
    echo "   Current permissions: $perms (needs to be 600 0 0 or 400 0 0)"
}

# Set permissions on grub.cfg
set_permissions() {
    CONFIG_FILE="/boot/grub/grub.cfg"
    
    # Check if file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "❌ ERROR: $CONFIG_FILE does not exist"
        exit 1
    fi
    
    # Check if we can write (need sudo)
    if [ ! -w "$CONFIG_FILE" ]; then
        echo "❌ ERROR: Cannot write to $CONFIG_FILE (permission denied)"
        echo "   This script must be run with sudo privileges"
        exit 1
    fi
    
    # Set ownership first
    chown root:root "$CONFIG_FILE"
    if [ $? -ne 0 ]; then
        echo "❌ ERROR: Failed to set ownership to root:root"
        exit 1
    fi
    
    # Set permissions to 600 (rw-------)
    chmod 600 "$CONFIG_FILE"
    if [ $? -ne 0 ]; then
        echo "❌ ERROR: Failed to set permissions to 600"
        exit 1
    fi
    
    echo "✅ Permissions set: chmod 600, chown root:root"
}

# Verify the fix
verify_fix() {
    echo "🔍 Verifying fix..."
    
    if [ ! -f /boot/grub/grub.cfg ]; then
        echo "❌ VERIFICATION FAILED: /boot/grub/grub.cfg does not exist"
        exit 1
    fi
    
    perms=$(stat -L -c "%a %u %g" /boot/grub/grub.cfg 2>/dev/null)
    if [ -z "$perms" ]; then
        echo "❌ VERIFICATION FAILED: Cannot read permissions"
    exit 1
fi
    
    echo "   Current permissions: $perms"
    
    # Check if permissions are correct (600 or 400 are both acceptable)
    if echo "$perms" | grep -qE "^(600|400) 0 0$"; then
        echo "✅ VERIFIED: Bootloader permissions are configured correctly"
        echo "   Permissions: $perms"
        return 0
    else
        echo "❌ VERIFICATION FAILED: Bootloader permissions are not correct"
        echo "   Expected: 600 0 0 or 400 0 0"
        echo "   Got: $perms"
        exit 1
    fi
}

# Main execution
main() {
    echo "🔧 Starting remediation for CIS 1.4.1 - Bootloader Permissions"
    
    # Check current status
    check_current_status
    
    # Set permissions
    set_permissions
    
    # Verify fix
    verify_fix
    
    echo "✅ Remediation completed successfully - Bootloader permissions are now configured"
    exit 0
}

# Run main function
main "$@"

