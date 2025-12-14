#!/bin/bash
# Test script để kiểm tra SSH config check commands
# Chạy script này trên server để debug

echo "=== Testing SSH Config Check Commands ==="
echo ""

# Test 1: Check if sshd command exists
echo "1. Testing sshd command:"
if command -v sshd >/dev/null 2>&1; then
    echo "   ✅ sshd found: $(which sshd)"
else
    echo "   ❌ sshd not found in PATH"
fi
echo ""

# Test 2: Check sshd -T
echo "2. Testing sshd -T:"
sshd_output=$(sshd -T 2>&1)
sshd_exit=$?
if [ $sshd_exit -eq 0 ]; then
    echo "   ✅ sshd -T succeeded"
    permit_empty=$(echo "$sshd_output" | grep -iE '^permitemptypasswords' | head -1)
    echo "   PermitEmptyPasswords setting: $permit_empty"
    if echo "$permit_empty" | grep -qiE '(no|false)'; then
        echo "   ✅ PermitEmptyPasswords is disabled (PASS)"
    else
        echo "   ❌ PermitEmptyPasswords is NOT disabled (FAIL)"
    fi
else
    echo "   ❌ sshd -T failed with exit code $sshd_exit"
    echo "   Error: $sshd_output"
fi
echo ""

# Test 3: Check file readability
echo "3. Testing file readability:"
if [ -r /etc/ssh/sshd_config ]; then
    echo "   ✅ /etc/ssh/sshd_config is readable"
    permit_empty_line=$(grep -iE '^[[:space:]]*PermitEmptyPasswords' /etc/ssh/sshd_config | head -1)
    echo "   PermitEmptyPasswords line: $permit_empty_line"
    if grep -iE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' /etc/ssh/sshd_config >/dev/null 2>&1; then
        echo "   ✅ File contains 'PermitEmptyPasswords no' (PASS)"
    else
        echo "   ❌ File does NOT contain 'PermitEmptyPasswords no' (FAIL)"
    fi
else
    echo "   ❌ /etc/ssh/sshd_config is NOT readable"
    echo "   File permissions: $(ls -l /etc/ssh/sshd_config 2>/dev/null || echo 'Cannot check')"
fi
echo ""

# Test 4: Check config.d directory
echo "4. Testing config.d directory:"
if [ -d /etc/ssh/sshd_config.d ] && [ -r /etc/ssh/sshd_config.d ]; then
    echo "   ✅ /etc/ssh/sshd_config.d exists and is readable"
    for f in /etc/ssh/sshd_config.d/*.conf; do
        if [ -f "$f" ] && [ -r "$f" ]; then
            echo "   Found config file: $f"
            if grep -iE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+no' "$f" >/dev/null 2>&1; then
                echo "   ✅ File contains 'PermitEmptyPasswords no'"
            fi
        fi
    done
else
    echo "   ⚠️ /etc/ssh/sshd_config.d does not exist or is not readable"
fi
echo ""

# Test 5: Current user and permissions
echo "5. Current user and permissions:"
echo "   User: $(whoami)"
echo "   UID: $(id -u)"
echo "   Groups: $(groups)"
echo "   Can read /etc/ssh/sshd_config: $([ -r /etc/ssh/sshd_config ] && echo 'YES' || echo 'NO')"
echo ""

# Test 6: Run the actual check command
echo "6. Running the actual check command:"
check_script='
set +e
if command -v sshd >/dev/null 2>&1; then
  sshd_output=$(sshd -T 2>&1)
  sshd_exit=$?
  if [ $sshd_exit -eq 0 ]; then
    permit_empty=$(echo "$sshd_output" | grep -iE "^permitemptypasswords" | head -1)
    if echo "$permit_empty" | grep -qiE "(no|false)"; then
      exit 0
    fi
  fi
fi
if [ -r /etc/ssh/sshd_config ]; then
  if grep -iE "^[[:space:]]*PermitEmptyPasswords[[:space:]]+no" /etc/ssh/sshd_config >/dev/null 2>&1; then
    exit 0
  fi
fi
exit 1
'

bash -c "$check_script"
check_exit=$?
if [ $check_exit -eq 0 ]; then
    echo "   ✅ Check command PASSED (exit 0)"
else
    echo "   ❌ Check command FAILED (exit $check_exit)"
fi
echo ""

echo "=== Test Complete ==="
