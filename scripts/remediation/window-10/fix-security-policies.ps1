# Security Hardening Remediation Script
Write-Output "=== SECURITY HARDENING REMEDIATION STARTED ==="

# 1. Fix Password Policy - Minimum Length
Write-Output "1. Setting minimum password length to 14..."
net accounts /minpwlen:14

# 2. Fix Account Lockout Threshold  
Write-Output "2. Setting account lockout threshold to 5..."
net accounts /lockoutthreshold:5

# 3. Fix Audit Policy - Logon Events
Write-Output "3. Enabling audit for logon events..."
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Write-Output "✓ Audit policy for Logon events configured"

# 4. Fix Remote Assistance
Write-Output "4. Disabling remote assistance..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

# 5. Verify changes
Write-Output "`n=== VERIFICATION ==="
Write-Output "Password Policy:"
net accounts | findstr "Minimum password length"

Write-Output "`nAccount Lockout:"
net accounts | findstr "Lockout threshold"

Write-Output "`nAudit Policy:"
auditpol /get /subcategory:"Account Logon" | findstr "Account Logon"
# Verification
Write-Output "`nAudit Policy - Logon:"
auditpol /get /subcategory:"Logon"

Write-Output "`n=== REMEDIATION COMPLETED ==="
