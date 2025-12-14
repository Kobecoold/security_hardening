# CIS Windows 10 2.3.1.3 - Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
}

Write-Log "=== STARTING REMEDIATION FOR CIS 2.3.1.3 ==="

# Variables
$RuleId = "cis-windows10-2.3.1.3"
$TestCommand = 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse 2>nul || echo KEY_NOT_EXIST'
$Expected = "0x1"

# Backup current registry
Write-Log "Backing up registry value..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "registry_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Enabling limit for blank passwords..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

if ($LASTEXITCODE -eq 0) {
    Write-Log "Registry value set successfully"
} else {
    Write-Log "Failed to set registry value (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse 2>$null

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Limit blank passwords is ENABLED" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
