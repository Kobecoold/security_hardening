# CIS Windows 10 2.3.1.2 - Ensure 'Accounts: Guest account status' is set to 'Disabled'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 2.3.1.2 ==="

# Variables
$RuleId = "cis-windows10-2.3.1.2"
$TestCommand = 'net user guest | findstr "Account active"'
$Expected = "No"

# Backup current setting
Write-Log "Backing up Guest account status..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "guest_account_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
net user guest > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Disabling Guest account..."
net user guest /active:no

if ($LASTEXITCODE -eq 0) {
    Write-Log "Guest account disabled successfully"
} else {
    Write-Log "Failed to disable Guest account (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = net user guest | findstr "Account active"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Guest account is DISABLED" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
