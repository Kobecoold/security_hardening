# CIS Windows 10 1.1.2 - Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 1.1.2 ==="

# Variables
$RuleId = "cis-windows10-1.1.2"
$TestCommand = 'net accounts | findstr "Maximum password age"'
$Expected = "365"

# Backup current setting
Write-Log "Backing up current password policy..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "net_accounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
net accounts > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Check current value
$current = net accounts | findstr "Maximum password age"
Write-Log "Current maximum password age: $current"

# Apply fix
Write-Log "Setting maximum password age to 365 days..."
net accounts /maxpwage:365

if ($LASTEXITCODE -eq 0) {
    Write-Log "Maximum password age set to 365 days successfully"
} else {
    Write-Log "Failed to set maximum password age (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = net accounts | findstr "Maximum password age"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Maximum password age is 365" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
