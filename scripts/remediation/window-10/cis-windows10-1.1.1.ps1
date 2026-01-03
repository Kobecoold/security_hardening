# CIS Windows 10 1.1.1 - Ensure 'Enforce password history' is set to '24 or more password(s)'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 1.1.1 ==="

# Variables
$RuleId = "cis-windows10-1.1.1"
$TestCommand = 'net accounts | findstr "Length of password history maintained"'
$Expected = "24"

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

# Apply fix
Write-Log "Setting password history to 24..."
net accounts /uniquepw:24

if ($LASTEXITCODE -eq 0) {
    Write-Log "Password history set to 24 successfully"
} else {
    Write-Log "Failed to set password history (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = net accounts | findstr "Length of password history maintained"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Password history is 24" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
