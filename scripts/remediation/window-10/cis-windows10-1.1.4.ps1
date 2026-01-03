# CIS Windows 10 1.1.4 - Ensure 'Minimum password length' is set to '14 or more character(s)'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 1.1.4 ==="

# Variables
$RuleId = "cis-windows10-1.1.4"
$TestCommand = 'net accounts | findstr "Minimum password length"'
$Expected = "14"

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
$current = net accounts | findstr "Minimum password length"
Write-Log "Current minimum password length: $current"

# Apply fix only if less than 14
if ($current -match "Minimum password length:\s+(\d+)") {
    $currentValue = $matches[1]
    if ([int]$currentValue -lt 14) {
        Write-Log "Setting minimum password length to 14 (was $currentValue)..."
        net accounts /minpwlen:14
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Minimum password length set to 14 successfully"
        } else {
            Write-Log "Failed to set minimum password length (exit code: $LASTEXITCODE)" -Level "ERROR"
            exit 1
        }
    } else {
        Write-Log "Minimum password length is already $currentValue (>= 14), no change needed"
    }
}

# Verify fix
Write-Log "Verifying fix..."
$output = net accounts | findstr "Minimum password length"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Minimum password length is 14" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
