# CIS Windows 10 9.1.1 - Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 9.1.1 ==="

# Variables
$RuleId = "cis-windows10-9.1.1"
$TestCommand = 'netsh advfirewall show domainprofile state | findstr "State"'
$Expected = "ON"

# Backup current setting
Write-Log "Backing up current firewall state..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "firewall_state_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
netsh advfirewall show domainprofile state > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Setting Domain firewall state to ON..."
netsh advfirewall set domainprofile state on

if ($LASTEXITCODE -eq 0) {
    Write-Log "Firewall state set to ON successfully"
} else {
    Write-Log "Failed to set firewall state (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = netsh advfirewall show domainprofile state | findstr "State"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Firewall state is ON" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
