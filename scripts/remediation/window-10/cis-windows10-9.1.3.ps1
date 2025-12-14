# CIS Windows 10 9.1.3 - Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 9.1.3 ==="

# Variables
$RuleId = "cis-windows10-9.1.3"
$TestCommand = 'netsh advfirewall show domainprofile settings | findstr "Inbound user notification"'
$Expected = "Disable"

# Backup current setting
Write-Log "Backing up current firewall settings..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "firewall_settings_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
netsh advfirewall show domainprofile settings > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Disabling firewall notifications for Domain profile..."
netsh advfirewall set domainprofile settings inboundusernotification disable

if ($LASTEXITCODE -eq 0) {
    Write-Log "Firewall notifications disabled successfully"
} else {
    Write-Log "Failed to disable firewall notifications (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = netsh advfirewall show domainprofile settings | findstr "Inbound user notification"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Firewall notifications are DISABLED" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
