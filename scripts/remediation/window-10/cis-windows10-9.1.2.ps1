# CIS Windows 10 9.1.2 - Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 9.1.2 ==="

# Variables
$RuleId = "cis-windows10-9.1.2"
$TestCommand = 'netsh advfirewall show domainprofile firewallpolicy | findstr "Firewall Policy"'
$Expected = "BlockInbound"

# Backup current setting
Write-Log "Backing up current firewall policy..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "firewall_policy_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
netsh advfirewall show domainprofile firewallpolicy > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Setting Domain inbound connections to Block..."
netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound

if ($LASTEXITCODE -eq 0) {
    Write-Log "Firewall policy set to BlockInbound successfully"
} else {
    Write-Log "Failed to set firewall policy (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = netsh advfirewall show domainprofile firewallpolicy | findstr "Firewall Policy"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Inbound connections are BLOCKED" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
