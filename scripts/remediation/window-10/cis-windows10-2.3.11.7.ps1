# CIS Windows 10 2.3.11.7 - Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 2.3.11.7 ==="

# Variables
$RuleId = "cis-windows10-2.3.11.7"
$TestCommand = 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2>nul || echo KEY_NOT_EXIST'
$Expected = "0x5"

# Backup current registry
Write-Log "Backing up registry value..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "registry_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Setting LAN Manager authentication level to 5 (Send NTLMv2 only)..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

if ($LASTEXITCODE -eq 0) {
    Write-Log "Registry value set successfully"
} else {
    Write-Log "Failed to set registry value (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2>$null

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - LAN Manager auth level is 5 (NTLMv2 only)" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
