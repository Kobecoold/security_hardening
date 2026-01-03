# CIS Windows 10 17.5.4 - Ensure 'Audit Logon' is set to 'Success and Failure'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 17.5.4 ==="

# Variables
$RuleId = "cis-windows10-17.5.4"
$TestCommand = 'auditpol /get /subcategory:"Logon" | findstr "Logon"'
$Expected = "Success and Failure"

# Backup current setting
Write-Log "Backing up current audit policy..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "audit_policy_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
auditpol /get /subcategory:"Logon" > $backupFile 2>$null
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix
Write-Log "Setting Audit Logon to Success and Failure..."
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

if ($LASTEXITCODE -eq 0) {
    Write-Log "Audit policy set successfully"
} else {
    Write-Log "Failed to set audit policy (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = auditpol /get /subcategory:"Logon" | findstr "Logon"

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Audit Logon is Success and Failure" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
