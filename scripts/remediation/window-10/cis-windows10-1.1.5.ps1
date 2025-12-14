# CIS Windows 10 1.1.5 - Ensure 'Password must meet complexity requirements' is set to 'Enabled'

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

Write-Log "=== STARTING REMEDIATION FOR CIS 1.1.5 ==="

# Variables
$RuleId = "cis-windows10-1.1.5"
$TestCommand = 'secedit /export /cfg %temp%\sec.cfg >nul && type "%temp%\sec.cfg" | findstr "PasswordComplexity"'
$Expected = "1"

# Backup current security policy
Write-Log "Backing up current security policy..."
$backupDir = "C:\Windows\Temp\SecurityHardeningBackup\$RuleId"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}
$backupFile = Join-Path $backupDir "secedit_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').inf"
secedit /export /cfg $backupFile /quiet
if (Test-Path $backupFile) {
    Write-Log "Backup saved to: $backupFile"
}

# Apply fix using secedit
Write-Log "Enabling password complexity requirements..."

# Create temporary INF file
$tempInf = "$env:TEMP\password_complexity.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordComplexity = 1
"@ | Out-File -FilePath $tempInf -Encoding ASCII

# Apply the policy
secedit /configure /db %windir%\security\local.sdb /cfg $tempInf /areas SECURITYPOLICY /quiet

if ($LASTEXITCODE -eq 0) {
    Write-Log "Password complexity requirements enabled successfully"
    Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
} else {
    Write-Log "Failed to enable password complexity (exit code: $LASTEXITCODE)" -Level "ERROR"
    exit 1
}

# Verify fix
Write-Log "Verifying fix..."
$output = cmd /c $TestCommand

if ($output -match $Expected) {
    Write-Log "✓ Verification PASSED - Password complexity is ENABLED" -Level "SUCCESS"
    Write-Log "=== REMEDIATION SUCCESSFUL ===" -Level "SUCCESS"
    exit 0
} else {
    Write-Log "✗ Verification FAILED" -Level "ERROR"
    Write-Log "Expected: $Expected"
    Write-Log "Got: $output"
    exit 1
}
