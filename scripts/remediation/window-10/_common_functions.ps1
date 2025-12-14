# Common Functions for Windows Remediation Scripts
# Version 1.0 - Security Hardening Agentless

# Global variables
$Global:BackupRoot = "C:\Windows\Temp\SecurityHardeningBackup"
$Global:LogFile = "$BackupRoot\remediation.log"
$Global:TimeoutSeconds = 300 # 5 minutes overall timeout

# ==================== LOGGING FUNCTIONS ====================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
    
    # Write to log file
    try {
        Add-Content -Path $Global:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Ignore log file errors
    }
}

function Initialize-BackupDirectory {
    param(
        [string]$RuleId
    )
    try {
        # Create backup root if not exists
        if (-not (Test-Path $Global:BackupRoot)) {
            New-Item -ItemType Directory -Path $Global:BackupRoot -Force | Out-Null
            Write-Log "Created backup directory: $Global:BackupRoot"
        }
        
        # Create rule-specific backup directory
        $ruleBackupDir = Join-Path $Global:BackupRoot $RuleId
        if (-not (Test-Path $ruleBackupDir)) {
            New-Item -ItemType Directory -Path $ruleBackupDir -Force | Out-Null
        }
        
        return $ruleBackupDir
    } catch {
        Write-Log "Failed to initialize backup directory: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ==================== SAFETY FUNCTIONS ====================
function Invoke-WithTimeout {
    param(
        [ScriptBlock]$ScriptBlock,
        [int]$TimeoutSeconds = 30,
        [string]$OperationName = "Command"
    )
    try {
        $job = Start-Job -ScriptBlock $ScriptBlock
        $result = $job | Wait-Job -Timeout $TimeoutSeconds
        
        if ($result -eq $null) {
            # Timeout occurred
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            Write-Log "$OperationName timed out after $TimeoutSeconds seconds" -Level "WARNING"
            return $null
        }
        
        $output = Receive-Job $job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        
        return $output
    } catch {
        Write-Log "Error in $OperationName : $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-RegistryPathExists {
    param(
        [string]$Path,
        [string]$ValueName
    )
    try {
        $value = Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction SilentlyContinue
        return ($null -ne $value)
    } catch {
        return $false
    }
}

# ==================== BACKUP FUNCTIONS ====================
function Backup-RegistryValue {
    param(
        [string]$BackupDir,
        [string]$RegistryPath,
        [string]$ValueName
    )
    try {
        if (Test-RegistryPathExists -Path $RegistryPath -ValueName $ValueName) {
            $value = Get-ItemProperty -Path $RegistryPath -Name $ValueName
            $backupData = @{
                "RegistryPath" = $RegistryPath
                "ValueName" = $ValueName
                "Value" = $value.$ValueName
                "ValueType" = "Registry"
                "Timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            
            $backupFile = Join-Path $BackupDir "registry_${ValueName}.json"
            $backupData | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding UTF8
            Write-Log "Backed up registry value: $RegistryPath\$ValueName"
            return $true
        } else {
            Write-Log "Registry value does not exist: $RegistryPath\$ValueName" -Level "WARNING"
            
            # Still create a backup entry indicating key doesn't exist
            $backupData = @{
                "RegistryPath" = $RegistryPath
                "ValueName" = $ValueName
                "Status" = "KEY_NOT_EXIST"
                "ValueType" = "Registry"
                "Timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            
            $backupFile = Join-Path $BackupDir "registry_${ValueName}_notexist.json"
            $backupData | ConvertTo-Json | Out-File -FilePath $backupFile -Encoding UTF8
            return $true
        }
    } catch {
        Write-Log "Failed to backup registry value $RegistryPath\$ValueName : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Backup-LocalSecurityPolicy {
    param(
        [string]$BackupDir
    )
    try {
        $backupFile = Join-Path $BackupDir "secedit_backup.inf"
        
        # Export current security policy
        secedit /export /cfg $backupFile /quiet
        if (Test-Path $backupFile) {
            Write-Log "Backed up security policy to: $backupFile"
            return $true
        } else {
            Write-Log "Failed to backup security policy" -Level "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error backing up security policy: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Backup-NetAccounts {
    param(
        [string]$BackupDir
    )
    try {
        $backupFile = Join-Path $BackupDir "net_accounts_backup.txt"
        net accounts > $backupFile 2>$null
        if (Test-Path $backupFile) {
            Write-Log "Backed up net accounts settings to: $backupFile"
            return $true
        }
        return $false
    } catch {
        Write-Log "Error backing up net accounts: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ==================== REMEDIATION FUNCTIONS ====================
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [string]$Type = "DWORD"
    )
    try {
        # Create the registry path if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Created registry path: $Path"
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Log "Set registry value: $Path\$Name = $Value ($Type)"
        return $true
    } catch {
        Write-Log "Failed to set registry value $Path\$Name : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Set-AuditPolicy {
    param(
        [string]$Subcategory,
        [string]$Success,
        [string]$Failure
    )
    try {
        $command = "auditpol /set /subcategory:`"$Subcategory`" /success:$Success /failure:$Failure"
        Write-Log "Setting audit policy: $command"
        
        Invoke-Expression $command
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Audit policy set successfully for $Subcategory"
            return $true
        } else {
            Write-Log "Failed to set audit policy for $Subcategory (exit code: $LASTEXITCODE)" -Level "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error setting audit policy: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Set-NetAccounts {
    param(
        [hashtable]$Settings
    )
    try {
        $success = $true
        foreach ($key in $Settings.Keys) {
            $value = $Settings[$key]
            $command = "net accounts /$key`:$value"
            Write-Log "Setting net accounts: $command"
            
            Invoke-Expression $command
            if ($LASTEXITCODE -ne 0) {
                Write-Log "Failed to set $key = $value (exit code: $LASTEXITCODE)" -Level "WARNING"
                $success = $false
            }
        }
        return $success
    } catch {
        Write-Log "Error setting net accounts: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Set-NetshFirewall {
    param(
        [string]$Profile,
        [string]$Setting,
        [string]$Value
    )
    try {
        $command = "netsh advfirewall set $Profile $Setting $Value"
        Write-Log "Setting firewall: $command"
        
        Invoke-Expression $command
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Firewall setting updated: $Profile $Setting = $Value"
            return $true
        } else {
            Write-Log "Failed to set firewall setting (exit code: $LASTEXITCODE)" -Level "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error setting firewall: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ==================== VERIFICATION FUNCTIONS ====================
function Test-RemediationSuccess {
    param(
        [string]$RuleId,
        [string]$TestCommand,
        [string]$ExpectedOutput
    )
    try {
        Write-Log "Verifying remediation for rule: $RuleId"
        Write-Log "Test command: $TestCommand"
        Write-Log "Expected output containing: $ExpectedOutput"
        
        # Execute test command with timeout
        $output = Invoke-WithTimeout -ScriptBlock {
            Invoke-Expression $TestCommand
        } -TimeoutSeconds 30 -OperationName "Verification"
        
        if ($output -eq $null) {
            Write-Log "Verification timed out" -Level "WARNING"
            return $false
        }
        
        # Check if expected output is in the result
        if ($output -match $ExpectedOutput) {
            Write-Log "✓ Verification PASSED - Rule $RuleId is FIXED" -Level "SUCCESS"
            return $true
        } else {
            Write-Log "✗ Verification FAILED - Expected '$ExpectedOutput' not found" -Level "WARNING"
            Write-Log "Actual output: $($output | Out-String)"
            return $false
        }
    } catch {
        Write-Log "Error during verification: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ==================== MAIN EXECUTION WRAPPER ====================
function Start-Remediation {
    param(
        [string]$RuleId,
        [ScriptBlock]$RemediationScript,
        [string]$VerificationCommand,
        [string]$ExpectedOutput
    )
    
    Write-Log "=== STARTING REMEDIATION FOR RULE: $RuleId ===" -Level "INFO"
    $startTime = Get-Date
    
    try {
        # 1. Initialize backup directory
        $backupDir = Initialize-BackupDirectory -RuleId $RuleId
        if (-not $backupDir) {
            Write-Log "Cannot continue without backup directory" -Level "ERROR"
            return $false
        }
        
        Write-Log "Backup directory: $backupDir"
        
        # 2. Execute remediation with overall timeout
        $remediationResult = Invoke-WithTimeout -ScriptBlock $RemediationScript `
            -TimeoutSeconds $Global:TimeoutSeconds `
            -OperationName "Remediation"
        
        if ($remediationResult -eq $null) {
            Write-Log "Remediation timed out after $($Global:TimeoutSeconds) seconds" -Level "ERROR"
            return $false
        }
        
        # 3. Verify remediation
        if ($VerificationCommand -and $ExpectedOutput) {
            $verified = Test-RemediationSuccess -RuleId $RuleId `
                -TestCommand $VerificationCommand `
                -ExpectedOutput $ExpectedOutput
            
            if (-not $verified) {
                Write-Log "Remediation completed but verification failed" -Level "WARNING"
                return $false
            }
        } else {
            Write-Log "No verification criteria provided, assuming success" -Level "WARNING"
        }
        
        # 4. Calculate duration
        $endTime = Get-Date
        $duration = New-TimeSpan -Start $startTime -End $endTime
        Write-Log "=== REMEDIATION COMPLETED SUCCESSFULLY ===" -Level "SUCCESS"
        Write-Log "Duration: $($duration.TotalSeconds) seconds"
        
        return $true
        
    } catch {
        Write-Log "=== REMEDIATION FAILED ===" -Level "ERROR"
        Write-Log "Error: $($_.Exception.Message)"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)"
        return $false
    }
}

# Export functions
Export-ModuleMember -Function Write-Log, Initialize-BackupDirectory, Invoke-WithTimeout, `
    Test-RegistryPathExists, Backup-RegistryValue, Backup-LocalSecurityPolicy, `
    Backup-NetAccounts, Set-RegistryValue, Set-AuditPolicy, Set-NetAccounts, `
    Set-NetshFirewall, Test-RemediationSuccess, Start-Remediation
