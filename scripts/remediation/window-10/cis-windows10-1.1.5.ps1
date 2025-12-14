# CIS Windows 10 1.1.5 - Simple version

Write-Host "=== STARTING REMEDIATION FOR CIS 1.1.5 ==="

# Method 1: Using secedit (standard method)
$tempInf = "$env:TEMP\pw_complex.inf"
@"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordComplexity = 1
"@ | Out-File $tempInf -Encoding ASCII

# Run secedit
Write-Host "Applying password complexity policy..."
cmd /c "secedit /configure /db %windir%\security\local.sdb /cfg `"$tempInf`" /areas SECURITYPOLICY /quiet"

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Password complexity enabled via secedit"
} else {
    Write-Host "⚠️ secedit failed, trying registry method..."
    
    # Method 2: Direct registry
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity /t REG_DWORD /d 1 /f
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Password complexity enabled via registry"
    } else {
        Write-Host "❌ All methods failed"
        exit 1
    }
}

# Verify
Write-Host "Verifying..."
$verifyFile = "$env:TEMP\verify.inf"
cmd /c "secedit /export /cfg `"$verifyFile`" /quiet"

if (Test-Path $verifyFile) {
    $content = Get-Content $verifyFile
    $found = $content | Where-Object { $_ -match "PasswordComplexity\s*=\s*1" }
    
    if ($found) {
        Write-Host "✅ VERIFIED: PasswordComplexity = 1"
        exit 0
    } else {
        # Check registry
        $regValue = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity 2>$null
        if ($regValue -match "0x1") {
            Write-Host "✅ VERIFIED in registry: PasswordComplexity = 1"
            exit 0
        }
        Write-Host "❌ Verification failed"
        exit 1
    }
} else {
    Write-Host "⚠️ Cannot verify with secedit"
    
    # Check registry
    $regValue = reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity 2>$null
    if ($regValue -match "0x1") {
        Write-Host "✅ VERIFIED in registry: PasswordComplexity = 1"
        exit 0
    }
    Write-Host "❌ Verification failed"
    exit 1
}
