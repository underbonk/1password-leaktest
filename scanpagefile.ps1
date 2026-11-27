#Requires -Version 5.1
<#
.SYNOPSIS
  Scan pagefile.sys for a research Secret Key via a VSS shadow copy.
.DESCRIPTION
  Reads KEY= from a local secrets file (default: .secrets next to this script).
  The key is never printed. Creates a shadow copy of C:, streams pagefile.sys
  through instrumentation\pagefile_scan.py, then deletes the shadow copy.
  Self-elevates if not already running as administrator.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scanpagefile.ps1
.EXAMPLE
  .\scanpagefile.ps1 -KeyName SECRET_KEY
#>
param(
    [string]$SecretsFile = (Join-Path $PSScriptRoot '.secrets'),
    [string]$KeyName = 'SECRET_KEY'
)

$root = $PSScriptRoot
$scanner = Join-Path $root 'instrumentation\pagefile_scan.py'
$python = (Get-Command python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $python) { throw 'python not found on PATH' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Elevation required - relaunching as administrator...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-SecretsFile', "`"$SecretsFile`"", '-KeyName', "`"$KeyName`"")
    exit
}

$ErrorActionPreference = 'Stop'
$shadow = $null
$tempDir = Join-Path $root 'tmp'
$tempKey = Join-Path $tempDir 'research-key.txt'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    if (-not (Test-Path $scanner)) { throw "Scanner not found at $scanner" }

    $line = Get-Content $SecretsFile | Where-Object { $_ -match "^$KeyName=" } | Select-Object -First 1
    if (-not $line) { throw "Key '$KeyName' not found in $SecretsFile. Expected a line like ${KeyName}=A3-..." }
    $key = ($line -replace "^$KeyName=", '').Trim().Trim('"').Trim("'")
    if ($key -notmatch '^A3-') { Write-Host 'WARNING: key does not start with A3- (continuing anyway)' -ForegroundColor Yellow }
    Set-Content -Path $tempKey -Value $key -NoNewline

    Write-Host 'Creating VSS shadow copy of C: ...'
    $r = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
    if ($r.ReturnValue -ne 0) { throw "VSS create failed: ReturnValue $($r.ReturnValue)" }
    $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }
    Write-Host "Shadow device: $($shadow.DeviceObject)"

    $target = $shadow.DeviceObject + '\pagefile.sys'
    Write-Host "Scanning $target"
    $logFile = Join-Path $tempDir ("pagefile-scan-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
    $out = & $python $scanner --key-file $tempKey --path $target 2>&1
    $out | Tee-Object -FilePath $logFile
    Write-Host "`nLog saved to $logFile"

    if ($out -match 'no key material found') {
        Write-Host "`nRESULT: pagefile is clean for this key." -ForegroundColor Green
    } else {
        Write-Host "`nRESULT: KEY MATERIAL FOUND in pagefile.sys (offsets above)." -ForegroundColor Red
    }
}
finally {
    if ($shadow) {
        Write-Host "`nDeleting shadow copy..."
        try { $shadow.Delete() }
        catch { Write-Host "shadow delete failed: $_ - check 'vssadmin list shadows'" -ForegroundColor Yellow }
    }
    Remove-Item $tempKey -Force -ErrorAction SilentlyContinue
}
Write-Host "`nDone. (verify no leftover shadows with: vssadmin list shadows)"
