#requires -Version 5.1
<#
.SYNOPSIS
  Hard-stop a vrchat-net-capture session: kill mitmdump, restore proxy.

.DESCRIPTION
  Use this if start-capture.ps1's PowerShell window was closed with the X
  button (so its finally{} block never ran) and the system proxy is still
  pointed at 127.0.0.1. Reads the latest .previous-proxy.json under
  captures/, restores it, and kills any orphan mitmdump process listed by
  its .mitmdump.pid sidecar.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CaptureRoot = Join-Path $ScriptDir 'captures'
$LatestPointer = Join-Path $CaptureRoot '.latest-session.json'
$ProxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

function Write-Step($msg) { Write-Host "[stop-capture] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[stop-capture] WARN: $msg" -ForegroundColor Yellow }

if (-not (Test-Path $CaptureRoot)) {
    Write-Step "no captures dir -- nothing to clean up."
    exit 0
}

# Discover the most recent session: prefer .latest-session.json, fall back to newest dir.
$session = $null
if (Test-Path $LatestPointer) {
    try {
        $session = (Get-Content $LatestPointer -Raw | ConvertFrom-Json).session_dir
    }
    catch {}
}
if (-not $session -or -not (Test-Path $session)) {
    $candidate = Get-ChildItem $CaptureRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName '.previous-proxy.json') } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($candidate) { $session = $candidate.FullName }
}

if (-not $session) {
    Write-Warn2 "no session with .previous-proxy.json found -- won't restore anything."
}
else {
    Write-Step "restoring proxy from $session"
    $prevFile = Join-Path $session '.previous-proxy.json'
    try {
        $prev = Get-Content $prevFile -Raw | ConvertFrom-Json
        $enable = if ($prev.PSObject.Properties.Match('ProxyEnable').Count -and $prev.ProxyEnable) { 1 } else { 0 }
        Set-ItemProperty -Path $ProxyKey -Name ProxyEnable -Value $enable -Type DWord
        if ($prev.PSObject.Properties.Match('ProxyServer').Count -and $prev.ProxyServer) {
            Set-ItemProperty -Path $ProxyKey -Name ProxyServer -Value $prev.ProxyServer
        }
        else {
            Remove-ItemProperty -Path $ProxyKey -Name ProxyServer -ErrorAction SilentlyContinue
        }
        if ($prev.PSObject.Properties.Match('ProxyOverride').Count -and $prev.ProxyOverride) {
            Set-ItemProperty -Path $ProxyKey -Name ProxyOverride -Value $prev.ProxyOverride
        }
        else {
            Remove-ItemProperty -Path $ProxyKey -Name ProxyOverride -ErrorAction SilentlyContinue
        }
        if (-not ([System.Management.Automation.PSTypeName]'WinInet.Settings').Type) {
            Add-Type -Namespace 'WinInet' -Name 'Settings' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll")]
public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);
'@ -ErrorAction SilentlyContinue
        }
        try {
            [WinInet.Settings]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0) | Out-Null
            [WinInet.Settings]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0) | Out-Null
        }
        catch {}
        Write-Step "proxy restored."
    }
    catch {
        Write-Warn2 "failed to restore proxy: $($_.Exception.Message)"
    }

    # Kill mitmdump if it's still around.
    $pidFile = Join-Path $session '.mitmdump.pid'
    if (Test-Path $pidFile) {
        try {
            $procId = [int](Get-Content $pidFile -Raw)
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($p) {
                Write-Step "killing orphan mitmdump pid=$procId"
                Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            }
        }
        catch {}
    }
}

# Belt-and-suspenders: kill any stray mitmdump on this user.
Get-Process -Name mitmdump -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Step "killing stray mitmdump pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Write-Step "done."
