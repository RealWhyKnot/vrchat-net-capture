#requires -Version 5.1
<#
.SYNOPSIS
  Start a one-shot VRChat HTTP(S) capture.

.DESCRIPTION
  Brings up mitmdump with the capture_addon, sets the Windows system proxy
  to it, and waits. On Ctrl+C / window close / mitmdump exit, restores the
  previous proxy settings. Safe to interrupt.

.PARAMETER ListenPort
  Port mitmdump listens on. Default 8080.

.PARAMETER IgnoreHosts
  Comma-separated list of hosts to skip recording (still proxied, just not
  written to disk). Default empty -- capture everything.

.PARAMETER NoCertInstall
  Skip the cert install step. Use only if you already have the mitmproxy
  CA in CurrentUser\Root.
#>

[CmdletBinding()]
param(
    [int] $ListenPort = 8080,
    [string] $IgnoreHosts = "",
    [switch] $NoCertInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CaptureRoot = Join-Path $ScriptDir 'captures'
$Stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$CaptureDir = Join-Path $CaptureRoot $Stamp
$AddonPath = Join-Path $ScriptDir 'capture_addon.py'
$ProxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$PrevProxyFile = Join-Path $CaptureDir '.previous-proxy.json'
$LatestPointer = Join-Path $CaptureRoot '.latest-session.json'

function Write-Step($msg) { Write-Host "[start-capture] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[start-capture] WARN: $msg" -ForegroundColor Yellow }
function Write-Err2($msg)  { Write-Host "[start-capture] ERROR: $msg" -ForegroundColor Red }

# ---- preflight --------------------------------------------------------------

Write-Step "session dir: $CaptureDir"
New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $CaptureDir 'bodies') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $CaptureDir 'decoded') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $CaptureDir 'by-host') | Out-Null

# Find a real Python -- avoid the Microsoft Store stub which is named
# python.exe but is just a launcher to the Store.
function Find-Python {
    $candidates = @()
    # py launcher first
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) { $candidates += @{ Cmd = $py.Source; Args = @('-3') } }
    # python on PATH, but skip the WindowsApps stub
    Get-Command python -All -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Source -notmatch 'WindowsApps\\python.exe$') {
            $candidates += @{ Cmd = $_.Source; Args = @() }
        }
    }
    foreach ($c in $candidates) {
        try {
            $out = & $c.Cmd @($c.Args + '--version') 2>&1
            if ($LASTEXITCODE -eq 0 -and $out -match 'Python 3\.') {
                return $c
            }
        } catch {}
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Write-Err2 "No real Python 3 found on PATH. Install Python 3.11+ from https://python.org/ (NOT the Microsoft Store stub)."
    exit 1
}
Write-Step "using python: $($py.Cmd) $($py.Args -join ' ')"

# Check mitmproxy is importable
function Invoke-Py {
    param([string[]] $RemainingArgs)
    & $py.Cmd @($py.Args + $RemainingArgs)
    return $LASTEXITCODE
}

$rc = Invoke-Py @('-c', 'import mitmproxy, sys; sys.exit(0)')
if ($rc -ne 0) {
    Write-Step "mitmproxy not installed in this Python -- installing..."
    $rc = Invoke-Py @('-m', 'pip', 'install', '--user', '-r', (Join-Path $ScriptDir 'requirements.txt'))
    if ($rc -ne 0) {
        Write-Err2 "pip install of mitmproxy failed. Run 'python -m pip install mitmproxy' manually and re-run this script."
        exit 1
    }
}

# Resolve mitmdump executable. After 'pip install [--user] mitmproxy', a
# console script 'mitmdump' / 'mitmdump.exe' is placed in Python's Scripts dir.
function Find-Mitmdump {
    param($pyCmd, $pyArgs)
    # 1. Already on PATH?
    $cmd = Get-Command 'mitmdump' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # 2. Ask Python for sysconfig's scripts dir.
    $script = @'
import sysconfig, os, sys
cands = [sysconfig.get_path("scripts")]
try:
    cands.append(sysconfig.get_path("scripts", "nt_user"))
except Exception:
    pass
cands.append(os.path.join(os.path.dirname(sys.executable), "Scripts"))
for p in cands:
    if p:
        print(p)
'@
    $dirs = & $pyCmd @($pyArgs + @('-c', $script)) 2>$null
    foreach ($d in $dirs) {
        $exe = Join-Path $d 'mitmdump.exe'
        if (Test-Path $exe) { return $exe }
        $exe = Join-Path $d 'mitmdump'
        if (Test-Path $exe) { return $exe }
    }
    return $null
}

$mitmdumpExe = Find-Mitmdump $py.Cmd $py.Args
if (-not $mitmdumpExe) {
    Write-Err2 "Cannot locate mitmdump executable. Try 'python -m pip install --user mitmproxy' and ensure Scripts dir is on PATH."
    exit 1
}
Write-Step "using mitmdump: $mitmdumpExe"

# ---- cert install (first-run) ----------------------------------------------

$mitmConfDir = Join-Path $env:USERPROFILE '.mitmproxy'
$caPem = Join-Path $mitmConfDir 'mitmproxy-ca-cert.cer'

if (-not $NoCertInstall) {
    if (-not (Test-Path $caPem)) {
        Write-Step "no mitmproxy CA found yet -- generating one (a brief mitmdump run will create it)..."
        # Run mitmdump on a random free port for 3 seconds to force CA generation.
        $genProc = Start-Process -FilePath $mitmdumpExe -ArgumentList @('--listen-host', '127.0.0.1', '--listen-port', '0', '-q') -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3
        if (-not $genProc.HasExited) { Stop-Process -Id $genProc.Id -Force -ErrorAction SilentlyContinue }
    }

    if (Test-Path $caPem) {
        Write-Step "importing mitmproxy CA into CurrentUser\Root..."
        try {
            Import-Certificate -FilePath $caPem -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
            Write-Step "  CA installed for current user."
        } catch {
            Write-Warn2 "CurrentUser cert install failed: $($_.Exception.Message)"
            Write-Warn2 "HTTPS interception may not work. To install manually: certutil -addstore -user Root '$caPem'"
        }
    } else {
        Write-Warn2 "mitmproxy CA not found at $caPem after generation step. HTTPS interception will fail."
    }
}

# ---- system proxy: stash + set ---------------------------------------------

Write-Step "stashing current proxy settings..."
$prev = Get-ItemProperty -Path $ProxyKey | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
$prevDump = @{
    ProxyEnable   = if ($prev.PSObject.Properties.Match('ProxyEnable').Count)   { [int]$prev.ProxyEnable }   else { 0 }
    ProxyServer   = if ($prev.PSObject.Properties.Match('ProxyServer').Count)   { [string]$prev.ProxyServer } else { $null }
    ProxyOverride = if ($prev.PSObject.Properties.Match('ProxyOverride').Count) { [string]$prev.ProxyOverride } else { $null }
    AutoConfigURL = if ($prev.PSObject.Properties.Match('AutoConfigURL').Count) { [string]$prev.AutoConfigURL } else { $null }
}
$prevDump | ConvertTo-Json | Set-Content -Path $PrevProxyFile -Encoding utf8

# Drop a pointer so stop-capture.ps1 can find this session if our finally{} doesn't run.
@{ session_dir = $CaptureDir; pid_file = (Join-Path $CaptureDir '.mitmdump.pid') } |
    ConvertTo-Json | Set-Content -Path $LatestPointer -Encoding utf8

# Win32 InternetSetOption signature so WinINET picks the new settings up immediately.
if (-not ([System.Management.Automation.PSTypeName]'WinInetSettings').Type) {
    Add-Type -Namespace 'WinInet' -Name 'Settings' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll")]
public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);
'@ -ErrorAction SilentlyContinue
}
function Notify-WinInet {
    try {
        [WinInet.Settings]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0) | Out-Null # SETTINGS_CHANGED
        [WinInet.Settings]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0) | Out-Null # REFRESH
    } catch {}
}

function Restore-Proxy {
    Write-Step "restoring previous proxy settings..."
    try {
        if ($prevDump.ProxyEnable) {
            Set-ItemProperty -Path $ProxyKey -Name ProxyEnable -Value $prevDump.ProxyEnable -Type DWord
        } else {
            Set-ItemProperty -Path $ProxyKey -Name ProxyEnable -Value 0 -Type DWord
        }
        if ($prevDump.ProxyServer) {
            Set-ItemProperty -Path $ProxyKey -Name ProxyServer -Value $prevDump.ProxyServer
        } else {
            Remove-ItemProperty -Path $ProxyKey -Name ProxyServer -ErrorAction SilentlyContinue
        }
        if ($prevDump.ProxyOverride) {
            Set-ItemProperty -Path $ProxyKey -Name ProxyOverride -Value $prevDump.ProxyOverride
        } else {
            Remove-ItemProperty -Path $ProxyKey -Name ProxyOverride -ErrorAction SilentlyContinue
        }
        Notify-WinInet
        Write-Step "proxy restored."
    } catch {
        Write-Warn2 "Restore-Proxy failed: $($_.Exception.Message). Edit Internet Options manually if your network is broken."
    }
}

Write-Step "setting system proxy to 127.0.0.1:$ListenPort"
Set-ItemProperty -Path $ProxyKey -Name ProxyEnable -Value 1 -Type DWord
Set-ItemProperty -Path $ProxyKey -Name ProxyServer -Value "127.0.0.1:$ListenPort"
Set-ItemProperty -Path $ProxyKey -Name ProxyOverride -Value '<local>'
Notify-WinInet

# ---- launch mitmdump --------------------------------------------------------

$mitmArgs = @('--mode', 'regular',
              '--listen-host', '127.0.0.1',
              '--listen-port', "$ListenPort",
              '-s', $AddonPath,
              '--set', "capture_dir=$CaptureDir",
              '--set', "ignore_hosts_list=$IgnoreHosts",
              '--set', 'flow_detail=0')

$proc = $null
try {
    Write-Step "launching mitmdump..."
    $proc = Start-Process -FilePath $mitmdumpExe -ArgumentList $mitmArgs -PassThru -NoNewWindow
    "$($proc.Id)" | Set-Content -Path (Join-Path $CaptureDir '.mitmdump.pid') -Encoding ascii

    # Brief readiness check -- try to TCP-connect to the proxy port.
    $deadline = (Get-Date).AddSeconds(10)
    $ready = $false
    while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect('127.0.0.1', $ListenPort)
            $tcp.Close()
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) {
        Write-Err2 "mitmdump did not bind 127.0.0.1:$ListenPort within 10s. Aborting."
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        return
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host " READY. Launch VRChat now and visit the worlds you want to study." -ForegroundColor Green
    Write-Host " Capture dir: $CaptureDir"                                          -ForegroundColor Green
    Write-Host " Press Ctrl+C in this window to stop and tear everything down."     -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""

    Wait-Process -Id $proc.Id
    Write-Step "mitmdump exited (code $($proc.ExitCode))."
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Write-Step "stopping mitmdump (pid $($proc.Id))..."
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    Restore-Proxy
    Write-Step "session dir: $CaptureDir"
    Write-Step "done."
}
