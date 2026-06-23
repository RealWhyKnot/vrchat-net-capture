#!/usr/bin/env pwsh
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

function Invoke-Native {
    param([string]$Name, [scriptblock]$Command)
    Write-Host "== $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

& git config --local core.hooksPath .githooks

Write-Host '== PowerShell syntax'
& .\.github\scripts\Test-WorkflowSyntax.ps1

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    throw 'PSScriptAnalyzer is required. Install it with: Install-Module PSScriptAnalyzer -Scope CurrentUser'
}
Import-Module PSScriptAnalyzer
$psFiles = @(
    & git ls-files '*.ps1' '*.psm1' '*.psd1'
    & git ls-files --others --exclude-standard '*.ps1' '*.psm1' '*.psd1'
) | Where-Object { $_ }
if ($psFiles) {
    Write-Host '== PSScriptAnalyzer'
    $findings = foreach ($file in $psFiles) {
        $path = Join-Path $RepoRoot $file
        if (-not (Test-Path -LiteralPath $path)) { continue }
        Invoke-ScriptAnalyzer -Path $path -Severity Error
    }
    if ($findings) {
        $findings | Format-Table -AutoSize
        throw "PSScriptAnalyzer reported $($findings.Count) error(s)."
    }
}

Invoke-Native 'ruff format check' { python -m ruff format --check . }
Invoke-Native 'ruff check' { python -m ruff check . }
Invoke-Native 'unittest' { python -m unittest discover }
Invoke-Native 'dotnet format check' { dotnet format src/VRChatNetCapture/VRChatNetCapture.csproj --verify-no-changes }
Invoke-Native 'dotnet test harness' { dotnet run --project src/VRChatNetCapture.Tests/VRChatNetCapture.Tests.csproj --configuration Release }
