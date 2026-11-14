#!/usr/bin/env pwsh
#Requires -Version 7.4
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '../..')).Path
$pythonPaths = @(
    'src/vrchat_net_capture', 'src/capture_addon.py', 'src/postprocess_raw_udp.py', 'tests'
)
Push-Location -LiteralPath $repoRoot
try {
    Write-Host '== ruff format'
    uv run --frozen ruff format @pythonPaths
    if ($LASTEXITCODE -ne 0) { throw "ruff format failed with exit code $LASTEXITCODE" }
    Write-Host '== ruff fix'
    uv run --frozen ruff check --fix @pythonPaths
    if ($LASTEXITCODE -ne 0) { throw "ruff fix failed with exit code $LASTEXITCODE" }
    Write-Host '== dotnet format'
    dotnet format VRChatNetCapture.slnx --no-restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet format failed with exit code $LASTEXITCODE" }

    if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
        Import-Module -Name PSScriptAnalyzer
        $settings = Join-Path -Path $PSScriptRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
        $files = @('build.ps1', '.github/lint/format.ps1', '.github/lint/lint.ps1')
        foreach ($file in $files) {
            $path = Join-Path -Path $repoRoot -ChildPath $file
            $text = [IO.File]::ReadAllText($path)
            $formatted = Invoke-Formatter -ScriptDefinition $text -Settings $settings
            if ($formatted -ne $text) {
                [IO.File]::WriteAllText($path, $formatted)
                Write-Host "Formatted $file"
            }
        }
    } else {
        Write-Warning 'PSScriptAnalyzer is not installed; skipped PowerShell formatting.'
    }
} finally {
    Pop-Location
}
exit 0
