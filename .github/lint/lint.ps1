#!/usr/bin/env pwsh
#Requires -Version 7.4
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '../..')).Path
Push-Location -LiteralPath $repoRoot
try {
    uv run --frozen python -B .github/lint/style_check.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    pwsh -NoProfile -File .github/lint/Invoke-PSLint.ps1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run --frozen ruff format --check .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run --frozen ruff check --ignore-noqa .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $pythonPaths = @(
        'src/vrchat_net_capture', 'src/capture_addon.py', 'src/postprocess_raw_udp.py', 'tests', '.github/lint'
    )
    uv run --frozen pyright --warnings @pythonPaths
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run --frozen python -I .github/lint/pystyle.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    uv run --frozen python -B -m unittest discover -s tests -t .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet restore VRChatNetCapture.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format VRChatNetCapture.slnx --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet build VRChatNetCapture.slnx -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet test VRChatNetCapture.slnx -c Release --no-build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet run .github/lint/CSharpStyle.cs -- .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
exit 0
