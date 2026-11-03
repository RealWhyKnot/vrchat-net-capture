#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$Version = '',
    [switch]$Package,
    [switch]$SkipZip,
    [string]$ArtifactsDir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-ManifestLine {
    [CmdletBinding()]
    [OutputType([string])]
    param([System.IO.FileInfo[]] $Files, [string] $BuildDirectory)
    foreach ($file in $Files) {
        $relativePath = $file.FullName.Substring($BuildDirectory.Length + 1) -replace '\\', '/'
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        "$hash`t$($file.Length)`t$relativePath"
    }
}

Set-Location -LiteralPath $PSScriptRoot
$BuildDir = Join-Path -Path $PSScriptRoot -ChildPath 'dist'
$BuildCapturesDir = Join-Path -Path $BuildDir -ChildPath 'captures'
$StateFile = Join-Path -Path $PSScriptRoot -ChildPath '.local_build_state.json'
$CreatePackage = $Package -and -not $SkipZip

if ($Version) {
    if ($Version -notmatch '^\d{4}\.\d+\.\d+\.\d+(-([A-Fa-f0-9]{4}|beta))?$') {
        throw "Invalid -Version '$Version'. Expected YYYY.M.D.N, YYYY.M.D.N-XXXX, or YYYY.M.D.N-beta."
    }
    $FullVersion = $Version
} else {
    $Today = Get-Date -Format 'yyyy.M.d'
    $BuildCount = 0
    if (Test-Path -LiteralPath $StateFile) {
        $State = [IO.File]::ReadAllText($StateFile) | ConvertFrom-Json
        if ($null -ne $State) {
            $stateDate = $State.PSObject.Properties['Date']
            $stateCount = $State.PSObject.Properties['Count']
            if ($stateDate -and $stateDate.Value -eq $Today) {
                $previousCount = if ($stateCount) { [int]$stateCount.Value } else { 0 }
                $BuildCount = $previousCount + 1
            }
        }
    }
    $UID = [Guid]::NewGuid().ToString().Substring(0, 4).ToUpper()
    $FullVersion = "$Today.$BuildCount-$UID"
    $stateJson = @{ Date = $Today; Count = $BuildCount } | ConvertTo-Json -Depth 2
    [IO.File]::WriteAllText($StateFile, $stateJson)
}

$AsmVersion = ($FullVersion -split '-')[0]
$VersionFile = Join-Path -Path $PSScriptRoot -ChildPath 'version.txt'
[System.IO.File]::WriteAllText($VersionFile, $FullVersion, [System.Text.UTF8Encoding]::new($false))
Write-Host "Building Version: $FullVersion" -ForegroundColor Cyan

if (Test-Path -LiteralPath $BuildDir) {
    $buildFiles = @(Get-ChildItem -LiteralPath $BuildDir -Force | Where-Object { $_.Name -ne 'captures' })
    foreach ($buildFile in $buildFiles) {
        Remove-Item -LiteralPath $buildFile.FullName -Recurse -Force
    }
}
$null = New-Item -ItemType Directory -Path $BuildDir -Force

Write-Host "`n--- Publishing ---" -ForegroundColor Cyan
$PubArgs = @(
    '-c', 'Release',
    '-r', 'win-x64',
    '--self-contained', 'true',
    "/p:Version=$AsmVersion",
    '/p:PublishSingleFile=true',
    '-o', $BuildDir,
    '--nologo'
)
dotnet publish 'src/VRChatNetCapture/VRChatNetCapture.csproj' @PubArgs
if ($LASTEXITCODE -ne 0) { throw 'VRChatNetCapture publish failed' }

$NativeBuildDir = Join-Path -Path $PSScriptRoot -ChildPath 'src\VRChatNetCapture\bin\Release\net10.0\win-x64'
foreach ($file in @('WinDivert.dll', 'WinDivert64.sys')) {
    $nativePath = Join-Path -Path $NativeBuildDir -ChildPath $file
    if (-not (Test-Path -LiteralPath $nativePath)) {
        throw "Missing native packet capture dependency: $nativePath"
    }
    Copy-Item -LiteralPath $nativePath -Destination (Join-Path -Path $BuildDir -ChildPath $file) -Force
}

$releaseDocuments = @(
    'README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'THIRD-PARTY-WinDivert-LICENSE.txt', 'version.txt'
)
foreach ($file in $releaseDocuments) {
    $sourcePath = Join-Path -Path $PSScriptRoot -ChildPath $file
    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path -Path $BuildDir -ChildPath $file) -Force
}

foreach ($symbols in @(Get-ChildItem -LiteralPath $BuildDir -Filter '*.pdb' -Recurse)) {
    Remove-Item -LiteralPath $symbols.FullName -Force -ErrorAction SilentlyContinue
}

$InstallManifestPath = Join-Path -Path $BuildDir -ChildPath 'release-manifest.tsv'
$installFiles = @(Get-ChildItem -LiteralPath $BuildDir -Recurse -File |
        Where-Object {
            $_.FullName -ne $InstallManifestPath -and
            -not $_.FullName.StartsWith($BuildCapturesDir, [System.StringComparison]::OrdinalIgnoreCase)
        } | Sort-Object -Property FullName)
$InstallManifestLines = @(Get-ManifestLine -Files $installFiles -BuildDirectory $BuildDir)
[IO.File]::WriteAllLines($InstallManifestPath, [string[]]$InstallManifestLines, [Text.UTF8Encoding]::new($false))

if ($CreatePackage) {
    $ArtifactRoot = if ($ArtifactsDir) { $ArtifactsDir } else { $BuildDir }
    if (-not [System.IO.Path]::IsPathRooted($ArtifactRoot)) {
        $ArtifactRoot = Join-Path -Path $PSScriptRoot -ChildPath $ArtifactRoot
    }
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        $null = New-Item -ItemType Directory -Path $ArtifactRoot -Force
    }

    $ManifestPath = Join-Path -Path $ArtifactRoot -ChildPath "VRChatNetCapture-v$FullVersion.manifest.tsv"
    $ZipPath = Join-Path -Path $ArtifactRoot -ChildPath "VRChatNetCapture-v$FullVersion.zip"
    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

    $PackageFiles = @(Get-ChildItem -LiteralPath $BuildDir -Recurse -File |
            Where-Object {
                -not $_.FullName.StartsWith($BuildCapturesDir, [System.StringComparison]::OrdinalIgnoreCase)
            } |
            Sort-Object -Property FullName)
    $manifestLines = @(Get-ManifestLine -Files $PackageFiles -BuildDirectory $BuildDir)
    $PackageInputs = @(foreach ($file in @(Get-ChildItem -LiteralPath $BuildDir -Force)) {
            if ($file.Name -ne 'captures') { $file.FullName }
        })
    [System.IO.File]::WriteAllLines($ManifestPath, [string[]]$manifestLines, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Manifest: $ManifestPath ($($manifestLines.Count) files)" -ForegroundColor Cyan

    Compress-Archive -Path $PackageInputs -DestinationPath $ZipPath
    Write-Host "`nRelease zip: $ZipPath" -ForegroundColor Green
}

Write-Host "`nBuild complete: v$FullVersion" -ForegroundColor Green

exit 0
