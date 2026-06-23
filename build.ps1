param(
    [string]$Version = "",
    [switch]$Package,
    [switch]$SkipZip,
    [string]$ArtifactsDir = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

try { & git config --local core.hooksPath .githooks 2>$null } catch {}

$BuildDir = Join-Path $PSScriptRoot "dist"
$StateFile = Join-Path $PSScriptRoot ".local_build_state.json"
$CreatePackage = $Package -and -not $SkipZip

if ($Version) {
    if ($Version -notmatch '^\d{4}\.\d+\.\d+\.\d+(-([A-Fa-f0-9]{4}|beta))?$') {
        throw "Invalid -Version '$Version'. Expected YYYY.M.D.N, YYYY.M.D.N-XXXX, or YYYY.M.D.N-beta."
    }
    $FullVersion = $Version
}
else {
    $Today = Get-Date -Format "yyyy.M.d"
    $BuildCount = 0
    if (Test-Path $StateFile) {
        $State = Get-Content $StateFile | ConvertFrom-Json
        if ($State.Date -eq $Today) { $BuildCount = [int]$State.Count + 1 }
    }
    $UID = [Guid]::NewGuid().ToString().Substring(0, 4).ToUpper()
    $FullVersion = "$Today.$BuildCount-$UID"
    @{ Date = $Today; Count = $BuildCount } | ConvertTo-Json | Out-File $StateFile -Encoding utf8
}

$AsmVersion = ($FullVersion -split '-')[0]
$VersionFile = Join-Path $PSScriptRoot "version.txt"
[System.IO.File]::WriteAllText($VersionFile, $FullVersion, [System.Text.UTF8Encoding]::new($false))
Write-Host "Building Version: $FullVersion" -ForegroundColor Cyan

if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory $BuildDir -Force | Out-Null

Write-Host "`n--- Publishing ---" -ForegroundColor Cyan
$PubArgs = @(
    "-c", "Release",
    "-r", "win-x64",
    "--self-contained", "true",
    "/p:Version=$AsmVersion",
    "/p:PublishSingleFile=true",
    "-o", $BuildDir,
    "--nologo"
)
dotnet publish "src/VRChatNetCapture/VRChatNetCapture.csproj" @PubArgs
if ($LASTEXITCODE -ne 0) { throw "VRChatNetCapture publish failed" }

$NativeBuildDir = Join-Path $PSScriptRoot "src\VRChatNetCapture\bin\Release\net10.0-windows\win-x64"
foreach ($file in @("WinDivert.dll", "WinDivert64.sys")) {
    $nativePath = Join-Path $NativeBuildDir $file
    if (-not (Test-Path -LiteralPath $nativePath)) {
        throw "Missing native packet capture dependency: $nativePath"
    }
    Copy-Item $nativePath (Join-Path $BuildDir $file) -Force
}

foreach ($file in @("README.md", "CHANGELOG.md", "LICENSE", "NOTICE", "THIRD-PARTY-WinDivert-LICENSE.txt", "version.txt")) {
    Copy-Item (Join-Path $PSScriptRoot $file) (Join-Path $BuildDir $file) -Force
}

Get-ChildItem $BuildDir -Filter "*.pdb" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue

$InstallManifestPath = Join-Path $BuildDir "release-manifest.tsv"
$InstallManifestLines = Get-ChildItem $BuildDir -Recurse -File |
    Where-Object { $_.FullName -ne $InstallManifestPath } |
    Sort-Object FullName |
    ForEach-Object {
        $relPath = $_.FullName.Substring($BuildDir.Length + 1) -replace '\\', '/'
        $sha = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$sha`t$($_.Length)`t$relPath"
    }
[System.IO.File]::WriteAllLines($InstallManifestPath, [string[]]$InstallManifestLines, [System.Text.UTF8Encoding]::new($false))

if ($CreatePackage) {
    $ArtifactRoot = if ($ArtifactsDir) { $ArtifactsDir } else { $BuildDir }
    if (-not [System.IO.Path]::IsPathRooted($ArtifactRoot)) {
        $ArtifactRoot = Join-Path $PSScriptRoot $ArtifactRoot
    }
    if (-not (Test-Path $ArtifactRoot)) { New-Item -ItemType Directory $ArtifactRoot -Force | Out-Null }

    $ManifestPath = Join-Path $ArtifactRoot "VRChatNetCapture-v$FullVersion.manifest.tsv"
    $ZipPath = Join-Path $ArtifactRoot "VRChatNetCapture-v$FullVersion.zip"
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

    $PackageFiles = Get-ChildItem $BuildDir -Recurse -File | Sort-Object FullName
    $manifestLines = $PackageFiles | ForEach-Object {
        $relPath = $_.FullName.Substring($BuildDir.Length + 1) -replace '\\', '/'
        $sha = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        "$sha`t$($_.Length)`t$relPath"
    }
    $PackageInputs = Get-ChildItem $BuildDir -Force | ForEach-Object { $_.FullName }
    [System.IO.File]::WriteAllLines($ManifestPath, [string[]]$manifestLines, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Manifest: $ManifestPath ($($manifestLines.Count) files)" -ForegroundColor Cyan

    Compress-Archive -Path $PackageInputs -DestinationPath $ZipPath
    Write-Host "`nRelease zip: $ZipPath" -ForegroundColor Green
}

Write-Host "`nBuild complete: v$FullVersion" -ForegroundColor Green
