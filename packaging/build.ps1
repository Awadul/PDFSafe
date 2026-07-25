<#
.SYNOPSIS
    Builds the PDFSafe Windows executable and installer.

.DESCRIPTION
    Pipeline:
      1. render icons
      2. rewrite the version resource from the package version
      3. PyInstaller  -> dist\PDFSafe\
      4. sign the exe  (optional, requires a certificate)
      5. Inno Setup    -> dist\installer\PDFSafe-<version>-setup.exe
      6. sign the installer (optional)
      7. write dist\installer\latest.json for the auto-updater

.PARAMETER CertificateThumbprint
    Thumbprint of a code-signing certificate in the current user's store.
    When omitted, signing is skipped and the build is marked unsigned.

.PARAMETER SkipInstaller
    Build the executable only.

.EXAMPLE
    .\packaging\build.ps1
    .\packaging\build.ps1 -CertificateThumbprint A1B2C3... -TimestampUrl http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [string]$CertificateThumbprint = $env:PDFSAFE_CERT_THUMBPRINT,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$FeedBaseUrl = "https://updates.pdfsafe.app/desktop",
    [switch]$SkipInstaller,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$Packaging = Join-Path $Root "packaging"
$Dist = Join-Path $Root "dist"
$AppDir = Join-Path $Dist "PDFSafe"
$InstallerDir = Join-Path $Dist "installer"

function Write-Step { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor Cyan }
function Write-Note { param([string]$Message) Write-Host "    $Message" -ForegroundColor DarkGray }
function Write-Warn { param([string]$Message) Write-Host "    ! $Message" -ForegroundColor Yellow }

# Defined before first use: PowerShell resolves functions at execution time, so
# a definition further down the file would not exist yet when it is called.
function Invoke-Signing {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Thumbprint,
        [string]$Timestamp
    )

    $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if ($signtool) {
        $signtool = $signtool.Source
    }
    else {
        $found = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match "x64" } |
                 Sort-Object FullName -Descending |
                 Select-Object -First 1
        if (-not $found) { throw "signtool.exe not found. Install the Windows SDK." }
        $signtool = $found.FullName
    }

    & $signtool sign /sha1 $Thumbprint /fd SHA256 /td SHA256 /tr $Timestamp /d "PDFSafe" $Path
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $Path" }

    & $signtool verify /pa /v $Path
    if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $Path" }

    Write-Note "Signed and verified: $(Split-Path -Leaf $Path)"
}

# ---------------------------------------------------------------------------
# 0. Environment
# ---------------------------------------------------------------------------
Write-Step "Checking the build environment"

Push-Location $Root
try {
    $version = (python -c "import tomllib,pathlib; print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])").Trim()
    if (-not $version) { throw "Could not read the version from pyproject.toml" }
    Write-Note "Version: $version"

    python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller is missing. Run: pip install -e "".[dev]""" }

    python -c "import PySide6" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "PySide6 is missing. Run: pip install -e "".[desktop]""" }

    if ($Clean -and (Test-Path $Dist)) {
        Write-Note "Removing $Dist"
        Remove-Item $Dist -Recurse -Force
    }

    # -----------------------------------------------------------------------
    # 1. Icons
    # -----------------------------------------------------------------------
    Write-Step "Rendering icons"
    python (Join-Path $Root "tools\make_icons.py") --output (Join-Path $Packaging "assets")
    if ($LASTEXITCODE -ne 0) { Write-Warn "Icon generation failed; the build will use the default icon." }

    # -----------------------------------------------------------------------
    # 2. Version resource
    # -----------------------------------------------------------------------
    Write-Step "Updating the version resource"
    $parts = $version.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $tuple = "($($parts[0]), $($parts[1]), $($parts[2]), $($parts[3]))"
    $dotted = ($parts -join '.')

    $versionFile = Join-Path $Packaging "version_info.txt"
    $content = Get-Content $versionFile -Raw
    $content = $content -replace 'filevers=\([0-9, ]+\)', "filevers=$tuple"
    $content = $content -replace 'prodvers=\([0-9, ]+\)', "prodvers=$tuple"
    $content = $content -replace "StringStruct\('FileVersion', '[^']*'\)", "StringStruct('FileVersion', '$dotted')"
    $content = $content -replace "StringStruct\('ProductVersion', '[^']*'\)", "StringStruct('ProductVersion', '$dotted')"
    Set-Content -Path $versionFile -Value $content -NoNewline
    Write-Note "FileVersion = $dotted"

    # -----------------------------------------------------------------------
    # 3. PyInstaller
    # -----------------------------------------------------------------------
    Write-Step "Building the executable"
    pyinstaller (Join-Path $Packaging "pdfsafe.spec") --noconfirm --distpath $Dist --workpath (Join-Path $Root "build")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

    $exePath = Join-Path $AppDir "PDFSafe.exe"
    if (-not (Test-Path $exePath)) { throw "Expected $exePath but it was not produced" }

    $sizeMb = [math]::Round((Get-ChildItem $AppDir -Recurse | Measure-Object Length -Sum).Sum / 1MB, 1)
    Write-Note "Bundle size: $sizeMb MB"

    # -----------------------------------------------------------------------
    # 4. Sign the executable
    # -----------------------------------------------------------------------
    if ($CertificateThumbprint) {
        Write-Step "Signing the executable"
        Invoke-Signing -Path $exePath -Thumbprint $CertificateThumbprint -Timestamp $TimestampUrl
    }
    else {
        Write-Warn "No certificate supplied - the build is UNSIGNED."
        Write-Warn "Windows SmartScreen will warn users until the binary is signed by a"
        Write-Warn "certificate with established reputation. Do not ship this to consumers."
    }

    if ($SkipInstaller) {
        Write-Step "Done (installer skipped)"
        return
    }

    # -----------------------------------------------------------------------
    # 5. Installer
    # -----------------------------------------------------------------------
    Write-Step "Building the installer"
    $iscc = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if (-not $iscc) {
        foreach ($candidate in @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles}\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $candidate) { $iscc = $candidate; break }
        }
    }
    if (-not $iscc) { throw "Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php" }

    New-Item -ItemType Directory -Force -Path $InstallerDir | Out-Null
    & $iscc "/DMyAppVersion=$version" (Join-Path $Packaging "installer.iss")
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

    $installer = Join-Path $InstallerDir "PDFSafe-$version-setup.exe"
    if (-not (Test-Path $installer)) { throw "Expected $installer but it was not produced" }

    # -----------------------------------------------------------------------
    # 6. Sign the installer
    # -----------------------------------------------------------------------
    if ($CertificateThumbprint) {
        Write-Step "Signing the installer"
        Invoke-Signing -Path $installer -Thumbprint $CertificateThumbprint -Timestamp $TimestampUrl
    }

    # -----------------------------------------------------------------------
    # 7. Update manifest
    # -----------------------------------------------------------------------
    Write-Step "Writing the update manifest"
    $hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLower()
    $manifest = [ordered]@{
        version         = $version
        released        = (Get-Date -Format "yyyy-MM-dd")
        channel         = "stable"
        url             = "$FeedBaseUrl/PDFSafe-$version-setup.exe"
        sha256          = $hash
        size            = (Get-Item $installer).Length
        minimum_version = "0.1.0"
        mandatory       = $false
        notes           = "See the release notes at $FeedBaseUrl/notes/$version.md"
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $InstallerDir "latest.json") -Encoding UTF8

    Write-Step "Build complete"
    Write-Host "    Installer : $installer" -ForegroundColor Green
    Write-Host "    SHA-256   : $hash" -ForegroundColor Green
    Write-Host "    Manifest  : $(Join-Path $InstallerDir 'latest.json')" -ForegroundColor Green
    if (-not $CertificateThumbprint) {
        Write-Warn "Remember: this artifact is unsigned."
    }
}
finally {
    Pop-Location
}
