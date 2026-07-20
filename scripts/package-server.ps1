#Requires -Version 5.1
<#
.SYNOPSIS
  Build a self-contained Windows server package + one-file installer.

.DESCRIPTION
  Publishes NetworkSentinel (self-contained win-x64) and creates:

    dist\NetworkSentinel-windows-server-x64-<version>.zip
    dist\NetworkSentinel-windows-server-x64-<version>.install.ps1
    dist\*.sha256

  Copy the .install.ps1 (or the zip) to the server. No .NET SDK required there.

  Server install (Administrator PowerShell):
    powershell -ExecutionPolicy Bypass -File .\NetworkSentinel-*-windows-server-x64-*.install.ps1
    # optional:
    powershell -ExecutionPolicy Bypass -File .\....install.ps1 -Port 18765

.PARAMETER OutputDir
  Folder for artifacts (default: <repo>\dist)

.PARAMETER FrameworkDependent
  Smaller package that requires .NET 8 Desktop Runtime on the server.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$FrameworkDependent
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Project = Join-Path $Root "NetworkSentinel.csproj"
if (-not (Test-Path $Project)) {
    throw "NetworkSentinel.csproj not found. Run from the Windows branch repo."
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK is required on this build machine (not on the server)."
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $Root "dist"
}

$Version = "0.0.0"
try {
    $xml = [xml](Get-Content $Project -Raw)
    $v = $xml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
    if ($v) { $Version = $v.ToString().Trim() }
}
catch { }

$rid = "win-x64"
$flavor = if ($FrameworkDependent) { "fd" } else { "selfcontained" }
$stage = Join-Path $Root "bin\package\windows-server-$rid-$flavor"
$pkgBase = "NetworkSentinel-windows-server-x64-$Version"
$zipName = "$pkgBase.zip"
$zipPath = Join-Path $OutputDir $zipName
$installName = "$pkgBase.install.ps1"
$installPath = Join-Path $OutputDir $installName

Write-Host "Network Sentinel - package for Windows server" -ForegroundColor Cyan
Write-Host "  Project : $Project"
Write-Host "  Version : $Version"
Write-Host "  Flavor  : $flavor"
Write-Host "  Stage   : $stage"
Write-Host "  Zip     : $zipPath"
Write-Host "  Install : $installPath"
Write-Host ""

if (Test-Path $stage) {
    Remove-Item $stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$selfContained = -not $FrameworkDependent
Write-Host "Publishing (self-contained=$selfContained)..." -ForegroundColor Yellow

& dotnet publish $Project `
    -c Release `
    -r $rid `
    --self-contained $selfContained `
    -o $stage `
    /p:PublishSingleFile=false `
    /p:IncludeNativeLibrariesForSelfExtract=true `
    /p:DebugType=None `
    /p:DebugSymbols=false

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed (exit $LASTEXITCODE)."
}

$exe = Join-Path $stage "NetworkSentinel.exe"
if (-not (Test-Path $exe)) {
    throw "Publish did not produce NetworkSentinel.exe"
}

# Ship install / uninstall with the package
$installSrc = Join-Path $PSScriptRoot "install-from-package.ps1"
$uninstallSrc = Join-Path $PSScriptRoot "uninstall-web-service.ps1"
if (-not (Test-Path $installSrc)) {
    throw "Missing $installSrc"
}
Copy-Item $installSrc (Join-Path $stage "install-from-package.ps1") -Force
if (Test-Path $uninstallSrc) {
    Copy-Item $uninstallSrc (Join-Path $stage "uninstall-web-service.ps1") -Force
}

# Double-click friendly launcher inside the zip
$cmdLauncher = @"
@echo off
setlocal
cd /d "%~dp0"
echo Network Sentinel - Windows server installer
echo.
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator rights...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0install-from-package.ps1\"' -Wait"
  exit /b %ERRORLEVEL%
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-from-package.ps1" %*
"@
Set-Content -Path (Join-Path $stage "INSTALL.cmd") -Value $cmdLauncher -Encoding ASCII

# README for operators
$runtimeNote = if ($FrameworkDependent) {
    "Requires: .NET 8 Desktop Runtime (x64) on the server."
} else {
    "Requires: 64-bit Windows Server / Windows 10+ only (runtime is included)."
}

@(
    "Network Sentinel $Version - Windows server package"
    "================================================="
    ""
    "Self-contained package: $(-not $FrameworkDependent)."
    "This package does NOT require the .NET SDK or a compiler on the server."
    $runtimeNote
    ""
    "------------------------------------------------"
    "Quick install (Administrator)"
    "------------------------------------------------"
    ""
    "  1. Copy this folder (or the .zip / .install.ps1) onto the server."
    "  2. Right-click PowerShell -> Run as administrator"
    "  3. cd to the unzipped folder"
    "  4. powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1"
    ""
    "  Or double-click INSTALL.cmd (UAC elevation)."
    ""
    "Optional port:"
    "  powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1 -Port 18765"
    ""
    "One-file installer (if you have $installName):"
    "  powershell -ExecutionPolicy Bypass -File .\$installName"
    "  powershell -ExecutionPolicy Bypass -File .\$installName -Port 18765"
    ""
    "After install:"
    "  Browser:  http://localhost:18765/   (or http://SERVER-IP:18765/)"
    "  First visit creates a master password (Settings can change it later)."
    "  App folder: %ProgramData%\NetworkSentinel"
    "  Startup task: NetworkSentinel-Web (SYSTEM, at boot)"
    ""
    "Manual run (no service):"
    "  .\NetworkSentinel.exe -w 18765"
    "  .\NetworkSentinel.exe --tui"
    ""
    "Uninstall (Admin):"
    "  powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1"
) | Set-Content -Path (Join-Path $stage "INSTALL.txt") -Encoding UTF8

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Write-Host "Creating zip..." -ForegroundColor Yellow
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force

# One-file self-extracting installer: PowerShell header + embedded zip
Write-Host "Building one-file installer..." -ForegroundColor Yellow
$sfxHeader = @'
#Requires -Version 5.1
<#
.SYNOPSIS
  Network Sentinel - self-extracting Windows server installer.

.DESCRIPTION
  Extracts the embedded package and installs the headless web UI as a
  startup task (SYSTEM). No .NET SDK required on this machine.

  Run in Administrator PowerShell, or accept the UAC prompt.

.PARAMETER Port
  Web listen port (default 18765).

.PARAMETER TaskName
  Scheduled task name (default NetworkSentinel-Web).

.PARAMETER StartNow
  Start the service immediately after install (default: true).

.PARAMETER ExtractOnly
  Only extract the package to a folder; do not install.
#>
[CmdletBinding()]
param(
    [int]$Port = 18765,
    [string]$TaskName = "NetworkSentinel-Web",
    [bool]$StartNow = $true,
    [switch]$ExtractOnly,
    [string]$ExtractTo = ""
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

# Relaunch elevated unless ExtractOnly (no system changes).
if (-not $ExtractOnly -and -not (Test-IsAdministrator)) {
    Write-Host "Administrator rights required. Requesting elevation (UAC)..." -ForegroundColor Yellow
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) {
        throw "Could not resolve installer path for elevation. Right-click PowerShell -> Run as administrator."
    }

    $argList = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$scriptPath`""
        "-Port", "$Port"
        "-TaskName", "`"$TaskName`""
        "-StartNow", "`$$StartNow"
    )
    if ($ExtractOnly) { $argList += "-ExtractOnly" }
    if (-not [string]::IsNullOrWhiteSpace($ExtractTo)) {
        $argList += @("-ExtractTo", "`"$ExtractTo`"")
    }

    try {
        $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
        exit $p.ExitCode
    }
    catch {
        throw "UAC elevation was cancelled or failed. Start PowerShell as Administrator and run again. $($_.Exception.Message)"
    }
}

function Find-ArchiveOffset {
    param([byte[]]$Bytes)

    # Marker is in the script header (first few KB). Scan only a small prefix.
    $scanLen = [Math]::Min($Bytes.Length, 256KB)
    $text = [Text.Encoding]::ASCII.GetString($Bytes, 0, $scanLen)
    $marker = "# __ARCHIVE_BELOW__"
    $idx = $text.IndexOf($marker, [StringComparison]::Ordinal)
    if ($idx -lt 0) { return -1 }

    $after = $idx + $marker.Length
    if ($after -lt $text.Length -and $text[$after] -eq "`r") { $after++ }
    if ($after -lt $text.Length -and $text[$after] -eq "`n") { $after++ }
    return $after
}

$selfPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
if (-not $selfPath -or -not (Test-Path -LiteralPath $selfPath)) {
    throw "Could not resolve this installer script path."
}

Write-Host "Network Sentinel - self-extracting Windows server installer" -ForegroundColor Cyan
Write-Host "  Installer : $selfPath"
Write-Host ""

Write-Host "Reading embedded package..." -ForegroundColor Yellow
$allBytes = [IO.File]::ReadAllBytes($selfPath)
$offset = Find-ArchiveOffset -Bytes $allBytes
if ($offset -lt 0 -or $offset -ge $allBytes.Length) {
    throw "Corrupt installer: missing embedded archive marker (# __ARCHIVE_BELOW__)."
}

$zipBytes = New-Object byte[] ($allBytes.Length - $offset)
[Array]::Copy($allBytes, $offset, $zipBytes, 0, $zipBytes.Length)

# ZIP local file header signature PK\x03\x04
if ($zipBytes.Length -lt 4 -or $zipBytes[0] -ne 0x50 -or $zipBytes[1] -ne 0x4B) {
    throw "Corrupt installer: embedded data is not a ZIP archive."
}

$workRoot = if (-not [string]::IsNullOrWhiteSpace($ExtractTo)) {
    $ExtractTo
} else {
    Join-Path $env:TEMP ("NetworkSentinel-sfx-" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
$zipFile = Join-Path $workRoot "package.zip"
[IO.File]::WriteAllBytes($zipFile, $zipBytes)

$extractDir = Join-Path $workRoot "pkg"
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
Write-Host "Extracting to $extractDir ..." -ForegroundColor Yellow
Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force

# Zip may be flat files or a single top-level folder
$pkgDir = $extractDir
$probe = Join-Path $extractDir "NetworkSentinel.exe"
if (-not (Test-Path $probe)) {
    $child = Get-ChildItem $extractDir -Directory | Select-Object -First 1
    if ($child -and (Test-Path (Join-Path $child.FullName "NetworkSentinel.exe"))) {
        $pkgDir = $child.FullName
    }
}

if (-not (Test-Path (Join-Path $pkgDir "NetworkSentinel.exe"))) {
    throw "Extracted package is missing NetworkSentinel.exe."
}

if ($ExtractOnly) {
    Write-Host ""
    Write-Host "Extracted only (no install)." -ForegroundColor Green
    Write-Host "  $pkgDir"
    exit 0
}

$innerInstall = Join-Path $pkgDir "install-from-package.ps1"
if (-not (Test-Path $innerInstall)) {
    throw "Package is missing install-from-package.ps1."
}

Write-Host "Running package installer..." -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $innerInstall `
    -PackagePath $pkgDir `
    -Port $Port `
    -TaskName $TaskName `
    -StartNow $StartNow

$exit = $LASTEXITCODE
if ($null -eq $exit) { $exit = 0 }

# Clean temp extract unless user chose a permanent path
if ([string]::IsNullOrWhiteSpace($ExtractTo) -and (Test-Path $workRoot)) {
    try { Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

exit $exit

# Embedded ZIP archive follows this marker. Do not edit below.
# __ARCHIVE_BELOW__
'@

# Write UTF-8 (no BOM) header, then append raw ZIP bytes
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
# Normalize header to LF-only for a stable marker, then write with CRLF-friendly content:
# Keep the marker line exactly as "# __ARCHIVE_BELOW__" + CRLF after WriteAllText on Windows.
$headerPath = $installPath + ".hdr.tmp"
[IO.File]::WriteAllText($headerPath, $sfxHeader.TrimEnd() + "`r`n", $utf8NoBom)

$headerBytes = [IO.File]::ReadAllBytes($headerPath)
$zipBytesOut = [IO.File]::ReadAllBytes($zipPath)
$combined = New-Object byte[] ($headerBytes.Length + $zipBytesOut.Length)
[Array]::Copy($headerBytes, 0, $combined, 0, $headerBytes.Length)
[Array]::Copy($zipBytesOut, 0, $combined, $headerBytes.Length, $zipBytesOut.Length)
[IO.File]::WriteAllBytes($installPath, $combined)
Remove-Item $headerPath -Force -ErrorAction SilentlyContinue

# Checksums
function Write-Sha256File {
    param([string]$Path)
    $hash = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    $name = Split-Path $Path -Leaf
    $out = "$Path.sha256"
    Set-Content -Path $out -Value "$hash  $name" -Encoding ASCII
    return $out
}

$shaZip = Write-Sha256File -Path $zipPath
$shaInstall = Write-Sha256File -Path $installPath

$zipItem = Get-Item $zipPath
$installItem = Get-Item $installPath
Write-Host ""
Write-Host "Package ready." -ForegroundColor Green
Write-Host "  Archive   : $($zipItem.FullName)  ($([math]::Round($zipItem.Length / 1MB, 1)) MB)"
Write-Host "  Installer : $($installItem.FullName)  ($([math]::Round($installItem.Length / 1MB, 1)) MB)"
Write-Host "  Checksums : $shaZip"
Write-Host "             $shaInstall"
Write-Host ""
Write-Host "On the Windows server (Administrator PowerShell):"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\$installName"
Write-Host "  # or unzip the zip and run INSTALL.cmd / install-from-package.ps1"
Write-Host ""
Write-Host "Open after install: http://SERVER-IP:18765/  (create master password on first visit)"
