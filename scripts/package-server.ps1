#Requires -Version 5.1
<#
.SYNOPSIS
  Build a self-contained Windows server package (no compile / no .NET SDK on the target).

.DESCRIPTION
  Publishes NetworkSentinel as a self-contained win-x64 app and creates:

    dist\NetworkSentinel-windows-server-x64.zip

  Copy that zip to the server, unzip, and run install-from-package.ps1 as Admin.

.PARAMETER OutputDir
  Folder for the zip (default: <repo>\dist)

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

$Version = "0.2.0"
try {
    $xml = [xml](Get-Content $Project -Raw)
    $v = $xml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
    if ($v) { $Version = $v.ToString().Trim() }
}
catch { }

$rid = "win-x64"
$flavor = if ($FrameworkDependent) { "fd" } else { "selfcontained" }
$stage = Join-Path $Root "bin\package\windows-server-$rid-$flavor"
$zipName = "NetworkSentinel-windows-server-x64-$Version.zip"
$zipPath = Join-Path $OutputDir $zipName

Write-Host "Network Sentinel - package for server" -ForegroundColor Cyan
Write-Host "  Project : $Project"
Write-Host "  Flavor  : $flavor"
Write-Host "  Stage   : $stage"
Write-Host "  Zip     : $zipPath"
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
    /p:IncludeNativeLibrariesForSelfExtract=true

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed (exit $LASTEXITCODE)."
}

$exe = Join-Path $stage "NetworkSentinel.exe"
if (-not (Test-Path $exe)) {
    throw "Publish did not produce NetworkSentinel.exe"
}

# Ship the no-build installer with the package
$installSrc = Join-Path $PSScriptRoot "install-from-package.ps1"
$uninstallSrc = Join-Path $PSScriptRoot "uninstall-web-service.ps1"
if (-not (Test-Path $installSrc)) {
    throw "Missing $installSrc"
}
Copy-Item $installSrc (Join-Path $stage "install-from-package.ps1") -Force
if (Test-Path $uninstallSrc) {
    Copy-Item $uninstallSrc (Join-Path $stage "uninstall-web-service.ps1") -Force
}

# README for operators
@(
    "Network Sentinel - Windows server package (self-contained: $(-not $FrameworkDependent))"
    ""
    "This package does NOT require the .NET SDK or a compiler on the server."
    $(if ($FrameworkDependent) { "Requires: .NET 8 Desktop Runtime (x64) on the server." } else { "Requires: 64-bit Windows only (runtime is included)." })
    ""
    "Install (Administrator PowerShell):"
    "  1. Unzip this folder onto the server (any path)."
    "  2. Right-click PowerShell -> Run as administrator"
    "  3. cd to the unzipped folder"
    "  4. powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1"
    ""
    "Optional port:"
    "  powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1 -Port 18765"
    ""
    "After install:"
    "  Browser:  http://localhost:18765/   (or http://SERVER-IP:18765/)"
    "  First visit creates a master password."
    "  App folder: %ProgramData%\NetworkSentinel"
    "  Task: NetworkSentinel-Web"
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
# Compress-Archive needs a clean folder name inside the zip
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force

$zipItem = Get-Item $zipPath
Write-Host ""
Write-Host "Package ready." -ForegroundColor Green
Write-Host "  $($zipItem.FullName)"
Write-Host "  Size: $([math]::Round($zipItem.Length / 1MB, 1)) MB"
Write-Host ""
Write-Host "Copy the zip to the server, unzip, then run install-from-package.ps1 as Administrator."
