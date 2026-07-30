#Requires -Version 5.1
<#
.SYNOPSIS
  Build a self-contained Windows server package + one-file installer.

.DESCRIPTION
  Publishes NetworkSentinel (self-contained win-x64) and creates:

    dist\NetworkSentinel-windows-server-x64-<version>.zip
    dist\NetworkSentinel-windows-server-x64-<version>.install.cmd
    dist\*.sha256

  Copy the .install.cmd (or the zip) to the server. No .NET SDK required there.

  Server install:
    .\NetworkSentinel-windows-server-x64-<version>.install.cmd
    # optional:
    .\NetworkSentinel-windows-server-x64-<version>.install.cmd -Port 18765

  The one-file installer is a .cmd, not a .ps1, on purpose: cmd.exe stops
  reading the script at "exit /b", so an appended ZIP payload is never parsed.
  PowerShell instead tokenizes the whole file before running a single line,
  which on a 67 MB payload takes hours and then fails to parse.

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
$installName = "$pkgBase.install.cmd"
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
    "  1. Copy this folder (or the .zip / .install.cmd) onto the server."
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
    "  .\$installName"
    "  .\$installName -Port 18765"
    "  .\$installName --extract-only   (unpack only, no install)"
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

# One-file self-extracting installer: cmd.exe header + embedded zip.
#
# The header MUST be a .cmd, not a .ps1: cmd.exe reads the script command by
# command and stops at "exit /b", so the appended ZIP is never looked at.
# PowerShell parses an entire -File script before executing anything, and the
# cost of tokenizing appended binary is quadratic (1 MB ~ 3 s, 16 MB ~ 5 min)
# before it finally reports a syntax error - so the sh-style "append a payload
# after exit" trick cannot work with a PowerShell entry point.
#
# The real work runs as a PowerShell payload passed via -EncodedCommand, which
# sidesteps cmd quoting entirely. It extracts the payload and hands off to
# install-from-package.ps1, which does its own UAC elevation.
Write-Host "Building one-file installer..." -ForegroundColor Yellow

# Kept deliberately small: this is the only code that must fit on one cmd line
# (base64 of UTF-16 grows ~2.7x). Everything else lives in the package itself,
# so the stub only locates and unpacks the payload, then hands off to
# install-from-package.ps1 (which does its own UAC elevation).
$sfxPayload = @'
$ErrorActionPreference = 'Stop'
$self = $env:NS_SFX
$mark = ':__NS' + 'ZIP__:'

$fs = [IO.File]::OpenRead($self)
$head = New-Object byte[] 8192
$n = $fs.Read($head, 0, $head.Length)
$off = [Text.Encoding]::ASCII.GetString($head, 0, $n).LastIndexOf($mark)
if ($off -lt 0) { throw 'Corrupt installer: archive marker missing.' }
$off += $mark.Length
while ($off -lt $n -and ($head[$off] -eq 13 -or $head[$off] -eq 10)) { $off++ }
if ($head[$off] -ne 0x50 -or $head[$off + 1] -ne 0x4B) {
    throw 'Corrupt installer: no ZIP archive after the marker.'
}

$work = Join-Path $env:TEMP ('NetworkSentinel-sfx-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Force -Path $work
$zip = Join-Path $work 'package.zip'
$fs.Position = $off
$out = [IO.File]::Create($zip)
try { $fs.CopyTo($out, 1048576) } finally { $out.Dispose(); $fs.Dispose() }

Write-Host 'Extracting package...' -ForegroundColor Yellow
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $work 'pkg') -Force
$exe = Get-ChildItem (Join-Path $work 'pkg') -Recurse -Filter 'NetworkSentinel.exe' | Select-Object -First 1
if (-not $exe) { throw 'Extracted package is missing NetworkSentinel.exe.' }
$pkg = $exe.DirectoryName

$extra = @(($env:NS_ARGS -split '\s+') | Where-Object { $_ })
if ($extra -contains '--extract-only') {
    Write-Host "Extracted to $pkg" -ForegroundColor Green
    exit 0
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'install-from-package.ps1') -PackagePath $pkg @extra
$code = $LASTEXITCODE
if ($null -eq $code) { $code = 0 }
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
exit $code
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($sfxPayload))
if ($encoded.Length -gt 7000) {
    # cmd.exe caps a command line at 8191 characters.
    throw "Encoded SFX payload is $($encoded.Length) chars - too long for a single cmd line."
}

$sfxHeader = @"
@echo off
setlocal
rem ===================================================================
rem  Network Sentinel $Version - self-extracting Windows server installer
rem
rem  Usage:   .\$installName [-Port 18765] [--extract-only]
rem
rem  A ZIP payload is appended after the marker line at the end of this file.
rem  cmd.exe stops reading here at "exit /b", so it never tries to parse the
rem  binary tail. Do not write the marker text anywhere above it.
rem ===================================================================
set "NS_SFX=%~f0"
set "NS_ARGS=%*"
echo Network Sentinel $Version - Windows server installer
echo.
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded
set "NS_CODE=%ERRORLEVEL%"
endlocal & exit /b %NS_CODE%
:__NSZIP__:
"@
# Write the header (UTF-8 without BOM, CRLF) then stream the ZIP bytes in after
# the marker line. Streaming, not ReadAllBytes: the payload is ~67 MB and there
# is no reason to hold two copies of it in memory.
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[IO.File]::WriteAllText($installPath, $sfxHeader.TrimEnd() + "`r`n", $utf8NoBom)

$outStream = [IO.File]::Open($installPath, [IO.FileMode]::Append, [IO.FileAccess]::Write)
try {
    $zipStream = [IO.File]::OpenRead($zipPath)
    try { $zipStream.CopyTo($outStream, 1048576) } finally { $zipStream.Dispose() }
}
finally { $outStream.Dispose() }

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
Write-Host "On the Windows server:"
Write-Host "  .\$installName            (UAC prompt if not already elevated)"
Write-Host "  # or unzip the zip and run INSTALL.cmd / install-from-package.ps1"
Write-Host ""
Write-Host "Open after install: http://SERVER-IP:18765/  (create master password on first visit)"
