#Requires -Version 5.1
<#
.SYNOPSIS
  Build Network Sentinel and install Start Menu + Desktop shortcuts for the current user.

.DESCRIPTION
  Publishes a framework-dependent win-x64 build to:
    %LocalAppData%\Programs\NetworkSentinel\

  Creates:
    Start Menu  -> Network Sentinel
    Desktop     -> Network Sentinel

.PARAMETER SkipDesktop
  Do not create a desktop shortcut (Start Menu only).

.PARAMETER Launch
  Start the app after install.
#>
[CmdletBinding()]
param(
    [switch]$SkipDesktop,
    [switch]$Launch
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "NetworkSentinel.csproj"))) {
    $Root = (Get-Location).Path
}

$Project = Join-Path $Root "NetworkSentinel.csproj"
if (-not (Test-Path $Project)) {
    throw "NetworkSentinel.csproj not found. Run from the repo root or scripts\ folder."
}

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\NetworkSentinel"
$ExeName = "NetworkSentinel.exe"
$PublishDir = Join-Path $Root "bin\publish\win-x64"

Write-Host "Network Sentinel - install" -ForegroundColor Cyan
Write-Host "  Project : $Project"
Write-Host "  Target  : $InstallDir"
Write-Host ""

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK not found. Install .NET 8 SDK from https://dotnet.microsoft.com/download"
}

Write-Host "Publishing Release win-x64 (framework-dependent)..." -ForegroundColor Yellow
& dotnet publish $Project `
    -c Release `
    -r win-x64 `
    --self-contained false `
    -o $PublishDir `
    /p:PublishSingleFile=false `
    /p:IncludeNativeLibrariesForSelfExtract=true

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed (exit $LASTEXITCODE)."
}

$PublishedExe = Join-Path $PublishDir $ExeName
if (-not (Test-Path $PublishedExe)) {
    throw "Publish succeeded but $ExeName was not found in $PublishDir"
}

# A running instance locks its own DLLs. Check before the wipe below, not after:
# deleting first and discovering the lock on the copy leaves a half-installed folder
# while the old process keeps running from a deleted image. The app's shortcuts are
# marked "Run as administrator", so a running copy is usually elevated and cannot be
# stopped from an unelevated install - hence the explicit instruction rather than a
# silently-ignored Stop-Process.
$running = @(Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Write-Host "Network Sentinel is running - closing it..." -ForegroundColor Yellow
    foreach ($proc in $running) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop }
        catch { Write-Host "  could not stop PID $($proc.Id): $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }
    Start-Sleep -Milliseconds 800

    $stillRunning = @(Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue)
    if ($stillRunning.Count -gt 0) {
        throw ("Network Sentinel is still running (PID $($stillRunning.Id -join ', ')) and its files are locked. " +
               "Close the app window and re-run this script. Nothing has been changed. " +
               "If it was started elevated, close it from that session or run this installer as Administrator.")
    }
}

Write-Host "Copying files to install folder..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Get-ChildItem -Path $InstallDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -Path (Join-Path $PublishDir "*") -Destination $InstallDir -Recurse -Force

$InstalledExe = Join-Path $InstallDir $ExeName
if (-not (Test-Path $InstalledExe)) {
    throw "Install copy failed - $InstalledExe missing."
}

# Ships beside the exe so Settings -> Remote access -> Issue certificate can find it;
# CertIssuanceService.FindScript looks next to the binary first.
$CertScript = Join-Path $PSScriptRoot "issue-duckdns-cert.ps1"
if (Test-Path $CertScript) {
    Copy-Item $CertScript (Join-Path $InstallDir "issue-duckdns-cert.ps1") -Force
}

# Prefer standalone .ico for shortcuts; fall back to the exe (embedded app icon).
$IconPath = $InstalledExe
$RootIcon = Join-Path $Root "Assets\icon.ico"
if (Test-Path $RootIcon) {
    Copy-Item $RootIcon (Join-Path $InstallDir "icon.ico") -Force
    $IconPath = Join-Path $InstallDir "icon.ico"
}

function New-Shortcut {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [string]$IconLocation,
        [string]$Description = "Network Sentinel - live network monitor",
        [switch]$RunAsAdmin
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($Path)
    $sc.TargetPath = $Target
    $sc.WorkingDirectory = $WorkingDirectory
    $sc.Description = $Description
    if ($IconLocation) {
        $sc.IconLocation = "$IconLocation,0"
    }
    $sc.Save()

    # Mark shortcut "Run as administrator" (app.manifest also requires elevation).
    if ($RunAsAdmin -and (Test-Path $Path)) {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        # LINKFLAGS byte at offset 0x15; 0x20 = RunAsUser
        if ($bytes.Length -gt 0x15) {
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Path, $bytes)
        }
    }
}

$StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$StartMenuShortcut = Join-Path $StartMenuDir "Network Sentinel.lnk"

Write-Host "Creating Start Menu shortcut (Run as administrator)..." -ForegroundColor Yellow
New-Shortcut -Path $StartMenuShortcut -Target $InstalledExe -WorkingDirectory $InstallDir -IconLocation $IconPath -RunAsAdmin

# Collected rather than tracked in a single variable: the loop below tries several
# folders and some of them legitimately fail, so a lone "$desktopShortcut" held
# whichever path was attempted last — normally Public\Desktop, which needs elevation
# and is exactly the one that did NOT get a shortcut. The summary then named the only
# path the user would not find an icon at.
$DesktopShortcuts = @()

if (-not $SkipDesktop) {
    # OneDrive can redirect "Desktop"; also try classic and Public so the icon is visible.
    $desktopDirs = @(
        [Environment]::GetFolderPath("Desktop"),
        (Join-Path $env:USERPROFILE "OneDrive\Desktop"),
        (Join-Path $env:USERPROFILE "Desktop"),
        (Join-Path $env:PUBLIC "Desktop")
    ) | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique

    Write-Host "Creating Desktop shortcut(s) (Run as administrator)..." -ForegroundColor Yellow
    foreach ($desk in $desktopDirs) {
        try {
            if (-not (Test-Path $desk)) {
                if ($desk -like "*\Public\*") { continue }
                New-Item -ItemType Directory -Force -Path $desk | Out-Null
            }
            $desktopShortcut = Join-Path $desk "Network Sentinel.lnk"
            New-Shortcut -Path $desktopShortcut -Target $InstalledExe -WorkingDirectory $InstallDir -IconLocation $IconPath -RunAsAdmin
            # Only after New-Shortcut returns: a throw here means no icon was written.
            $DesktopShortcuts += $desktopShortcut
            Write-Host "  -> $desktopShortcut"
        }
        catch {
            Write-Host "  (skipped $desk : $($_.Exception.Message))" -ForegroundColor DarkYellow
        }
    }
}

$UninstallPs1 = Join-Path $InstallDir "uninstall.ps1"
@(
    '# Removes Network Sentinel install folder and shortcuts for the current user.'
    '$ErrorActionPreference = "Stop"'
    '$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path'
    '$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Network Sentinel.lnk"'
    '$Desktop = Join-Path ([Environment]::GetFolderPath("Desktop")) "Network Sentinel.lnk"'
    'foreach ($p in @($StartMenu, $Desktop)) {'
    '    if (Test-Path $p) { Remove-Item $p -Force }'
    '}'
    'Write-Host "Removed shortcuts."'
    'Write-Host "Removing $InstallDir ..."'
    'Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue'
    'Start-Sleep -Milliseconds 500'
    'Remove-Item -LiteralPath $InstallDir -Recurse -Force'
) | Set-Content -Path $UninstallPs1 -Encoding UTF8

Write-Host ""
Write-Host "Installed successfully." -ForegroundColor Green
Write-Host "  App       : $InstalledExe"
Write-Host "  Start Menu: $StartMenuShortcut"
if (-not $SkipDesktop) {
    if ($DesktopShortcuts.Count -gt 0) {
        foreach ($shortcut in $DesktopShortcuts) {
            Write-Host "  Desktop   : $shortcut"
        }
    }
    else {
        # Worth saying plainly: the install itself succeeded and the Start Menu entry
        # is there, so silence here would read as "your desktop icon is somewhere".
        Write-Host "  Desktop   : none created - see the skipped notes above; use the Start Menu entry" -ForegroundColor DarkYellow
    }
}
Write-Host ""
Write-Host "Open Start and type Network Sentinel, or double-click the desktop icon."
Write-Host "Uninstall:  powershell -File `"$UninstallPs1`""
Write-Host ""

if ($Launch) {
    Start-Process -FilePath $InstalledExe -WorkingDirectory $InstallDir
}
