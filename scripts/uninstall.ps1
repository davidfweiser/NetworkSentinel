#Requires -Version 5.1
<#
.SYNOPSIS
  Remove Network Sentinel Start Menu / Desktop shortcuts and the install folder.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\NetworkSentinel"
$StartMenuShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Network Sentinel.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Network Sentinel.lnk"

Write-Host "Network Sentinel — uninstall" -ForegroundColor Cyan

foreach ($p in @($StartMenuShortcut, $DesktopShortcut)) {
    if (Test-Path $p) {
        Remove-Item $p -Force
        Write-Host "  Removed shortcut: $p"
    }
}

if (Test-Path $InstallDir) {
    # Stop running instances that lock files
    Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "  Removed app folder: $InstallDir"
} else {
    Write-Host "  Install folder not found (already removed)."
}

Write-Host ""
Write-Host "Done. Settings under %LocalAppData%\NetworkSentinel were left in place." -ForegroundColor Green
Write-Host "Delete that folder manually if you also want a clean settings reset."
