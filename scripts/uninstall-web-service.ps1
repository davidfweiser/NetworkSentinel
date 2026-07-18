#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove Network Sentinel web scheduled task, firewall rule, URL ACL, and install folder.
#>
[CmdletBinding()]
param(
    [int]$Port = 18765,
    [string]$TaskName = "NetworkSentinel-Web"
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:ProgramData "NetworkSentinel"

Write-Host "Network Sentinel - uninstall web service" -ForegroundColor Cyan

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "  Removed task: $TaskName"

$fwName = "NetworkSentinel-Web-$Port"
netsh advfirewall firewall delete rule name="$fwName" 2>$null | Out-Null
Write-Host "  Removed firewall rule: $fwName"

$url = "http://+:$Port/"
netsh http delete urlacl url=$url 2>$null | Out-Null
Write-Host "  Removed URL ACL: $url"

Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

if (Test-Path $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "  Removed: $InstallDir"
}

Write-Host ""
Write-Host "Done. Per-user settings under %LocalAppData%\NetworkSentinel were left intact." -ForegroundColor Green
