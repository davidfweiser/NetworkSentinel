#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install Network Sentinel headless web UI as a Windows Scheduled Task (runs at startup, elevated).

.DESCRIPTION
  Publishes the app, installs under %ProgramData%\NetworkSentinel, registers a scheduled task
  that starts:  NetworkSentinel.exe -w [PORT]
  at system startup (highest privileges).

.PARAMETER Port
  Web listen port (default 18765).

.PARAMETER TaskName
  Scheduled task name (default NetworkSentinel-Web).
#>
[CmdletBinding()]
param(
    [int]$Port = 18765,
    [string]$TaskName = "NetworkSentinel-Web"
)

$ErrorActionPreference = "Stop"

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be 1-65535."
}

$Root = Split-Path -Parent $PSScriptRoot
$Project = Join-Path $Root "NetworkSentinel.csproj"
if (-not (Test-Path $Project)) {
    throw "NetworkSentinel.csproj not found."
}

$InstallDir = Join-Path $env:ProgramData "NetworkSentinel"
$PublishDir = Join-Path $Root "bin\publish\win-x64-server"
$ExeName = "NetworkSentinel.exe"

Write-Host "Network Sentinel - install web service" -ForegroundColor Cyan
Write-Host "  Port      : $Port"
Write-Host "  Install   : $InstallDir"
Write-Host "  Task name : $TaskName"
Write-Host ""

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK not found."
}

Write-Host "Publishing..." -ForegroundColor Yellow
& dotnet publish $Project -c Release -r win-x64 --self-contained false -o $PublishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne "logs" } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $PublishDir "*") $InstallDir -Recurse -Force

$Exe = Join-Path $InstallDir $ExeName
if (-not (Test-Path $Exe)) { throw "Missing $Exe" }

# Allow non-admin HttpListener bind on this port for all interfaces (optional convenience).
try {
    $url = "http://+:$Port/"
    $existing = netsh http show urlacl url=$url 2>$null
    if ("$existing" -notmatch [regex]::Escape($url)) {
        Write-Host "Reserving URL ACL for $url ..." -ForegroundColor Yellow
        netsh http add urlacl url=$url user="Everyone" | Out-Null
    }
}
catch {
    Write-Host "URL ACL note: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Open Windows Firewall for the web UI (inbound TCP)
$fwName = "NetworkSentinel-Web-$Port"
try {
    netsh advfirewall firewall delete rule name="$fwName" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="$fwName" dir=in action=allow protocol=TCP localport=$Port enable=yes profile=any description="Network Sentinel headless web UI" | Out-Null
    Write-Host "Firewall rule added: $fwName" -ForegroundColor Yellow
}
catch {
    Write-Host "Firewall rule note: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Scheduled task at startup, highest privileges
$arg = "-w $Port"
$action = New-ScheduledTaskAction -Execute $Exe -Argument $arg -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Network Sentinel headless web UI (-w $Port)" | Out-Null

Write-Host "Starting task..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Installed." -ForegroundColor Green
Write-Host "  App     : $Exe -w $Port"
Write-Host "  Task    : $TaskName (At startup, SYSTEM, highest)"
Write-Host "  Open    : http://localhost:$Port/  (or http://<server-ip>:$Port/)"
Write-Host "  First visit creates a master password."
Write-Host ""
Write-Host "Uninstall:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-web-service.ps1 -Port $Port"
