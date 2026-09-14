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
  Web listen port. Defaults to the port the installed task is already using, or
  18765 on a first install. Passing -Port explicitly always wins.

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

# An upgrade must not move the console.
#
# Every install used to register the task with the default port, so a console on any
# other port disappeared from the address people had bookmarked and from whatever app
# was pointed at it - and reinstalling the previous version, the obvious thing to try
# next, wrote the same default again. The port already in use is read back from the
# registered task's own arguments; -Port still wins when it is given.
$PortExplicit = $PSBoundParameters.ContainsKey('Port')
$PreviousPort = 0

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    foreach ($existingAction in $existingTask.Actions) {
        if ($existingAction.Arguments -match '(?:^|\s)-w\s+(\d{1,5})(?:\s|$)') {
            $found = [int]$Matches[1]
            if ($found -ge 1 -and $found -le 65535) { $PreviousPort = $found }
            break
        }
    }
}

$KeptPort = $false
if (-not $PortExplicit -and $PreviousPort -ne 0 -and $PreviousPort -ne $Port) {
    $Port = $PreviousPort
    $KeptPort = $true
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
if ($KeptPort) {
    Write-Host "  Port      : $Port (kept from the installed task; pass -Port to change it)"
}
else {
    Write-Host "  Port      : $Port"
}
Write-Host "  Install   : $InstallDir"
Write-Host "  Task name : $TaskName"
Write-Host ""

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK not found."
}

Write-Host "Publishing..." -ForegroundColor Yellow
& dotnet publish $Project -c Release -r win-x64 --self-contained false -o $PublishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

# The running console holds its files, and the task re-launches a console that is not
# running (see the trigger below), so stop both before replacing anything. Registering
# the task again re-enables it.
# If the install then fails, the trap turns the task back on: left disabled, the console
# would not start at the next boot either, and nothing would say why.
$TaskDisabled = $false
trap {
    if ($TaskDisabled) {
        Enable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    }
    break
}
if ($existingTask) {
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    $TaskDisabled = $true
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

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
if ($PreviousPort -ne 0 -and $PreviousPort -ne $Port) {
    # The rule name carries the port, so a deliberate move would otherwise leave the
    # old port allowed inbound with nothing listening on it.
    $stale = "NetworkSentinel-Web-$PreviousPort"
    try {
        netsh advfirewall firewall delete rule name="$stale" 2>$null | Out-Null
        Write-Host "Removed the firewall rule for the previous port: $stale" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Note: could not remove $stale - $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}
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

# A boot trigger fires once, and -RestartCount only retries a launch Task Scheduler could
# not make: a console that starts and then exits with an error is left stopped. The
# trigger repeats every 5 minutes for as long as the machine is up; with IgnoreNew a tick
# while the console runs does nothing, and one after it stopped starts it.
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition

# ExecutionTimeLimit zero is no limit; the default of 72 hours ends the console three days in.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Network Sentinel headless web UI (-w $Port)" | Out-Null

Write-Host "Starting task..." -ForegroundColor Yellow
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Installed." -ForegroundColor Green
Write-Host "  App     : $Exe -w $Port"
Write-Host "  Task    : $TaskName (At startup, SYSTEM, highest; restarted within 5 minutes if it stops)"
Write-Host "  Open    : http://localhost:$Port/  (or http://<server-ip>:$Port/)"
Write-Host "  First visit creates a master password."
Write-Host ""
Write-Host "Uninstall:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-web-service.ps1 -Port $Port"
