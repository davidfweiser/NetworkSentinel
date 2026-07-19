#Requires -Version 5.1
<#
.SYNOPSIS
  Install Network Sentinel web UI from a pre-built package (NO compile on the server).

.DESCRIPTION
  Use this on the server after copying NetworkSentinel-windows-server-x64-*.zip.

  - Unzip the package
  - Run this script from the unzipped folder
  - If not elevated, a UAC prompt will relaunch the installer as Administrator

  Installs files to %ProgramData%\NetworkSentinel and registers a startup task:
    NetworkSentinel.exe -w [PORT]

.PARAMETER PackagePath
  Path to the unzipped package folder, or to the .zip file.
  Default: folder containing this script.

.PARAMETER Port
  Web listen port (default 18765).

.PARAMETER TaskName
  Scheduled task name (default NetworkSentinel-Web).

.PARAMETER StartNow
  Start the scheduled task immediately (default: true).
#>
[CmdletBinding()]
param(
    [string]$PackagePath = "",
    [int]$Port = 18765,
    [string]$TaskName = "NetworkSentinel-Web",
    [bool]$StartNow = $true
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

# Relaunch elevated when needed (UAC). Avoids hard #Requires failure in a normal shell.
if (-not (Test-IsAdministrator)) {
    Write-Host "Administrator rights required. Requesting elevation (UAC)..." -ForegroundColor Yellow
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) {
        throw "Could not resolve script path for elevation. Right-click PowerShell -> Run as administrator, then re-run."
    }

    $argList = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$scriptPath`""
        "-Port", "$Port"
        "-TaskName", "`"$TaskName`""
        "-StartNow", "`$$StartNow"
    )
    if (-not [string]::IsNullOrWhiteSpace($PackagePath)) {
        $argList += @("-PackagePath", "`"$PackagePath`"")
    }

    try {
        $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
        exit $p.ExitCode
    }
    catch {
        throw "UAC elevation was cancelled or failed. Start PowerShell as Administrator and run the script again. $($_.Exception.Message)"
    }
}

if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Port must be 1-65535."
}

function Resolve-PackageDir {
    param([string]$PathHint)

    $candidate = $PathHint
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    }

    if (Test-Path $candidate -PathType Leaf) {
        if ([IO.Path]::GetExtension($candidate) -ieq ".zip") {
            $extract = Join-Path $env:TEMP ("NetworkSentinel-pkg-" + [Guid]::NewGuid().ToString("N"))
            New-Item -ItemType Directory -Force -Path $extract | Out-Null
            Write-Host "Extracting zip to $extract ..." -ForegroundColor Yellow
            Expand-Archive -Path $candidate -DestinationPath $extract -Force
            $candidate = $extract
        }
        else {
            throw "PackagePath must be a folder or a .zip file: $candidate"
        }
    }

    if (-not (Test-Path $candidate -PathType Container)) {
        throw "Package folder not found: $candidate"
    }

    $exe = Join-Path $candidate "NetworkSentinel.exe"
    if (-not (Test-Path $exe)) {
        # zip may have a single top-level folder
        $child = Get-ChildItem $candidate -Directory | Select-Object -First 1
        if ($child -and (Test-Path (Join-Path $child.FullName "NetworkSentinel.exe"))) {
            return $child.FullName
        }
        throw "NetworkSentinel.exe not found under $candidate. Unzip the full package."
    }

    return (Resolve-Path $candidate).Path
}

$SourceDir = Resolve-PackageDir -PathHint $PackagePath
$InstallDir = Join-Path $env:ProgramData "NetworkSentinel"
$ExeName = "NetworkSentinel.exe"

Write-Host "Network Sentinel - install from package (no build)" -ForegroundColor Cyan
Write-Host "  Source    : $SourceDir"
Write-Host "  Install   : $InstallDir"
Write-Host "  Port      : $Port"
Write-Host "  Task name : $TaskName"
Write-Host ""

# Stop previous instance
Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Write-Host "Copying files..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("logs") } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Copy-Item -Path (Join-Path $SourceDir "*") -Destination $InstallDir -Recurse -Force

$Exe = Join-Path $InstallDir $ExeName
if (-not (Test-Path $Exe)) {
    throw "Install copy failed - missing $Exe"
}

# URL ACL so HttpListener can bind all interfaces when not running as admin user
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

# Firewall inbound TCP for web UI
$fwName = "NetworkSentinel-Web-$Port"
try {
    netsh advfirewall firewall delete rule name="$fwName" 2>$null | Out-Null
    netsh advfirewall firewall add rule name="$fwName" dir=in action=allow protocol=TCP localport=$Port enable=yes profile=any description="Network Sentinel headless web UI" | Out-Null
    Write-Host "Firewall rule: $fwName" -ForegroundColor Yellow
}
catch {
    Write-Host "Firewall note: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Startup task (SYSTEM, highest)
$arg = "-w $Port"
$action = New-ScheduledTaskAction -Execute $Exe -Argument $arg -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Network Sentinel headless web UI (-w $Port)" | Out-Null

if ($StartNow) {
    Write-Host "Starting task..." -ForegroundColor Yellow
    Start-ScheduledTask -TaskName $TaskName
}

Write-Host ""
Write-Host "Installed successfully (no compile required)." -ForegroundColor Green
Write-Host "  App     : $Exe -w $Port"
Write-Host "  Task    : $TaskName"
Write-Host "  Open    : http://localhost:$Port/  or  http://<server-ip>:$Port/"
Write-Host "  First browser visit creates a master password."
Write-Host ""
Write-Host "Uninstall (Admin):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'uninstall-web-service.ps1')`" -Port $Port"
Write-Host "  # or from the package folder: .\uninstall-web-service.ps1"
