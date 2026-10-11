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

.PARAMETER HttpsPort
  Also open the firewall for the TLS port (default 18443). Use 0 to skip.
  HTTPS itself is switched on in Settings -> Remote access (it persists in
  settings.json), not here -- this only makes the port reachable.

.PARAMETER TaskName
  Scheduled task name (default NetworkSentinel-Web).

.PARAMETER StartNow
  Start the scheduled task immediately (default: true).
#>
[CmdletBinding()]
param(
    [string]$PackagePath = "",
    [int]$Port = 18765,
    [int]$HttpsPort = 18443,
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

# Stop previous instance. The task goes first: it re-launches a console that is not
# running (see the trigger below), so killing only the process could let it come back
# mid-copy and hold the files being replaced. Registering the task again re-enables it.
# If the install then fails, the trap turns the task back on: left disabled, the console
# would not start at the next boot either, and nothing would say why.
$TaskDisabled = $false
trap {
    if ($TaskDisabled) {
        Enable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    }
    break
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
    $TaskDisabled = $true
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

Write-Host "Copying files..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# This folder is both the install target and the app's data directory, so an upgrade
# must replace only what the package ships. Enumerating the package and deleting just
# those names keeps every operator file -- settings, master-password hash, allowlist,
# logs, host history, threat log, duckdns.json, tls\, acme\ -- without needing a list
# that has to be updated every time the app starts writing something new.
$packageNames = @(Get-ChildItem -Path $SourceDir -Force | Select-Object -ExpandProperty Name)

# Files the package may also ship a default copy of; an existing one always wins.
$preserveNames = @(
    "logs",
    "settings.json",
    "web-master.json",
    "allowlist.json",
    "allowlist-resolved.json",
    "auto-block-suppress.json",
    "duckdns.json",
    "tls",
    "acme"
)

Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
    Where-Object { $packageNames -contains $_.Name -and $preserveNames -notcontains $_.Name } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Copy package bits; do not overwrite preserved data files if the package also ships defaults.
Get-ChildItem -Path $SourceDir -Force | ForEach-Object {
    $dest = Join-Path $InstallDir $_.Name
    if ($preserveNames -contains $_.Name -and (Test-Path $dest)) {
        return
    }
    Copy-Item -Path $_.FullName -Destination $dest -Recurse -Force
}

$Exe = Join-Path $InstallDir $ExeName
if (-not (Test-Path $Exe)) {
    throw "Install copy failed - missing $Exe"
}

# No URL ACL is reserved here. That was an HttpListener requirement; the console
# now runs on Kestrel, which binds the socket directly. Any reservation an older
# install left behind is cleaned up by uninstall-web-service.ps1.

# Firewall inbound TCP for the web UI, and for the TLS port when one is wanted.
function Add-InboundRule {
    param([string]$Name, [int]$TcpPort, [string]$Description)
    try {
        netsh advfirewall firewall delete rule name="$Name" 2>$null | Out-Null
        netsh advfirewall firewall add rule name="$Name" dir=in action=allow protocol=TCP localport=$TcpPort enable=yes profile=any description="$Description" | Out-Null
        Write-Host "Firewall rule: $Name (TCP $TcpPort)" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Firewall note ($Name): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

Add-InboundRule -Name "NetworkSentinel-Web-$Port" -TcpPort $Port -Description "Network Sentinel headless web UI"

# Opened up front so turning HTTPS on later in Settings does not also need a
# firewall change. The port is only listened on once HTTPS is actually enabled.
if ($HttpsPort -gt 0 -and $HttpsPort -ne $Port) {
    Add-InboundRule -Name "NetworkSentinel-WebTls-$HttpsPort" -TcpPort $HttpsPort -Description "Network Sentinel web console (HTTPS)"
}

# Startup task (SYSTEM, highest)
$arg = "-w $Port"
$action = New-ScheduledTaskAction -Execute $Exe -Argument $arg -WorkingDirectory $InstallDir

# A boot trigger fires once, and -RestartCount only retries a launch Task Scheduler could
# not make: a console that starts and then exits with an error is left stopped. So one
# that failed at boot - something it needs was not up yet - stayed down until somebody
# started it. The trigger repeats every 5 minutes for as long as the machine is up; with
# IgnoreNew a tick while the console runs does nothing, and one after it stopped starts it.
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)).Repetition

# ExecutionTimeLimit zero is no limit. Left out, it is Task Scheduler's default of 72
# hours, and the console was ended three days after every start.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
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
Write-Host "  Task    : $TaskName  (runs as SYSTEM at boot, before anyone logs in,"
Write-Host "            and starts it again within 5 minutes if it stops)"
Write-Host "  Open    : http://localhost:$Port/  or  http://<server-ip>:$Port/"
Write-Host "  First browser visit creates a master password. It asks for the setup code in"
Write-Host "  %ProgramData%\NetworkSentinel\setup-code.txt (Administrators only; the code"
Write-Host "  changes each time the task starts, and the file goes once a password is set)."
if ($HttpsPort -gt 0 -and $HttpsPort -ne $Port) {
    Write-Host ""
    Write-Host "  HTTPS   : TCP $HttpsPort is open in the firewall but not served yet." -ForegroundColor Cyan
    Write-Host "            Turn it on under Settings -> Remote access, or issue a free"
    Write-Host "            certificate for a duckdns.org name there, then restart the task:"
    Write-Host "              schtasks /End /TN `"$TaskName`"  &&  schtasks /Run /TN `"$TaskName`""
}
Write-Host ""
Write-Host "Uninstall (Admin):"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'uninstall-web-service.ps1')`" -Port $Port"
Write-Host "  # or from the package folder: .\uninstall-web-service.ps1"
