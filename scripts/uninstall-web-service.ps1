#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove Network Sentinel web scheduled task, firewall rules, and program files.

.DESCRIPTION
  %ProgramData%\NetworkSentinel is both the install folder and the data directory,
  so program files are removed but operator data is kept by default: the master
  password hash, settings, allowlist, logs, host history, threat log, the DuckDNS
  token, the TLS certificate and key, and the Posh-ACME account. Reinstalling then
  picks up where you left off. Use -PurgeData to delete all of it as well.

.PARAMETER HttpsPort
  TLS port whose firewall rule should be removed (default 18443). Use 0 to skip.

.PARAMETER PurgeData
  Also delete settings, credentials, certificates, and the ACME account.
  The Let's Encrypt account cannot be recovered afterwards -- a reinstall registers
  a new one, which counts against Let's Encrypt's rate limits.
#>
[CmdletBinding()]
param(
    [int]$Port = 18765,
    [int]$HttpsPort = 18443,
    [string]$TaskName = "NetworkSentinel-Web",
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:ProgramData "NetworkSentinel"

Write-Host "Network Sentinel - uninstall web service" -ForegroundColor Cyan

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "  Removed task: $TaskName"

# Registered by scripts\issue-duckdns-cert.ps1 when a certificate was issued.
Unregister-ScheduledTask -TaskName "NetworkSentinel-CertRenew" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "  Removed task: NetworkSentinel-CertRenew (if present)"

foreach ($rule in @("NetworkSentinel-Web-$Port", "NetworkSentinel-WebTls-$HttpsPort")) {
    netsh advfirewall firewall delete rule name="$rule" 2>$null | Out-Null
    Write-Host "  Removed firewall rule: $rule"
}

# Only ever created by pre-Kestrel installs, but clean it up so nothing is left behind.
$url = "http://+:$Port/"
netsh http delete urlacl url=$url 2>$null | Out-Null
Write-Host "  Removed URL ACL: $url (legacy, if present)"

Get-Process -Name "NetworkSentinel" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Operator data lives in this same folder. Removing the whole tree would take the
# master password, certificates, DuckDNS token, and ACME account with it, so only
# the files that came out of the package go unless -PurgeData was asked for.
$dataNames = @(
    "logs", "settings.json", "web-master.json", "web-api-tokens.json", "allowlist.json",
    "allowlist-resolved.json", "auto-block-suppress.json", "host-history.json",
    "threat-log.jsonl", "threat-intel-cache.json", "duckdns.json",
    "tls", "acme", "renew-cert.ps1"
)

if (Test-Path $InstallDir) {
    if ($PurgeData) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force
        Write-Host "  Removed (including all data): $InstallDir" -ForegroundColor Yellow
    }
    else {
        Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
            Where-Object { $dataNames -notcontains $_.Name } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed program files from: $InstallDir"

        $left = @(Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "  Kept $($left.Count) data item(s) in $InstallDir" -ForegroundColor DarkYellow
        }
    }
}

Write-Host ""
if ($PurgeData) {
    Write-Host "Done. Settings, credentials, certificates, and the ACME account were deleted." -ForegroundColor Green
}
else {
    Write-Host "Done. Settings, master password, certificates, and the ACME account were kept." -ForegroundColor Green
    Write-Host "Remove them too with:  .\uninstall-web-service.ps1 -PurgeData" -ForegroundColor DarkGray
}
