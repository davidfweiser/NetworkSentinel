<#
.SYNOPSIS
    Read-only diagnostics for a site-to-site IPSec tunnel that will not come up.

.DESCRIPTION
    Changes nothing. Every command here only reads state, so it is safe to run on
    a production gateway and safe to run repeatedly.

    The question it answers, in order:
      1. is this host blocking the peer, or the IKE ports?
      2. is the peer's traffic arriving at all, and from which address?
      3. what does Windows say about why the tunnel is down?

.PARAMETER Peer
    The far end's public address. Compare it against what the remote device's WAN
    actually is right now - a peer whose WAN IP changed is the most common cause of
    a tunnel that "just stopped".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\diagnose-ipsec.ps1 203.0.113.4
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Peer = "203.0.113.4",

    [int]$CaptureSeconds = 20
)

$ErrorActionPreference = 'Continue'

function Say([string]$title) {
    Write-Output ""
    Write-Output "=== $title ==="
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Output "Run from an elevated prompt - firewall rules, IPSec state and packet capture all need Administrator."
    Write-Output "  powershell -ExecutionPolicy Bypass -File $PSCommandPath $Peer"
    exit 1
}

Write-Output "Diagnosing IPSec tunnel to peer $Peer"
Get-Date

Say "Network Sentinel service"
$svc = Get-Service -Name 'NetworkSentinelWeb' -ErrorAction SilentlyContinue
if ($svc) {
    $svc | Format-List Name, Status, StartType | Out-String | Write-Output
} else {
    Write-Output "(NetworkSentinelWeb service not installed)"
}

Say "Firewall rules naming the peer or the IKE ports"
# Both halves matter: a rule can name the peer's address, or close 500/4500 for
# everyone. Network Sentinel's own auto-block rules are named NetworkSentinel-IP-*.
$found = 0
$dump = netsh advfirewall firewall show rule name=all 2>&1 | Out-String
$block = @()
foreach ($chunk in ($dump -split "(?m)^Rule Name:")) {
    if ($chunk -match [regex]::Escape($Peer) -or $chunk -match '\b(500|4500)\b') {
        $block += ("Rule Name:" + ($chunk -split "`n" | Select-Object -First 12 | Out-String))
        $found = 1
    }
}
if ($found) { $block | Write-Output } else { Write-Output "(no firewall rule names the peer or the IKE ports)" }
Write-Output "--> blocking rules present: $found (0 = none found, so a block is NOT the cause)"

Say "Network Sentinel's tunnel-endpoint shield"
# The shield remembers peers for 24h so a tunnel that is already down cannot be
# auto-blocked. If the peer is listed here, the app will refuse to block it.
$state = Join-Path $env:ProgramData 'NetworkSentinel\ipsec-endpoints.json'
if (Test-Path $state) {
    Get-Content $state -Raw | Write-Output
    Write-Output "--> if $Peer is listed, auto-block is already refusing to touch it."
} else {
    Write-Output "(no ipsec-endpoints.json yet - the guard has not recorded a peer)"
}

Say "Configured peer addresses"
# Connection-security rules are where a Windows-terminated tunnel is configured.
$consec = netsh advfirewall consec show rule name=all 2>&1 | Out-String
if ($consec -match 'Endpoint') {
    Write-Output $consec
    Write-Output "--> compare the remote endpoint here against the peer's CURRENT WAN IP."
} else {
    Write-Output "(no connection-security rules - if the tunnel is terminated by RRAS or by"
    Write-Output " another device, check the demand-dial interfaces below instead)"
}

Say "RRAS site-to-site interfaces"
if (Get-Command Get-VpnS2SInterface -ErrorAction SilentlyContinue) {
    try {
        Get-VpnS2SInterface | Format-List Name, Destination, ConnectionState, IPv4Subnet |
            Out-String | Write-Output
    } catch {
        Write-Output "(Get-VpnS2SInterface failed: $($_.Exception.Message))"
    }
} else {
    Write-Output "(RemoteAccess module not present - RRAS is not installed)"
}

Say "Live IPSec state"
Write-Output "--- Main mode (IKE) ---"
netsh advfirewall monitor show mmsa 2>&1 | Select-Object -First 30 | Write-Output
Write-Output "--- Quick mode (ESP child) ---"
netsh advfirewall monitor show qmsa 2>&1 | Select-Object -First 30 | Write-Output

if (Get-Command Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue) {
    Write-Output "--- Get-NetIPsecMainModeSA ---"
    try {
        Get-NetIPsecMainModeSA | Select-Object -First 10 LocalEndpoint, RemoteEndpoint |
            Format-Table -AutoSize | Out-String | Write-Output
    } catch {
        Write-Output "(no main mode SAs - the tunnel is fully down)"
    }
}

Say "Are the peer's packets arriving? ($CaptureSeconds s capture)"
# pktmon ships with Windows 10 1809+ and needs no install, unlike Wireshark.
if (Get-Command pktmon -ErrorAction SilentlyContinue) {
    Write-Output "Watching UDP 500/4500 and ESP. Source addresses below are who is actually dialling in."
    $etl = Join-Path $env:TEMP 'ns-ipsec-diag.etl'
    try {
        pktmon filter remove | Out-Null
        pktmon filter add IKE -t UDP -p 500 | Out-Null
        pktmon filter add NATT -t UDP -p 4500 | Out-Null
        pktmon filter add ESP -t 50 | Out-Null
        pktmon start --capture --pkt-size 128 --file $etl | Out-Null
        Start-Sleep -Seconds $CaptureSeconds
        pktmon stop | Out-Null
        pktmon format $etl -o "$etl.txt" | Out-Null
        Get-Content "$etl.txt" -ErrorAction SilentlyContinue | Select-Object -First 40 | Write-Output
    } catch {
        Write-Output "(pktmon capture failed: $($_.Exception.Message))"
    } finally {
        # Leave no filters behind - this script promises to change nothing.
        pktmon filter remove | Out-Null
        Remove-Item $etl, "$etl.txt" -ErrorAction SilentlyContinue
    }
    Write-Output "--> if this is empty, nothing is reaching the box: check the upstream/cloud"
    Write-Output "    firewall, which is a separate layer and invisible from here."
    Write-Output "--> if packets arrive from an address other than $Peer, the far end's WAN IP"
    Write-Output "    changed and the configuration above is pinned to the old one."
} else {
    Write-Output "(pktmon not available on this build of Windows)"
}

Say "Recent IKE log"
# IPsec negotiation failures land in the Security log as 4650-4655 when IPsec
# auditing is on, and in the System log when the IKEEXT service itself trips.
$since = (Get-Date).AddHours(-24)
try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4650, 4651, 4652, 4653, 4654, 4655; StartTime = $since } `
        -MaxEvents 15 -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -split "`n")[0] } } |
        Format-Table -AutoSize | Out-String | Write-Output
} catch {
    Write-Output "(no IPsec audit events in the last 24h - auditing may be off:"
    Write-Output " auditpol /set /subcategory:`"IPsec Main Mode`" /failure:enable)"
}

try {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-IKEEXT'; StartTime = $since } `
        -MaxEvents 15 -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -split "`n")[0] } } |
        Format-Table -AutoSize | Out-String | Write-Output
} catch {
    Write-Output "(no IKEEXT events in the last 24h)"
}

Say "Done"
Write-Output "Paste this whole output back. Nothing above changed any state."
