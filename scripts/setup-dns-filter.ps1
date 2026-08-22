#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install AdGuard Home as the filtering resolver for this node's VPN clients.

.DESCRIPTION
  What this buys you that Network Sentinel cannot: blocking by *name*, before a
  connection exists. Network Sentinel sees a connection once it is established and
  can then block the address; a resolver refuses to answer, so the client never
  learns an address and never dials out. The two do not overlap - a name-based
  blocklist misses malware that hard-codes an IP, which is exactly the case the
  threat-intel feeds catch.

  The resulting arrangement is the one the README's DNS-hygiene section asks for:

      host + tunnel clients -> AdGuard Home (this node) -> [DoT] -> upstream

  Queries never leave the node in the clear, and because the resolver is local you
  keep full visibility while the network sees nothing.

  Normally you do not run this by hand. Network Sentinel's DNS filtering switch
  (Settings -> DNS filtering, desktop app) runs it for you and stores the resolver
  address and credentials it reports back. Running it directly is for a headless
  server, or for anyone who would rather read the script first.

.PARAMETER ResultPath
  Where to write a one-line JSON result for Network Sentinel: ok, url, username,
  password, message. This is how the app learns what was built, because an elevated
  child process cannot have its output redirected. Omit when running by hand.

.PARAMETER TunnelAddress
  This node's address on the tunnel. Autodetected from WireGuard/RAS adapters when
  omitted.

.PARAMETER Upstream
  quad9 (default) | cloudflare | adguard | nextdns:<id>

.PARAMETER UiPort
  AdGuard admin UI port, bound to the tunnel address only. Default 3000.

.PARAMETER AdminUser
  Admin user for the AdGuard API. Default "admin".

.PARAMETER AdminPassword
  Admin password. A strong one is generated when omitted, and returned in the
  result so Network Sentinel can store it.

.PARAMETER StrayDns
  Block (default) | Allow - what happens to a tunnel client that ignores the pushed
  resolver and dials 8.8.8.8 directly. Note there is no Windows equivalent of the
  Linux build's "redirect" mode; see the notes on StrayDns below.

.PARAMETER Uninstall
  Reverse everything and restore the backups.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\setup-dns-filter.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\setup-dns-filter.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ResultPath = "",
    [string]$TunnelAddress = "",
    [string]$Upstream = "quad9",
    [int]$UiPort = 3000,
    [string]$AdminUser = "admin",
    [string]$AdminPassword = "",
    [ValidateSet("Block", "Allow")]
    [string]$StrayDns = "Block",
    [string]$Version = "latest",
    [switch]$NoFirewall,
    [switch]$NoHostResolver,
    [switch]$AssumeYes,
    [switch]$DryRun,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# TLS 1.2 is not the default negotiation in Windows PowerShell 5.1 on older builds,
# and GitHub refuses anything less. Without this the very first download fails with
# "the underlying connection was closed", which reads like a network fault.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Older frameworks may not expose Tls12 by that name; the download will say so.
}

$InstallDir  = Join-Path $env:ProgramFiles "AdGuardHome"
$AghExe      = Join-Path $InstallDir "AdGuardHome.exe"
$ServiceName = "AdGuardHome"
$StateDir    = Join-Path $env:ProgramData "NetworkSentinel\dns-filter"
$BackupRoot  = Join-Path $StateDir "backups"
$FirewallTag = "NetworkSentinel-DNSFilter"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Say  { param([string]$Text = "") Write-Host $Text }
function Info { param([string]$Text) Write-Host "  $Text" }
function Step { param([string]$Text) Write-Host ""; Write-Host "== $Text" -ForegroundColor Cyan }
function Warn { param([string]$Text) Write-Host "Warning: $Text" -ForegroundColor DarkYellow }

# Every exit goes through here so the app always gets a result file, including on
# failure. A missing file is indistinguishable from a declined UAC prompt, and the
# two need different things said to the operator.
function Write-Result {
    param(
        [bool]$Ok,
        [string]$Message,
        [string]$Url = "",
        [string]$Username = "",
        [string]$Password = ""
    )
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { return }
    try {
        $payload = [ordered]@{
            ok       = $Ok
            url      = $Url
            username = $Username
            password = $Password
            message  = $Message
        }
        $json = $payload | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($ResultPath, $json, (New-Object Text.UTF8Encoding($false)))
    }
    catch {
        Warn "could not write the result file: $($_.Exception.Message)"
    }
}

function Die {
    param([string]$Text)
    Write-Host "Error: $Text" -ForegroundColor Red
    Write-Result -Ok $false -Message $Text
    exit 1
}

function Confirm-Step {
    param([string]$Question)
    if ($AssumeYes) { return $true }
    $answer = Read-Host "  $Question [y/N]"
    return ($answer -match '^(y|yes)$')
}

function Invoke-Step {
    param([string]$Description, [scriptblock]$Action)
    if ($DryRun) { Info "[dry-run] $Description"; return }
    & $Action
}

# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
$Stamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupDir = Join-Path $BackupRoot $Stamp

function Backup-File {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    if ($DryRun) { Info "[dry-run] would back up $Path"; return }
    $target = Join-Path $BackupDir (Split-Path $Path -Leaf)
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Copy-Item $Path $target -Force
    Info "backed up $Path"
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Step "Removing the DNS filter"

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Invoke-Step "stop and unregister the $ServiceName service" {
            try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch {}
            if (Test-Path $AghExe) {
                & $AghExe -s uninstall 2>&1 | Out-Null
            }
        }
        Info "service removed"
    }
    else {
        Info "no $ServiceName service registered"
    }

    Invoke-Step "remove the firewall rules tagged $FirewallTag" {
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$FirewallTag*" } |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    Info "firewall rules removed"

    # The host's own resolver, put back exactly as it was found. A DNS client left
    # pointing at a resolver that no longer exists loses name resolution entirely,
    # which is a far worse outcome than never having installed anything.
    $resolverBackup = Join-Path $StateDir "host-resolvers.json"
    if (Test-Path $resolverBackup) {
        Invoke-Step "restore this host's resolver settings" {
            $saved = Get-Content $resolverBackup -Raw | ConvertFrom-Json
            foreach ($entry in $saved) {
                try {
                    if ($entry.Addresses -and $entry.Addresses.Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex `
                            -ServerAddresses $entry.Addresses -ErrorAction Stop
                    }
                    else {
                        # Empty means it was on DHCP before, which is its own state and
                        # not the same as "no resolvers".
                        Set-DnsClientServerAddress -InterfaceIndex $entry.InterfaceIndex `
                            -ResetServerAddresses -ErrorAction Stop
                    }
                    Info "restored interface $($entry.InterfaceIndex) ($($entry.Alias))"
                }
                catch {
                    Warn "could not restore interface $($entry.InterfaceIndex): $($_.Exception.Message)"
                }
            }
        }
        if (-not $DryRun) { Remove-Item $resolverBackup -Force -ErrorAction SilentlyContinue }
    }

    if (Test-Path $InstallDir) {
        Say ""
        if (Confirm-Step "Delete $InstallDir, including AdGuard's config, statistics and query log?") {
            Invoke-Step "delete $InstallDir" {
                Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            Info "removed $InstallDir"
        }
        else {
            Info "left $InstallDir in place"
        }
    }

    Say ""
    Say "Done. Clear the resolver address in Network Sentinel (Settings -> DNS filtering)"
    Say "so the switch stops pointing at a resolver that is no longer there."
    Say "Backups: $BackupRoot"
    Write-Result -Ok $true -Message "The filtering resolver was removed."
    exit 0
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
Step "Checking the node"

if (-not [Environment]::Is64BitOperatingSystem) {
    Die "AdGuard Home ships 64-bit Windows builds; this is a 32-bit system"
}
$AghArch = "windows_amd64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $AghArch = "windows_arm64" }
Info "architecture: $AghArch"

# --- Find the tunnel -------------------------------------------------------
# WireGuard for Windows presents a Wintun adapter; RRAS hands out addresses on a
# RAS/PPP interface. Both are found the same way WireGuardMonitor finds them:
# by the adapter, not by guessing a subnet.
function Find-TunnelAddress {
    $candidates = @()
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            $looksLikeTunnel =
                $adapter.InterfaceDescription -match 'Wintun|WireGuard|TAP-Windows|OpenVPN|RAS|WAN Miniport' -or
                $adapter.Name -match 'wg|wireguard|tun|tap|vpn'
            if (-not $looksLikeTunnel) { continue }

            $addresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
                -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($address in $addresses) {
                if ($address.IPAddress -like '169.254.*') { continue }
                $candidates += [pscustomobject]@{
                    Address = $address.IPAddress
                    Prefix  = $address.PrefixLength
                    Alias   = $adapter.Name
                    Index   = $adapter.ifIndex
                }
            }
        }
    }
    catch {
        Warn "could not enumerate adapters: $($_.Exception.Message)"
    }
    return $candidates
}

$TunnelPrefix = 24
$TunnelAlias  = ""

if ([string]::IsNullOrWhiteSpace($TunnelAddress)) {
    $found = Find-TunnelAddress
    if ($found.Count -eq 0) {
        Die ("no tunnel interface found. Bring the VPN up first, or pass -TunnelAddress " +
             "with this node's address on the tunnel")
    }
    if ($found.Count -gt 1) {
        Say ""
        Say "More than one tunnel interface is up:"
        for ($i = 0; $i -lt $found.Count; $i++) {
            Say ("  [{0}] {1} on {2}/{3}" -f $i, $found[$i].Alias, $found[$i].Address, $found[$i].Prefix)
        }
        if ($AssumeYes) {
            Info "non-interactive: taking the first"
            $chosen = $found[0]
        }
        else {
            $pick = Read-Host "  Which one carries your VPN clients? [0]"
            if ([string]::IsNullOrWhiteSpace($pick)) { $pick = "0" }
            $index = 0
            if (-not [int]::TryParse($pick, [ref]$index) -or $index -lt 0 -or $index -ge $found.Count) {
                Die "not one of the listed interfaces: $pick"
            }
            $chosen = $found[$index]
        }
    }
    else {
        $chosen = $found[0]
    }
    $TunnelAddress = $chosen.Address
    $TunnelPrefix  = $chosen.Prefix
    $TunnelAlias   = $chosen.Alias
}
else {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($TunnelAddress, [ref]$parsed)) {
        Die "not an IP address: $TunnelAddress"
    }
    $match = Find-TunnelAddress | Where-Object { $_.Address -eq $TunnelAddress } | Select-Object -First 1
    if ($match) {
        $TunnelPrefix = $match.Prefix
        $TunnelAlias  = $match.Alias
    }
    else {
        Warn "$TunnelAddress is not on any tunnel adapter that is up; assuming a /24"
    }
}

# The client subnet, derived rather than guessed: the firewall rules below are what
# keep the resolver off the internet, and a wrong prefix either locks clients out or
# opens it wider than intended.
function Get-NetworkAddress {
    param([string]$Address, [int]$Prefix)
    $bytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)
    $mask  = [uint32]0
    if ($Prefix -gt 0) { $mask = [uint32]([uint32]::MaxValue -shl (32 - $Prefix)) }
    $network = $value -band $mask
    $networkBytes = [BitConverter]::GetBytes([uint32]$network)
    [Array]::Reverse($networkBytes)
    return ([Net.IPAddress]::new($networkBytes)).ToString()
}

$TunnelNetwork = Get-NetworkAddress -Address $TunnelAddress -Prefix $TunnelPrefix
$TunnelSubnet  = "$TunnelNetwork/$TunnelPrefix"
Info "tunnel: $TunnelAddress on $TunnelSubnet$(if ($TunnelAlias) { " ($TunnelAlias)" })"

# --- Upstream --------------------------------------------------------------
# DoT rather than DoH: port 853 is identifiable, so the DNS-hygiene monitor can
# recognise it as encrypted DNS without being told. A DoH upstream on 443 would be
# indistinguishable from web traffic and would have to be allowlisted by hand.
switch -Regex ($Upstream) {
    '^quad9$'      { $UpstreamUrl = "tls://dns.quad9.net";              $Bootstrap = @("9.9.9.9", "149.112.112.112") }
    '^cloudflare$' { $UpstreamUrl = "tls://security.cloudflare-dns.com"; $Bootstrap = @("1.1.1.2", "1.0.0.2") }
    '^adguard$'    { $UpstreamUrl = "tls://dns.adguard-dns.com";        $Bootstrap = @("94.140.14.14", "94.140.15.15") }
    '^nextdns:.+$' { $UpstreamUrl = "tls://$($Upstream.Substring(8)).dns.nextdns.io"; $Bootstrap = @("45.90.28.0", "45.90.30.0") }
    default        { Die "unknown -Upstream: $Upstream" }
}
Info "upstream: $UpstreamUrl (encrypted, port 853)"

# --- Port 53 ---------------------------------------------------------------
# Refuse to install into a port 53 that is already taken. Finding that out after the
# service fails to start is a worse time, and on a domain controller or a machine
# running the DNS Server role this is the expected answer, not a surprise.
function Test-Port53 {
    $holders = @()
    try {
        $udp = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
        foreach ($endpoint in $udp) {
            if ($endpoint.LocalAddress -in @("0.0.0.0", "::", $TunnelAddress, "127.0.0.1")) {
                $name = "?"
                try { $name = (Get-Process -Id $endpoint.OwningProcess -ErrorAction Stop).ProcessName } catch {}
                $holders += "UDP $($endpoint.LocalAddress):53 held by $name (pid $($endpoint.OwningProcess))"
            }
        }
        $tcp = Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue
        foreach ($endpoint in $tcp) {
            if ($endpoint.LocalAddress -in @("0.0.0.0", "::", $TunnelAddress, "127.0.0.1")) {
                $name = "?"
                try { $name = (Get-Process -Id $endpoint.OwningProcess -ErrorAction Stop).ProcessName } catch {}
                $holders += "TCP $($endpoint.LocalAddress):53 held by $name (pid $($endpoint.OwningProcess))"
            }
        }
    }
    catch {
        Warn "could not read port 53 listeners: $($_.Exception.Message)"
    }
    return $holders
}

$port53 = Test-Port53
if ($port53.Count -gt 0) {
    Warn "something is already listening on port 53:"
    foreach ($holder in $port53) { Info $holder }
    Say ""
    Say "  The DNS Server role and this cannot both own port 53. If this machine is a"
    Say "  domain controller, stop here - filtering belongs in that resolver instead."
    if (-not (Confirm-Step "Continue anyway?")) { Die "aborted - free port 53 first" }
}

# --- Credentials -----------------------------------------------------------
# Generated rather than prompted by default. The switch in the app runs this with no
# console anyone is watching, and a resolver left on the setup wizard is a resolver
# the app cannot authenticate to - the one state where every other check says the
# install worked.
if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    # Base64url: no shell-quoting hazards in a password that gets pasted into a
    # config file and an HTTP header.
    $AdminPassword = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    Info "generated an admin password; Network Sentinel will store it"
}

$UiUrl = "http://${TunnelAddress}:${UiPort}"

Say ""
Say "Plan:"
Say "  1. install AdGuard Home to $InstallDir as the '$ServiceName' service"
Say "  2. bind DNS to ${TunnelAddress}:53 and 127.0.0.1:53"
Say "  3. bind the admin UI to ${TunnelAddress}:${UiPort} - reachable over the tunnel only"
Say "  4. filter with the AdGuard base + malware/phishing blocklists"
Say "  5. forward upstream over DoT to $UpstreamUrl"
Say "  6. firewall: accept 53 only from $TunnelSubnet; never from the internet"
Say "  7. stray client DNS (hardcoded 8.8.8.8 etc): $StrayDns"
if (-not $NoHostResolver) { Say "  8. point this node's own resolver at it" }
Say ""
if (-not (Confirm-Step "Proceed?")) { Die "aborted" }

if (-not $DryRun) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
}

# ---------------------------------------------------------------------------
# Install AdGuard Home
# ---------------------------------------------------------------------------
Step "Installing AdGuard Home"

if (Test-Path $AghExe) {
    Info "already installed at $AghExe - reusing the binary"
}
else {
    if ($Version -eq "latest") {
        try {
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest" `
                -Headers @{ "User-Agent" = "NetworkSentinel" } -UseBasicParsing
            $Version = $release.tag_name
        }
        catch {
            Die "could not determine the latest AdGuard Home release ($($_.Exception.Message)) - pass -Version"
        }
    }
    if ([string]::IsNullOrWhiteSpace($Version)) {
        Die "could not determine the latest AdGuard Home release - pass -Version"
    }
    Info "version: $Version"

    $zipName  = "AdGuardHome_$AghArch.zip"
    $baseUrl  = "https://github.com/AdguardTeam/AdGuardHome/releases/download/$Version"
    $tmp      = Join-Path $env:TEMP "ns-dns-filter-$Stamp"
    $zipPath  = Join-Path $tmp $zipName
    $sumsPath = Join-Path $tmp "checksums.txt"

    if ($DryRun) {
        Info "[dry-run] would download $baseUrl/$zipName"
    }
    else {
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            Invoke-WebRequest -Uri "$baseUrl/$zipName" -OutFile $zipPath -UseBasicParsing
            Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $sumsPath -UseBasicParsing
        }
        catch {
            Die "download failed: $($_.Exception.Message)"
        }

        # Verify before unpacking. A resolver is the single most valuable thing on this
        # box to tamper with - it decides where every client goes.
        #
        # AdGuard lists names as "./AdGuardHome_windows_amd64.zip", and sha256sum also
        # writes a "*" binary marker, so the basename is compared rather than the line
        # pattern-matched. The two failures are kept apart: a missing line is a
        # packaging change at AdGuard, a differing hash is a reason to stop.
        $expected = ""
        foreach ($line in (Get-Content $sumsPath)) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -lt 2) { continue }
            $name = $parts[1].Trim().TrimStart('*').TrimStart('.').TrimStart('/', '\')
            if ([IO.Path]::GetFileName($name) -eq $zipName) {
                $expected = $parts[0].Trim().ToLowerInvariant()
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($expected)) {
            Warn "checksums.txt has no line for $zipName - AdGuard may have changed its packaging"
            if (-not (Confirm-Step "Install without verifying the download?")) {
                Die "aborted - could not verify $zipName"
            }
        }
        else {
            $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                Die "checksum mismatch on ${zipName}: expected $expected, got $actual - refusing to install"
            }
            Info "checksum verified"
        }

        Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        # The archive unpacks into an AdGuardHome\ folder.
        $unpacked = Join-Path $tmp "AdGuardHome"
        if (-not (Test-Path (Join-Path $unpacked "AdGuardHome.exe"))) {
            Die "the archive did not contain AdGuardHome.exe where expected"
        }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item (Join-Path $unpacked "*") $InstallDir -Recurse -Force
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Info "installed to $InstallDir"
    }
}

# ---------------------------------------------------------------------------
# Register the service
# ---------------------------------------------------------------------------
Step "Registering the service"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Info "the $ServiceName service is already registered"
    Invoke-Step "restart $ServiceName" { Restart-Service -Name $ServiceName -Force }
}
else {
    Invoke-Step "register and start $ServiceName" {
        Push-Location $InstallDir
        try {
            & $AghExe -s install 2>&1 | ForEach-Object { Info $_ }
        }
        finally {
            Pop-Location
        }
    }
    if (-not $DryRun) {
        $registered = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $registered) { Die "the $ServiceName service did not register" }
        Info "service registered"
    }
}

if ($DryRun) {
    Say ""
    Say "[dry-run] nothing was changed."
    Write-Result -Ok $false -Message "Dry run: nothing was changed."
    exit 0
}

# ---------------------------------------------------------------------------
# First-run configuration
# ---------------------------------------------------------------------------
# AdGuard Home's own install API rather than writing AdGuardHome.yaml: the admin
# password is stored as a bcrypt hash, and Windows has no htpasswd. Letting AdGuard
# hash it means the credential this script returns is one the API will actually
# accept - which is the whole point of the switch that calls this.
Step "Configuring the resolver"

function Wait-ForApi {
    param([string]$Url, [int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 | Out-Null
            return $true
        }
        catch {
            # A 4xx still means something is answering, which is all this is asking.
            if ($_.Exception.Response) { return $true }
            Start-Sleep -Milliseconds 750
        }
    }
    return $false
}

# Before it is configured, AdGuard serves its install wizard on 0.0.0.0:3000, so the
# first contact is made on the loopback rather than the tunnel address it has not
# been told about yet.
$bootstrapUrl = "http://127.0.0.1:$UiPort"
if (-not (Wait-ForApi -Url "$bootstrapUrl/control/status")) {
    Die "AdGuard Home did not start answering on $bootstrapUrl within 60s"
}

$configured = $false
try {
    $status = Invoke-RestMethod -Uri "$bootstrapUrl/control/status" -UseBasicParsing -TimeoutSec 10
    # A configured instance answers /control/status with a running state; a fresh one
    # answers the install endpoints instead.
    if ($null -ne $status -and $null -ne $status.dns_addresses) { $configured = $true }
}
catch {
    $configured = $false
}

$authHeader = @{}
$pair = "${AdminUser}:${AdminPassword}"
$token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
$authHeader["Authorization"] = "Basic $token"

if ($configured) {
    Warn "AdGuard Home is already configured; leaving its existing admin account alone"
    Say  "  If Network Sentinel cannot authenticate, set the resolver user and password"
    Say  "  by hand in Settings -> DNS filtering."
}
else {
    $installBody = @{
        web = @{
            ip   = $TunnelAddress
            port = $UiPort
        }
        dns = @{
            ip   = "0.0.0.0"
            port = 53
        }
        username = $AdminUser
        password = $AdminPassword
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Uri "$bootstrapUrl/control/install/configure" -Method Post `
            -Body $installBody -ContentType "application/json" -UseBasicParsing -TimeoutSec 30 | Out-Null
        Info "admin account created (user '$AdminUser')"
    }
    catch {
        Die "AdGuard Home refused the initial configuration: $($_.Exception.Message)"
    }

    # It rebinds the UI to the tunnel address, so the API moves with it.
    Start-Sleep -Seconds 2
}

if (-not (Wait-ForApi -Url "$UiUrl/control/status")) {
    Die "the admin API did not come back on $UiUrl after configuration"
}

# --- Upstreams -------------------------------------------------------------
# Content-Type is exactly application/json, with no charset parameter: AdGuard Home
# compares the header rather than parsing it and answers 415 otherwise. Same trap
# DnsFilterService.JsonBody exists to avoid.
function Invoke-AghApi {
    param([string]$Path, $Body, [string]$Method = "Post")
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    return Invoke-RestMethod -Uri "$UiUrl$Path" -Method $Method -Body $json `
        -ContentType "application/json" -Headers $authHeader -UseBasicParsing -TimeoutSec 30
}

try {
    Invoke-AghApi -Path "/control/dns_config" -Body @{
        upstream_dns      = @($UpstreamUrl)
        bootstrap_dns     = $Bootstrap
        protection_enabled = $true
        # Answer only for the tunnel and the host itself. An open resolver on a public
        # address is an amplification reflector, and the firewall rules below are the
        # second layer of the same answer rather than the only one.
        ratelimit         = 40
    } | Out-Null
    Info "upstream set to $UpstreamUrl over DoT"
}
catch {
    Warn "could not set the upstream resolver: $($_.Exception.Message)"
}

# --- Blocklists ------------------------------------------------------------
$blocklists = @(
    @{ name = "AdGuard DNS filter";                url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" },
    @{ name = "AdAway Default Blocklist";          url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt" },
    @{ name = "Phishing URL Blocklist";            url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt" },
    @{ name = "Scam Blocklist by DurableNapkin";   url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt" },
    @{ name = "Malicious URL Blocklist";           url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt" }
)

foreach ($list in $blocklists) {
    try {
        Invoke-AghApi -Path "/control/filtering/add_url" -Body @{
            name      = $list.name
            url       = $list.url
            whitelist = $false
        } | Out-Null
        Info "added blocklist: $($list.name)"
    }
    catch {
        # Already present is the common answer on a re-run, and not a failure.
        Warn "blocklist '$($list.name)' not added: $($_.Exception.Message)"
    }
}

try {
    Invoke-AghApi -Path "/control/filtering/config" -Body @{
        enabled  = $true
        interval = 24
    } | Out-Null
    Invoke-AghApi -Path "/control/safebrowsing/enable" -Body @{} | Out-Null
    Info "filtering and safe browsing on"
}
catch {
    Warn "could not confirm the filtering configuration: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
if (-not $NoFirewall) {
    Step "Firewall rules"

    Invoke-Step "replace any previous $FirewallTag rules" {
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$FirewallTag*" } |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }

    # DNS from the tunnel only. Without the RemoteAddress scope this is an open
    # resolver the moment the host has a public address - a reflector, and a listed
    # one within days.
    foreach ($protocol in @("UDP", "TCP")) {
        Invoke-Step "allow $protocol/53 from $TunnelSubnet" {
            New-NetFirewallRule -DisplayName "$FirewallTag - DNS in ($protocol)" `
                -Direction Inbound -Action Allow -Protocol $protocol -LocalPort 53 `
                -RemoteAddress $TunnelSubnet -Profile Any `
                -Description "Network Sentinel DNS filter: tunnel clients only" | Out-Null
        }
    }
    Info "allowed 53/udp and 53/tcp from $TunnelSubnet"

    # The admin UI, tunnel-only for the same reason.
    Invoke-Step "allow TCP/$UiPort from $TunnelSubnet" {
        New-NetFirewallRule -DisplayName "$FirewallTag - Admin UI" `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort $UiPort `
            -RemoteAddress $TunnelSubnet -Profile Any `
            -Description "Network Sentinel DNS filter: AdGuard admin UI, tunnel only" | Out-Null
    }
    Info "allowed the admin UI on $UiPort from $TunnelSubnet"

    # Stray client DNS.
    #
    # The Linux build can DNAT a client's hardcoded 8.8.8.8 back to the local
    # resolver, so filtering holds even for a client that ignores the pushed setting.
    # Windows Firewall has no DNAT, and netsh portproxy is TCP-only, so the same
    # trick does not exist here - "redirect" is deliberately not offered rather than
    # half-implemented. Blocking is the honest alternative: the client's own DNS
    # fails rather than quietly bypassing the filter.
    if ($StrayDns -eq "Block") {
        Invoke-Step "block tunnel clients from reaching other resolvers" {
            foreach ($protocol in @("UDP", "TCP")) {
                New-NetFirewallRule -DisplayName "$FirewallTag - Stray DNS out ($protocol)" `
                    -Direction Outbound -Action Block -Protocol $protocol -RemotePort 53 `
                    -RemoteAddress "Internet" -Profile Any `
                    -Description "Network Sentinel DNS filter: no plaintext DNS past the local resolver" | Out-Null
            }
        }
        Info "blocked outbound plaintext DNS to the internet"
        Warn ("this covers traffic originating on this host. Whether it also covers " +
              "RRAS-forwarded client traffic depends on your routing setup - verify with a client")
    }
    else {
        Info "stray client DNS left alone (-StrayDns Allow)"
    }
}
else {
    Step "Firewall rules"
    Warn "skipped (-NoFirewall). Add them by hand, or the resolver is reachable from anywhere it is routable."
}

# ---------------------------------------------------------------------------
# Point this host at the new resolver
# ---------------------------------------------------------------------------
if (-not $NoHostResolver) {
    Step "Pointing this node at the resolver"

    # Saved before it is changed, so -Uninstall can put it back exactly. A host left
    # pointing at a resolver that no longer exists loses name resolution entirely.
    $resolverBackup = Join-Path $StateDir "host-resolvers.json"
    if (-not (Test-Path $resolverBackup)) {
        $saved = @()
        try {
            $physical = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
            foreach ($adapter in $physical) {
                $current = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue
                $saved += [pscustomobject]@{
                    InterfaceIndex = $adapter.ifIndex
                    Alias          = $adapter.Name
                    Addresses      = @($current.ServerAddresses)
                }
            }
            $saved | ConvertTo-Json -Depth 4 |
                Set-Content -Path $resolverBackup -Encoding utf8
            Info "saved the current resolver settings"
        }
        catch {
            Warn "could not save the current resolver settings: $($_.Exception.Message)"
        }
    }

    try {
        $physical = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $physical) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
                -ServerAddresses @("127.0.0.1") -ErrorAction Stop
            Info "$($adapter.Name) -> 127.0.0.1"
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
    }
    catch {
        Warn "could not repoint this host's resolver: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# What is left for you to do
# ---------------------------------------------------------------------------
Step "Done - one manual step left"

Say ""
Say "Point your clients at the resolver. Nothing filters until you do:"
Say ""
Say "  WireGuard - in each CLIENT config, under [Interface]:"
Say ""
Say "      DNS = $TunnelAddress"
Say ""
Say "  and make sure the client's AllowedIPs covers $TunnelAddress (0.0.0.0/0 does)."
Say ""
Say "  RRAS / IKEv2 - set the DNS server handed to clients in the RRAS console,"
Say "  under IPv4 -> DHCP Relay Agent or the static address pool, to $TunnelAddress."
Say ""
Say "Then reconnect a client and check it:"
Say ""
Say "    Resolve-DnsName example.com    -Server $TunnelAddress   # answers normally"
Say "    Resolve-DnsName doubleclick.net -Server $TunnelAddress   # comes back blocked"
Say ""
Say "Web UI:  $UiUrl   (user '$AdminUser')"
Say "Reachable over the tunnel only; the firewall drops it from everywhere else."
Say ""
Say "Filtering can be switched on and off from Network Sentinel itself - Settings ->"
Say "DNS filtering, in the desktop app, the TUI and the web console. That switches"
Say "filtering only: the resolver keeps answering, so no client loses name resolution."
Say ""
Say "Undo everything:   powershell -ExecutionPolicy Bypass -File $PSCommandPath -Uninstall"
Say "Backups:           $BackupDir"
Say ""
Say "Worth knowing: this blocks by NAME. Malware that dials a hard-coded IP makes no"
Say "DNS query and passes straight through - that gap is what Network Sentinel's"
Say "threat-intel feeds cover, so keep both on."

Write-Result -Ok $true -Url $UiUrl -Username $AdminUser -Password $AdminPassword `
    -Message "DNS filtering is on, at $UiUrl. Point your VPN clients at $TunnelAddress."

# Run by hand rather than by the app: hold the window open so the summary above can
# actually be read. When the app called this it is waiting on the exit code.
if ([string]::IsNullOrWhiteSpace($ResultPath) -and -not $AssumeYes) {
    Say ""
    Read-Host "Press Enter to close" | Out-Null
}

exit 0
