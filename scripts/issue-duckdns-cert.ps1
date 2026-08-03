<#
.SYNOPSIS
  Issue a free Let's Encrypt certificate for a duckdns.org hostname and install it
  where the Network Sentinel web console expects it.

.DESCRIPTION
  DNS-01 is used rather than HTTP-01: it proves control by writing a TXT record
  through the DuckDNS API, so nothing has to be reachable on port 80.

  Issuance runs through Posh-ACME, which ships a DuckDNS plugin. It is the Windows
  counterpart to acme.sh on the Linux build; unlike acme.sh it does not install its
  own renewal job, so this script registers a scheduled task for that.

.PARAMETER DomainLabel
  Just the subdomain label ("myhost" for myhost.duckdns.org). Falls back to the
  subdomain saved in duckdns.json, then prompts.

.EXAMPLE
  .\scripts\issue-duckdns-cert.ps1                 # prompts for anything missing
  .\scripts\issue-duckdns-cert.ps1 myhost          # subdomain as an argument

.NOTES
  Non-interactive (this is how the app's "Issue certificate" button runs it — there
  is no console to answer prompts on, so anything missing is an error, not a read):
    $env:NS_ASSUME_YES = '1'
    $env:NS_ACME_EMAIL = 'you@example.com'
    $env:DuckDNS_Token = '....'
    .\scripts\issue-duckdns-cert.ps1 myhost

  Renewal: a "NetworkSentinel-CertRenew" scheduled task runs Submit-Renewal daily.
  The console re-reads the files when they change, so a renewal applies without
  restarting it.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$DomainLabel
)

$ErrorActionPreference = 'Stop'

function Say { param([string]$Text = '') Write-Host $Text }
function Die {
    param([string]$Text)
    # "Error:" prefix is what CertIssuanceService greps for to explain a failure.
    Write-Host "Error: $Text" -ForegroundColor Red
    exit 1
}

# No console means nothing can answer a prompt; treat that as non-interactive so a
# missing value fails with a message instead of blocking forever.
$assumeYes = ($env:NS_ASSUME_YES -eq '1') -or [Console]::IsInputRedirected
function Interactive { return -not $assumeYes }

# Mirrors AppPaths.DataDirectory: %ProgramData%\NetworkSentinel, with the same
# per-user fallback for when ProgramData is not writable.
$DataDir = Join-Path $env:ProgramData 'NetworkSentinel'
try {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $probe = Join-Path $DataDir ".write-test-$PID"
    Set-Content -LiteralPath $probe -Value '' -ErrorAction Stop
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
} catch {
    $DataDir = Join-Path $env:LOCALAPPDATA 'NetworkSentinel'
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
}

$TlsDir = Join-Path $DataDir 'tls'
$DuckDnsJson = Join-Path $DataDir 'duckdns.json'

# Posh-ACME is kept with the app's own data rather than a profile module folder.
# The desktop app runs as the signed-in user and the renewal task as SYSTEM; a
# per-profile copy would mean installing it twice, and under SYSTEM the usual
# Documents\WindowsPowerShell\Modules path may be OneDrive-redirected or absent.
$ModuleRoot = Join-Path $DataDir 'modules'
if ($env:PSModulePath -notlike "*$ModuleRoot*") {
    $env:PSModulePath = "$ModuleRoot;$env:PSModulePath"
}

# Keep ACME state beside the app's own data instead of the calling account's profile.
# The desktop GUI runs as the signed-in user and the web service as SYSTEM; a
# per-profile store would mean each one issuing and renewing its own certificate.
$env:POSHACME_HOME = Join-Path $DataDir 'acme'
New-Item -ItemType Directory -Force -Path $env:POSHACME_HOME | Out-Null

# --- Subdomain -------------------------------------------------------------
$savedConfig = $null
if (Test-Path -LiteralPath $DuckDnsJson) {
    try { $savedConfig = Get-Content -LiteralPath $DuckDnsJson -Raw | ConvertFrom-Json } catch { $savedConfig = $null }
}

if ([string]::IsNullOrWhiteSpace($DomainLabel) -and $savedConfig) {
    $DomainLabel = ($savedConfig.Domain -split ',')[0]
    if (-not [string]::IsNullOrWhiteSpace($DomainLabel)) {
        Say "Using subdomain from ${DuckDnsJson}: $DomainLabel"
    }
}

if ([string]::IsNullOrWhiteSpace($DomainLabel)) {
    if (-not (Interactive)) { Die "no DuckDNS subdomain - pass it as an argument or save one first" }
    $DomainLabel = Read-Host "DuckDNS subdomain (just the label, e.g. 'myhost')"
}

# Accept myhost, myhost.duckdns.org, or a pasted URL.
$DomainLabel = $DomainLabel.Trim().ToLowerInvariant()
$DomainLabel = $DomainLabel -replace '^https?://', ''
$DomainLabel = ($DomainLabel -split '/')[0]
$DomainLabel = $DomainLabel -replace '\.duckdns\.org$', ''
$DomainLabel = $DomainLabel.Trim('.')
if ([string]::IsNullOrWhiteSpace($DomainLabel)) { Die "no subdomain given" }
if ($DomainLabel -notmatch '^[a-z0-9-]+$') { Die "invalid subdomain '$DomainLabel' - use just the label, e.g. myhost" }

$Fqdn = "$DomainLabel.duckdns.org"

# --- Token -----------------------------------------------------------------
$Token = $env:DuckDNS_Token
if ([string]::IsNullOrWhiteSpace($Token) -and $savedConfig) {
    $Token = $savedConfig.Token
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        Say "Using the token already saved for the web console."
    }
}

if ([string]::IsNullOrWhiteSpace($Token)) {
    if (-not (Interactive)) { Die "no DuckDNS token saved - set one in Settings or with --set-duckdns" }
    $secure = Read-Host "DuckDNS token (hidden)" -AsSecureString
    $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
if ([string]::IsNullOrWhiteSpace($Token)) { Die "no DuckDNS token given" }

# --- Posh-ACME -------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Posh-ACME)) {
    Say ""
    Say "Posh-ACME is not installed."
    Say "It is the PowerShell ACME client; it installs to $ModuleRoot."

    if (Interactive) {
        $reply = Read-Host "Install it now from the PowerShell Gallery? [y/N]"
        if ($reply -notmatch '^[Yy]$') { Die "Posh-ACME is required - install it and re-run" }
    } else {
        Say "Installing it now (NS_ASSUME_YES)."
    }

    # PowerShell 5.1 still negotiates TLS 1.0 by default; the Gallery requires 1.2.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $installed = $false

    New-Item -ItemType Directory -Force -Path $ModuleRoot | Out-Null

    # Preferred path, on machines whose PowerShellGet actually works.
    # Save-Module rather than Install-Module -Scope CurrentUser: this has to be visible
    # to both the desktop app (signed-in user) and the renewal task (SYSTEM), and a
    # profile install would be found by only one of them.
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
        Save-Module -Name Posh-ACME -Path $ModuleRoot -Repository PSGallery -Force -ErrorAction Stop
        $installed = [bool](Get-Module -ListAvailable -Name Posh-ACME)
    }
    catch {
        Say "  PowerShellGet could not fetch it: $($_.Exception.Message.Trim())"
    }

    # Fallback. Windows ships PackageManagement/PowerShellGet 1.0.0.1 with no NuGet
    # provider, and bootstrapping one fails on plenty of otherwise healthy machines
    # ("Unable to resolve package source ..."), which used to sink issuance even
    # though the gallery was perfectly reachable. A .nupkg is a zip and Posh-ACME has
    # no dependencies, so fetching it directly needs none of that stack.
    if (-not $installed) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "posh-acme-$PID"
        try {
            New-Item -ItemType Directory -Force -Path $tmp | Out-Null
            # Expand-Archive insists on a .zip extension.
            $zip = Join-Path $tmp 'posh-acme.zip'

            # Escape hatch for a server with no outbound internet: fetch
            # Posh-ACME.<version>.nupkg on a machine that has access and copy it over.
            # NS_POSHACME_NUPKG names it explicitly; otherwise it is enough to drop the
            # file in the data directory or beside this script, so an operator who
            # cannot set a machine variable and restart the service can still get there.
            $localPkg = $null
            if ($env:NS_POSHACME_NUPKG -and (Test-Path -LiteralPath $env:NS_POSHACME_NUPKG)) {
                $localPkg = $env:NS_POSHACME_NUPKG
            }
            else {
                $localPkg = Get-ChildItem -Path @($DataDir, $PSScriptRoot) -Filter 'Posh-ACME*.nupkg' `
                    -File -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending |
                    Select-Object -First 1 -ExpandProperty FullName
            }

            if ($localPkg) {
                Say "  Using the local package $localPkg"
                Copy-Item -LiteralPath $localPkg -Destination $zip -Force
            }
            else {
                Say "  Downloading Posh-ACME straight from the gallery instead..."

                # A proxy is the usual reason this leg fails on a server. Invoke-WebRequest
                # resolves the *calling account's* proxy configuration, and issuance runs as
                # SYSTEM from the web console, which does not inherit the signed-in user's
                # settings -- so the request dies with "Unable to connect to the remote
                # server" on a machine where a browser reaches the gallery fine.
                $web = @{
                    Uri             = 'https://www.powershellgallery.com/api/v2/package/Posh-ACME'
                    OutFile         = $zip
                    UseBasicParsing = $true
                    TimeoutSec      = 180
                }
                $proxyUrl = $env:NS_PROXY
                if (-not $proxyUrl) {
                    try {
                        $resolved = [Net.WebRequest]::GetSystemWebProxy().GetProxy($web.Uri)
                        # GetProxy echoes the target back when no proxy applies.
                        if ($resolved -and $resolved.AbsoluteUri -notlike '*powershellgallery.com*') {
                            $proxyUrl = $resolved.AbsoluteUri
                        }
                    }
                    catch { }
                }
                if ($proxyUrl) {
                    Say "  Using proxy $proxyUrl"
                    $web['Proxy'] = $proxyUrl
                    $web['ProxyUseDefaultCredentials'] = $true
                }

                Invoke-WebRequest @web
            }

            $ext = Join-Path $tmp 'extract'
            Expand-Archive -LiteralPath $zip -DestinationPath $ext -Force

            $nuspec = Get-ChildItem -LiteralPath $ext -Filter '*.nuspec' | Select-Object -First 1
            if (-not $nuspec) { throw "downloaded package contained no .nuspec" }
            [xml]$meta = Get-Content -LiteralPath $nuspec.FullName
            $version = $meta.package.metadata.version
            if (-not $version) { throw "could not read a version out of the package" }

            $dest = Join-Path $ModuleRoot "Posh-ACME\$version"
            if (Test-Path $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
            New-Item -ItemType Directory -Force -Path $dest | Out-Null

            # Literal names, not -Exclude: '[Content_Types].xml' is a wildcard pattern
            # to PowerShell and would not match the file it is named after.
            $skip = @('_rels', 'package', '[Content_Types].xml')
            Get-ChildItem -LiteralPath $ext -Force |
                Where-Object { $skip -notcontains $_.Name -and $_.Extension -ne '.nuspec' } |
                Copy-Item -Destination $dest -Recurse -Force

            $installed = [bool](Get-Module -ListAvailable -Name Posh-ACME)
            if ($installed) { Say "  Installed Posh-ACME $version to $ModuleRoot" }
        }
        catch {
            $why = $_.Exception.Message.Trim()

            # "Unable to connect" is a connection-level failure, not a TLS one, and on a
            # server it nearly always means egress is blocked or goes through a proxy.
            # Say what to do about it rather than only quoting the exception.
            $hint = ""
            if ($why -match 'Unable to connect|remote name could not be resolved|timed out|forbidden|\(407\)') {
                $probe = "cannot reach powershellgallery.com"
                try {
                    $tcp = Test-NetConnection -ComputerName 'www.powershellgallery.com' -Port 443 -WarningAction SilentlyContinue
                    if ($tcp.NameResolutionSucceeded -eq $false) { $probe = "DNS does not resolve www.powershellgallery.com" }
                    elseif ($tcp.TcpTestSucceeded) { $probe = "TCP 443 to www.powershellgallery.com is open, so this is a proxy or filtering problem" }
                    else { $probe = "TCP 443 to www.powershellgallery.com is blocked" }
                }
                catch { }

                $hint = " [$probe]. If this machine uses a proxy, set NS_PROXY (issuance runs as SYSTEM " +
                        "from the web console and does not inherit your proxy settings). If it has no outbound " +
                        "internet, download Posh-ACME.<version>.nupkg on a machine that does and copy it into " +
                        "$DataDir - it is picked up from there automatically, no restart needed."
            }

            Die "could not install Posh-ACME: $why$hint"
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $installed) {
        Die "Posh-ACME install did not produce a usable module"
    }
}

Import-Module Posh-ACME -ErrorAction Stop

# Reports which layer is broken. Posh-ACME surfaces a connectivity failure as a
# generic Write-Error, which on its own does not distinguish "blocked" from
# "wrong credentials".
function Test-Egress {
    param([string]$HostName)
    try {
        $t = Test-NetConnection -ComputerName $HostName -Port 443 -WarningAction SilentlyContinue
        if ($t.NameResolutionSucceeded -eq $false) { return "DNS does not resolve $HostName" }
        if ($t.TcpTestSucceeded) { return "TCP 443 to $HostName is open" }
        return "TCP 443 to $HostName is blocked"
    }
    catch { return "could not probe $HostName" }
}

$AcmeHost = 'acme-v02.api.letsencrypt.org'
$OfflineAdvice = "DNS-01 needs no inbound port 80, but issuance still needs outbound HTTPS to Let's Encrypt. " +
                 "If that is blocked here, issue the certificate on a machine that has access and copy the " +
                 ".fullchain.cer and .key into $TlsDir, then point Settings -> Remote access at them."

# Contacts the ACME directory, so this is the first thing to fail on a server with
# filtered egress. Uncaught, it exits with a bare PowerShell error and no usable text.
try {
    Set-PAServer LE_PROD -ErrorAction Stop
}
catch {
    Die "could not reach Let's Encrypt: $($_.Exception.Message.Trim()) [$(Test-Egress $AcmeHost)]. $OfflineAdvice"
}

# Let's Encrypt registers the account against this address. There is no way to skip
# it on first run, so fail with the fix rather than registering a fake one.
$AccountEmail = $env:NS_ACME_EMAIL
$existingAccount = $null
try { $existingAccount = Get-PAAccount -ErrorAction Stop }
catch {
    Die "could not read the Let's Encrypt account: $($_.Exception.Message.Trim()) [$(Test-Egress $AcmeHost)]. $OfflineAdvice"
}

if (-not $existingAccount) {
    if ([string]::IsNullOrWhiteSpace($AccountEmail)) {
        if (-not (Interactive)) {
            Die "no Let's Encrypt account yet and no email was given - set NS_ACME_EMAIL to register the account"
        }
        $AccountEmail = Read-Host "Email for Let's Encrypt expiry notices"
    }
    if ([string]::IsNullOrWhiteSpace($AccountEmail)) { Die "an email is required to register an ACME account" }

    try {
        New-PAAccount -Contact $AccountEmail -AcceptTOS -ErrorAction Stop | Out-Null
    }
    catch {
        Die "could not register the Let's Encrypt account: $($_.Exception.Message.Trim()) [$(Test-Egress $AcmeHost)]. $OfflineAdvice"
    }
}

# --- Issue -----------------------------------------------------------------
$forceRenew = ($env:NS_FORCE_RENEW -eq '1')
$existing = $null
try { $existing = Get-PACertificate -MainDomain $Fqdn -ErrorAction SilentlyContinue } catch { $existing = $null }

# Let's Encrypt rate-limits re-issuing a name, so a certificate that is still
# comfortably valid is reused rather than replaced. The console still needs it
# copied into place, so this falls through to the install step either way.
$reuse = $false
if ($existing -and -not $forceRenew) {
    $daysLeft = ($existing.NotAfter - (Get-Date)).TotalDays
    if ($daysLeft -gt 30) {
        Say ""
        # "skipped renewal" is the phrase CertIssuanceService looks for to report
        # this as a reuse rather than a fresh issuance. Keep the wording in step.
        Say ("Certificate is still current ({0:0} days left), so Posh-ACME skipped renewal - installing the existing one." -f $daysLeft)
        Say "Re-issue early with NS_FORCE_RENEW=1 (Let's Encrypt rate-limits this, so only when needed)."
        $reuse = $true
    }
}

if (-not $reuse) {
    Say ""
    Say "Issuing a certificate for $Fqdn (DNS-01 via the DuckDNS API)..."
    Say "DuckDNS TXT records take a couple of minutes to propagate - this is not stuck."
    Say ""

    $secureToken = ConvertTo-SecureString $Token -AsPlainText -Force
    $pluginArgs = @{
        DuckToken  = $secureToken
        DuckDomain = $DomainLabel
    }

    $certParams = @{
        Domain     = $Fqdn
        Plugin     = 'DuckDNS'
        PluginArgs = $pluginArgs
        # DuckDNS publishes TXT records more slowly than the default probe allows.
        DNSSleep   = 120
        AcceptTOS  = $true
        Force      = $forceRenew
    }
    if (-not [string]::IsNullOrWhiteSpace($AccountEmail)) { $certParams['Contact'] = $AccountEmail }

    try {
        New-PACertificate @certParams | Out-Null
    } catch {
        # Two different remote hosts are involved: the TXT record is written through
        # the DuckDNS API, and the order is placed with Let's Encrypt. Naming which
        # one is unreachable saves guessing at the token.
        Die ("certificate issuance failed: $($_.Exception.Message.Trim()) " +
             "[$(Test-Egress $AcmeHost); $(Test-Egress 'www.duckdns.org')]. $OfflineAdvice")
    }

    $existing = Get-PACertificate -MainDomain $Fqdn -ErrorAction SilentlyContinue
}

if (-not $existing) { Die "issuance reported success but no certificate was found for $Fqdn" }

# --- Install where the console reads it ------------------------------------
New-Item -ItemType Directory -Force -Path $TlsDir | Out-Null

$CertFile = Join-Path $TlsDir "$Fqdn.fullchain.cer"
$KeyFile = Join-Path $TlsDir "$Fqdn.key"

Copy-Item -LiteralPath $existing.FullChainFile -Destination $CertFile -Force
Copy-Item -LiteralPath $existing.KeyFile -Destination $KeyFile -Force

# The private key must not inherit the Users:Modify grant AppPaths puts on the data
# directory so the GUI and the SYSTEM service can share state.
function Protect-Path {
    param([string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
        foreach ($sid in @(
                New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::LocalSystemSid), $null
                New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid), $null
            )) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($me) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                        $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Say "Note: could not tighten permissions on $Path ($($_.Exception.Message))"
    }
}
Protect-Path $TlsDir
Protect-Path $KeyFile

# --- Renewal ---------------------------------------------------------------
# acme.sh adds its own cron entry on Linux; Posh-ACME does not, so register the
# equivalent here. Needs elevation, so it is best-effort.
$TaskName = 'NetworkSentinel-CertRenew'
try {
    $renewCommand = @"
`$env:POSHACME_HOME = '$($env:POSHACME_HOME)'
# The module may live with the app's data rather than in a profile module folder,
# and this task runs as SYSTEM, so put that path on PSModulePath before importing.
`$env:PSModulePath = '$ModuleRoot;' + `$env:PSModulePath
Import-Module Posh-ACME
Submit-Renewal -AllOrders
Copy-Item -LiteralPath (Get-PACertificate -MainDomain '$Fqdn').FullChainFile -Destination '$CertFile' -Force
Copy-Item -LiteralPath (Get-PACertificate -MainDomain '$Fqdn').KeyFile -Destination '$KeyFile' -Force
"@
    $renewScript = Join-Path $DataDir 'renew-cert.ps1'
    Set-Content -LiteralPath $renewScript -Value $renewCommand -Encoding UTF8

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$renewScript`""
    $trigger = New-ScheduledTaskTrigger -Daily -At 3:17am
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Force -ErrorAction Stop | Out-Null
    Say ""
    Say "Renewal scheduled task '$TaskName' registered (daily)."
} catch {
    Say ""
    Say "Note: could not register the renewal task ($($_.Exception.Message))."
    Say "Re-run this script from an elevated prompt to set up automatic renewal."
}

# Machine-readable result for the app, which fills the two path fields in Settings
# from these lines. Only emitted when driven non-interactively, so the hand-run
# output stays prose.
if (-not (Interactive)) {
    Write-Host "NS_CERT_FILE=$CertFile"
    Write-Host "NS_KEY_FILE=$KeyFile"
}

Say ""
Say "Certificate installed:"
Say "  cert: $CertFile"
Say "  key:  $KeyFile"
Say ""
Say "Start the console over HTTPS with:"
Say "  NetworkSentinel -w --https ``"
Say "      --tls-cert `"$CertFile`" ``"
Say "      --tls-key  `"$KeyFile`""
Say ""
Say "Or set the same paths under Settings -> Remote access to make it the default."
Say ""
Say "The renewal task rewrites these files; the console reloads them within a few"
Say "minutes, so no restart is needed at renewal."
Say ""
Say "Reachability from outside your LAN still needs a router port-forward to this machine."
Say "Forward only the HTTPS port, and use a long unique master password."
