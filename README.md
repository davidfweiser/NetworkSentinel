# Network Sentinel (Windows)

Native **Windows** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking**.

Three ways to run it (same idea as the Linux build):

| Mode | When to use |
|------|-------------|
| **Desktop GUI** | Interactive workstation (default) |
| **Terminal UI (`--tui`)** | Server Core, RDP console, SSH-style workflows |
| **Headless web UI (`-w`)** | Browser dashboard on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement. Version **0.4.0**.

---

## What's new in 0.4.0

Brings the Windows build level with the Linux and macOS 0.4.0 releases.

| Area | What changed |
|------|--------------|
| **Intrusion detection** | Seven new detectors beyond the connection heuristics — [new-listener baseline](#intrusion-detection), threat-intel blocklists (FireHOL + Spamhaus), process reputation, honeypot decoy ports, ARP/gateway watch, startup-item watch, and an exfiltration monitor. All are toggleable per detector in **Settings** (desktop, TUI, and web console). |
| **Remote alerting** | Webhook push for Critical threats — **ntfy**, **Slack**, and **Discord** payloads are detected automatically, anything else gets generic JSON. |
| **Auto-block expiry** | Block rules can now expire after 1 h … 7 days instead of accumulating forever. Off by default; manual blocks stay permanent. |
| **Persistence** | First-seen hosts, the listening-port baseline, and the threat log survive restarts (`host-history.json`, `threat-log.jsonl`), so a relaunch no longer makes every known peer look new. |
| **New palette** | Backgrounds move from navy to deep slate and the severity colours are now shared with the iOS app, so the two front-ends read as one product. |

**Upgrading** is in place — master password, settings, and allowlist are preserved. Re-run the installer and confirm the web header reads `v0.4.0`.

Two Windows-specific notes:

- The **exfiltration monitor** needs administrator rights to enable its per-connection counters. The headless web service runs as SYSTEM and collects normally; an unelevated desktop session says so in its status line and stays quiet.
- **Connected UDP peers** are not tracked on Windows — the UDP table exposes no peer address for a connected socket. UDP *listeners* are still enumerated and still classify inbound traffic.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via Windows IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable`) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this PC, reverse DNS, geo/ISP when public |
| **Activity chart** | 5-minute connection chart with **threat markers**, in both the desktop app and the web console |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance — fast (45 s window) **and slow/paced** (10 min window, catches `nmap -T1`-style scans)
- **Scans of closed ports** (opt-in) — Windows Firewall drops those SYNs before the TCP stack sees them, so they never appear as connections; with dropped-packet logging on, a log watcher turns them into alerts within seconds
- RDP, SSH, and SMB hammering
- **Failed logon bursts** from the Windows Security event log (4625 / 4771) — catches RDP/SMB/WinRM brute-force even when it reuses one TCP session or paces below the connection-rate thresholds
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- **Outbound beaconing** — regular-interval new sessions to an uncommon remote port (C2 "calling home" signature); common client ports and LAN peers are excluded
- First-seen remote hosts — tracked **across restarts** (30-day persistent host history), so relaunching doesn't make every known peer look new again
- Multicast/broadcast chatter (mDNS, SSDP) is excluded from host tracking and the scan heuristics

### Intrusion detection
| Detector | What it catches |
|----------|-----------------|
| **New-listener alerts** | A new port starts listening after the baseline (backdoor/implant signature), or a known port changes owner process (service replaced/impersonated). Baseline persists in `host-history.json`; loopback-only and ephemeral (49152+) listeners are skipped. |
| **Threat-intel blocklists** | Remote IPs checked against **FireHOL level1** and **Spamhaus DROP** (fetched daily over HTTPS, cached offline). A match is an instant **Critical** — those ranges are attack infrastructure. |
| **Process reputation** | Command shells, script hosts and download cradles (`cmd`, `powershell`, `wscript`, `mshta`, `certutil`, `nc`, …) holding outbound connections to public hosts (reverse-shell signature, High); processes whose **image has been deleted** from a local fixed disk while still running (High — Windows keeps a running image locked, so this is deliberate anti-forensics); binaries running from `%TEMP%`, `Downloads` or `C:\Users\Public` with network activity; **unsigned** binaries under `Windows` / `Program Files` (Authenticode via WinVerifyTrust). Image paths come from `QueryFullProcessImageName` — no per-poll shelling out, and signature checks are cached per path off the poll loop. |
| **Honeypot decoy ports** (opt-in) | Binds decoy TCP ports (default `2323,3389,5900`). Nothing legitimate connects to a decoy, so any completed connection is a **zero-false-positive Critical**. Ports already in use are skipped — the listener binds exclusively, so it can never shadow a real service such as RDP on 3389. |
| **ARP / gateway watch** | The default gateway's MAC address changing (**Critical** — classic ARP-spoof MITM opener) or another LAN IP claiming the gateway's MAC (High). Reads the IP Helper route and neighbour tables; no elevation, no subprocess. |
| **Startup-item watch** | New or modified entries in the per-user and all-users **Startup** folders, the **Scheduled Tasks** store, and the **Run / RunOnce / Winlogon** registry keys (both registry views) — the standard persistence step right after a successful intrusion. Folders are watched live; the registry keys are baselined at start and diffed on a timer. Admin-only locations are skipped when running unprivileged. |
| **Exfiltration monitor** | Per-connection **TCP ESTATS** byte counters; alerts when outbound traffic to a single non-allowlisted public host exceeds a threshold (default **250 MB / 10 min**). LAN destinations (NAS backups) and allowlisted hosts stay quiet. TCP only — UDP/QUIC carries no equivalent counter. Enabling the counters requires administrator rights, so an unelevated GUI reports the feature as unavailable while the web service (SYSTEM) collects normally. |

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo). Threat events and the host/listener baseline **persist across restarts** (`threat-log.jsonl`, `host-history.json`).

### Remote alerting (webhook)
Set **Settings → Webhook URL** to push Critical threats off the machine — the payload adapts automatically: **ntfy** (plain text + `Title`/`Priority` headers), **Slack** (`{"text": …}`), **Discord** (`{"content": …}`), anything else gets a generic JSON document. Per-source/type cooldown stops a burst from flooding the channel.

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both) — rules are created as an `-In`/`-Out` pair and removed together
- **Block local ports** (TCP/UDP)
- Only manages rules named `NetworkSentinel-*` so other firewall rules are left alone
- All firewall changes go through **`netsh` in a separate process** (never firewall COM — COM from web/thread-pool threads can crash the host)
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Removing/unblocking a rule **suppresses auto-block for that IP for 24 h** (persisted), so removed rules stay gone across restarts
- **Auto-block expiry** (1 h … 7 days, off by default) — an expired address stops counting as blocked immediately; the `netsh` rule itself is deleted by a background sweep, which needs the app to be running elevated. Manual blocks are always permanent
- Settings stored machine-wide in `%ProgramData%\NetworkSentinel\settings.json` — shared by the GUI, TUI, and the web service (which runs as SYSTEM); falls back to `%LocalAppData%` if ProgramData is not writable
- **Run as Admin** when elevation is required

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `%ProgramData%\NetworkSentinel\allowlist.json` |
| **Remote feed** | Optional refresh from this repo’s `allowlist-default.json` on GitHub |

Domains are **DNS-resolved** to current IPs (cloud addresses change often); if a DNS pass fails, the previously resolved IPs are kept so an outage never strips protection. `cidrs` entries (e.g. `"140.82.112.0/20"`) in any allowlist file protect whole address ranges. On startup, **Restore good sites** removes any Network Sentinel blocks that hit allowlisted IPs (recovery if GitHub/Grok were blocked earlier).

Auto-block never touches allowlisted IPs. A **manual** block of an allowlisted IP asks for explicit confirmation instead of refusing outright.

> **Note:** Turning auto-block **off** does **not** remove rules already created. Use **Unblock**, **Restore good sites**, **Remove**, or **Remove All** on the Firewall tab.

---

## Requirements

- **Windows 10, 11, or Windows Server** (2019/2022+)
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download) on the target machine (framework-dependent publish)
- [.NET 8 SDK](https://dotnet.microsoft.com/download) to build
- **Administrator** rights to create or delete Windows Defender Firewall rules

> **Linux servers:** use the `linux` branch and `./scripts/package.sh` → one-file installer
> `networksentinel-*-linux-x64.install.sh` with `sudo ./….install.sh --web-service`.

---

## Quick start

```powershell
git clone https://github.com/davidfweiser/NetworkSentinel.git
cd NetworkSentinel
git checkout windows   # Windows WPF + TUI + web tree
dotnet run
```

### Modes

```powershell
# Desktop GUI (default)
dotnet run -c Release

# Terminal UI
dotnet run -c Release -- --tui

# Headless web UI (browser) — auto-picks a free high port, or set one
dotnet run -c Release -- -w
dotnet run -c Release -- -w 18765

# Set/reset the web console master password from the terminal
dotnet run -c Release -- --set-master-password

# Configure the DuckDNS hostname (token is prompted, not a flag)
dotnet run -c Release -- --set-duckdns

# Headless web UI over HTTPS as well as HTTP
dotnet run -c Release -- -w --https `
    --tls-cert "$env:ProgramData\NetworkSentinel\tls\myhost.duckdns.org.fullchain.cer" `
    --tls-key  "$env:ProgramData\NetworkSentinel\tls\myhost.duckdns.org.key"
```

Environment variables: `NETWORKSENTINEL_TUI=1`, `NETWORKSENTINEL_WEB=1`.

### Server package (no compile on the server)

Build artifacts **on a dev PC** that has the .NET 8 SDK:

```powershell
git checkout windows
powershell -ExecutionPolicy Bypass -File .\scripts\package-server.ps1
```

Output:

```text
dist\NetworkSentinel-windows-server-x64-<version>.zip
dist\NetworkSentinel-windows-server-x64-<version>.install.cmd   ← one-file installer
dist\*.sha256
```

Self-contained by default — the server does **not** need the .NET SDK or a compiler (runtime is inside the package).

**On the Windows server — one-file installer (recommended):**

```powershell
# Copy the .install.cmd to the server, then run it (UAC prompt if not elevated):
.\NetworkSentinel-windows-server-x64-0.4.0.install.cmd
# optional port:
.\NetworkSentinel-windows-server-x64-0.4.0.install.cmd -Port 18765
# unpack without installing:
.\NetworkSentinel-windows-server-x64-0.4.0.install.cmd --extract-only
```

The one-file installer is a `.cmd`, not a `.ps1`: `cmd.exe` stops reading the script at `exit /b`, so the ZIP appended to it is never parsed. PowerShell tokenizes an entire `-File` script before running any of it, and the cost on appended binary is quadratic (16 MB ≈ 5½ minutes) before it fails to parse at all — so the shell-style "payload after exit" trick only works with a `cmd` entry point.

**Or classic zip:**

```powershell
# Unzip, then either double-click INSTALL.cmd or:
powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1
powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1 -Port 18765
```

That copies files to `%ProgramData%\NetworkSentinel\`, opens the firewall port, reserves a URL ACL, and registers **Scheduled Task** `NetworkSentinel-Web` at startup:

```text
NetworkSentinel.exe -w 18765
```

Open `http://localhost:18765/` (or `http://<server-ip>:18765/`). **First browser visit creates a master password.** Change it anytime under **Settings → Master password**.

Re-running the installer **upgrades in place**: it stops the running task, replaces the binaries, and restarts. Master password, settings, and allowlist are **preserved**. The web page header shows the running version (e.g. `v0.4.0`) — check it after an upgrade to confirm the new build is live.

#### Web console tabs

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers), monitoring/firewall status, recent threats |
| **Connections / Threats** | Live traffic with a **Block** button on every row |
| **Hosts** | Remote peers; block / unblock by row or by typed IP |
| **Ports** | Local listeners; one-click **Block port** |
| **Firewall** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, geo lookups, failed-logon monitoring, closed-port scan detection, the intrusion detectors (threat intel, new-listener, process reputation, ARP watch, startup-item watch, exfiltration, honeypot), **HTTPS + DuckDNS remote access** (including **Issue certificate**), webhook alerts, auto-block + minimum severity + expiry, block direction (in/out), allowlist feed, **change master password**, **Remove all rules** |

The console protects itself: it refuses to remove its own firewall access rule or block its own port (doing so would cut off your browser mid-request and look exactly like a crash).

Uninstall (Admin):

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1
```

### Server install from source (dev machine only)

If the machine **can** compile:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-service.ps1
```

### Install (Start Menu + Desktop shortcut)

From the repo root (requires [.NET 8 SDK](https://dotnet.microsoft.com/download)):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

Optional flags:

```powershell
# Start Menu only (no desktop icon)
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -SkipDesktop

# Install and launch
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Launch
```

This publishes the app to `%LocalAppData%\Programs\NetworkSentinel\` and creates:

| Shortcut | Location |
|----------|----------|
| **Start Menu** | Start → type **Network Sentinel** |
| **Desktop** | `Network Sentinel` icon on your desktop |

Uninstall shortcuts + install folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1
```

Settings remain in `%ProgramData%\NetworkSentinel\` until you delete that folder yourself.

### Release build

```powershell
dotnet build -c Release
```

Executable:

```text
bin\Release\net8.0-windows\NetworkSentinel.exe
```

Publish (framework-dependent):

```powershell
dotnet publish -c Release -r win-x64 --self-contained false
```

The app starts **without** forcing UAC (so TUI/web work on servers). Desktop install shortcuts are still marked **Run as administrator**. TUI key **`u`** and the web **Authorize** button relaunch elevated via UAC when firewall changes need it. The web scheduled-task installer runs as **SYSTEM** (already elevated).

### Web UI security
- First browser visit **creates a master password** (min. 8 characters)
- Later visits require that password; change it under **Settings → Master password**
- Can't reach a browser yet (e.g. still opening the port in a cloud firewall), or lost the password? Set/reset it from the terminal instead — see below
- Hash stored as PBKDF2-SHA256 (random salt, 200k iterations) in `%ProgramData%\NetworkSentinel\web-master.json` — never plain text
- Session cookie until sign-out, browser close, or 12 hours idle
- Failed attempts are throttled **per client IP**: five wrong guesses trigger a lockout that doubles with each further attempt (1 minute up to 1 hour), answered with `429` and a `Retry-After`. A fixed delay alone only slows one connection at a time — this caps a parallel guesser

### HTTPS and remote access

The console is served by **Kestrel** rather than `HttpListener`. On Windows `HttpListener` *can* do TLS, but only against a certificate imported into the machine store and bound to the port with `netsh http add sslcert` — per-port, admin-only, and redone at every renewal. Kestrel reads the PEM or `.pfx` straight off disk, which is exactly what an ACME renewal rewrites. It also removes the `netsh http add urlacl` reservation that binding to all interfaces used to need, so the console no longer falls back to localhost-only when it isn't elevated.

HTTP and HTTPS are served side by side: the LAN keeps working on plain HTTP while requests that arrive **by hostname** are redirected to TLS — requests to a bare IP are left alone, since the certificate only covers the name and redirecting an IP would trade a working page for a certificate warning.

```powershell
.\NetworkSentinel.exe -w --https `
    --tls-cert "$env:ProgramData\NetworkSentinel\tls\myhost.duckdns.org.fullchain.cer" `
    --tls-key  "$env:ProgramData\NetworkSentinel\tls\myhost.duckdns.org.key"
```

| Flag | Meaning |
|------|---------|
| `--https` | Serve TLS in addition to HTTP |
| `--https-port PORT` | TLS port (default **18443**; below 1024 needs Administrator) |
| `--tls-cert PATH` | PEM fullchain, or a `.pfx` / `.p12` bundle |
| `--tls-key PATH` | PEM private key (omit for `.pfx`) |
| `--tls-password PW` | Password for a `.pfx` / `.p12` |
| `--no-https` | Force plain HTTP for this run |

Flags win over `settings.json` for that run **without overwriting it**, so `--https` is safe to try. The same values live under **Settings → Remote access** in *both* front-ends — the desktop app and the web console — so you never have to hand-edit a config file; endpoint changes take effect at the console's next restart. Certificate files are re-read when they change on disk (checked every 5 minutes), so an **ACME renewal applies without restarting** the console. Session cookies gain the `Secure` flag automatically when the request arrives over TLS.

Already have a `.pfx` (an internal CA, or one exported from the certificate store)? Point `--tls-cert` at it, leave `--tls-key` empty, and pass `--tls-password` if it has one — none of the DuckDNS or Let's Encrypt machinery below is required.

#### Free trusted certificate for a duckdns.org name

[DuckDNS](https://www.duckdns.org) gives a free hostname that follows your public IP. The certificate comes from Let's Encrypt via a **DNS-01** challenge — proving control by writing a TXT record through the DuckDNS API, so **nothing has to be reachable on port 80**.

Easiest route is either front-end: fill in the subdomain and token under **Settings → Remote access** (desktop app or web console), then press **Issue certificate**. It runs the same script below and fills the two path fields in for you. From a terminal:

```powershell
.\NetworkSentinel.exe --set-duckdns          # subdomain + token (token is prompted, not a flag)
.\scripts\issue-duckdns-cert.ps1             # installs Posh-ACME if needed, issues + installs the cert
```

Entering the subdomain and token only sets up **dynamic DNS** — it keeps the name pointed at your current IP. Issuing the certificate is a separate step, whether you press the button or run the script.

Issuance goes through [**Posh-ACME**](https://poshac.me), which ships a DuckDNS plugin — it is the Windows counterpart to `acme.sh` on the Linux build. The script installs it per-user from the PowerShell Gallery on first run (Windows PowerShell 5.1 still negotiates TLS 1.0 by default, so it enables TLS 1.2 and bootstraps the NuGet provider first). ACME state is kept in `%ProgramData%\NetworkSentinel\acme` rather than the calling account's profile, so the desktop app (your user) and the web service (SYSTEM) share one account and one certificate instead of issuing their own.

The script is non-interactive when it has everything it needs, which is how the button drives it:

```powershell
$env:NS_ASSUME_YES = '1'; $env:NS_ACME_EMAIL = 'you@example.com'
.\scripts\issue-duckdns-cert.ps1 myhost
```

`NS_ACME_EMAIL` is only used the first time, to register the Let's Encrypt account. Without a console the script never prompts — anything missing is a clear error instead of a hang.

Unlike `acme.sh`, Posh-ACME does not install its own renewal job, so the script registers a **`NetworkSentinel-CertRenew` scheduled task** that runs `Submit-Renewal` daily as SYSTEM and re-copies the files into place. Registering it needs elevation; run the script from an elevated prompt (or press the button in the elevated desktop app) or renewal stays manual.

The token is stored in `%ProgramData%\NetworkSentinel\duckdns.json`, is **never sent to the browser** (the settings page shows only whether one is saved), and is prompted for rather than passed as a flag so it stays out of shell history and the process list. Because `AppPaths` grants `BUILTIN\Users` Modify on the data directory so the GUI and the SYSTEM service can share state, that file and the `tls\` folder break inheritance and are restricted to **SYSTEM, Administrators, and the writer** — otherwise the token and private key would be readable by every local user. While the console runs it refreshes the A record every 5 minutes.

> **Before you forward a port.** This console can add and remove firewall rules on this machine, and anyone who guesses the master password gets that control. A VPN or [Tailscale](https://tailscale.com) is the safer way to reach it from outside — `tailscale serve` even supplies a valid certificate with no port-forwarding at all. If you do forward a port, forward **only** the HTTPS one and use a long unique password.

#### Set or reset the master password from the terminal

```powershell
# elevated prompt (so the file lands in %ProgramData%, where the service reads it)
Start-Process -Wait .\NetworkSentinel.exe --set-master-password

# then restart the web service so it picks up the change
schtasks /End /TN "NetworkSentinel-Web"
schtasks /Run /TN "NetworkSentinel-Web"
```

`Start-Process -Wait` (or running it from `cmd.exe`) matters: the app is a GUI-subsystem binary, so launched directly from PowerShell the prompt would share the console with your shell. Or delete `%ProgramData%\NetworkSentinel\web-master.json` outright and let the next browser visit create a fresh one.

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block toggle, managed rule list |
| **Settings** | Monitor poll interval, geo lookups, failed-logon monitoring, closed-port scan detection, **remote access (HTTPS + DuckDNS)**, allowlist feed, data folder |

### Remote access from the desktop Settings

**Settings → Remote access (web console)** configures HTTPS and DuckDNS without touching a config file or the command line:

| Field | What goes in it |
|-------|-----------------|
| **DuckDNS subdomain** | Just the label — `myhost`, not `myhost.duckdns.org`. The checkbox arms the 5-minute refresh. |
| **DuckDNS token** | Your token from duckdns.org, masked as you type. **Update now** tests it immediately and reports the result. |
| **Serve the console over HTTPS** | On/off, with the TLS port beside it |
| **Issue certificate** | Gets a free Let's Encrypt certificate for the DuckDNS name above and **fills in the two paths below**. The email box beside it is only used the first time, to register the account when Posh-ACME is installed. |
| **Certificate** / **Private key** | Filled in by **Issue certificate**; still editable if your certificate lives elsewhere. Validated as you enter them |
| **Redirect HTTP to HTTPS** | On by default |

**Issue certificate** shells out to `issue-duckdns-cert.ps1` — both installers put a copy beside the binary so it works without a source tree. It runs the script non-interactively (`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass`), so it needs the subdomain and token saved first; issuance waits on DNS propagation and takes a few minutes, during which the button reads *Issuing…*. Failures name the likely cause where the wording identifies one — a rejected DuckDNS token, slow propagation, a Let's Encrypt rate limit, a Gallery download that couldn't negotiate TLS 1.2 — quote the last few output lines, and point at the full transcript in `%ProgramData%\NetworkSentinel\logs\cert-issue.log`.

> **A wrong DuckDNS token looks like a certificate problem.** Issuance proves control by writing a TXT record through the DuckDNS API, so a bad token fails at the DNS step, not the TLS one. If issuance fails, check that **Update now** reports OK before looking anywhere else.

Pressing the button again when the certificate is still valid is safe: a certificate with more than 30 days left is reused rather than re-issued, and it is installed and the paths filled in as usual. To re-issue early — rarely needed, and rate-limited by Let's Encrypt — run the script with `NS_FORCE_RENEW=1`.

The same button is in the **web console's** Settings tab. There it runs in the background and the page polls for the result, because holding an HTTP request open for the length of an ACME run would time out the browser. It needs an authenticated session like every other action, and only one run happens at a time — concurrent ACME runs for the same name fight over the same TXT record. Be aware of what the button is: an authenticated browser session can start a PowerShell script that, on first use, installs a module from the PowerShell Gallery and registers a Let's Encrypt account. That is a real capability to expose remotely — the master password is the only thing in front of it, so make it a long unique one, and prefer a VPN or Tailscale over a forwarded port.

A status line at the top of the card shows certificate expiry, the live DuckDNS result, and the full console URL once both halves are configured. Certificate and port changes apply the next time the **web console** starts — the desktop app doesn't serve anything itself — but the **DuckDNS refresh runs in the desktop app too**, so the hostname stays current whenever either front-end is open.

The token is written to `duckdns.json`, not `settings.json`; the GUI, TUI, and web console all read the same file.

### Auto-block
1. Run elevated (Administrator).
2. Turn **Auto-block** **On** (top bar, sidebar, or Firewall tab).
3. Choose **Minimum severity** (default **High**).
4. Public IPs that hit that severity get Windows Firewall block rules automatically.
5. Private/LAN addresses and “new host” info events are **never** auto-blocked.

---

## How it works (high level)

```text
┌─────────────────┐     poll ~1.2s      ┌──────────────────────┐
│  Windows stack  │ ─────────────────► │ NetworkMonitorService │
│  (iphlpapi)     │                    └──────────┬───────────┘
└─────────────────┘                               │
                                                  ▼
                                       ┌──────────────────────┐
                                       │ IntrusionDetector    │
                                       │ (heuristics)         │
                                       └──────────┬───────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    ▼                             ▼                             ▼
           Geo / DNS lookup              WPF dashboard UI              FirewallService
           (origin details)              (MVVM + charts)               (netsh, cached)
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/IpHelper.cs` | P/Invoke into Windows IP Helper API |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/AuthLogMonitor.cs` | Failed-logon detection from the Windows Security event log |
| `Services/ProbeLogMonitor.cs` | Closed-port scan detection from the Windows Firewall log |
| `Services/ProcessReputationService.cs` | Shell / deleted-image / throwaway-path / unsigned-binary checks |
| `Services/Authenticode.cs` | WinVerifyTrust signature verification |
| `Services/ThreatIntelService.cs` | FireHOL + Spamhaus feed download, cache, CIDR matching |
| `Services/HoneypotService.cs` | Decoy TCP listeners |
| `Services/ArpWatchService.cs` | Gateway MAC watch from the IP Helper route/neighbour tables |
| `Services/PersistenceWatcher.cs` | Startup folder, scheduled task, and Run-key watch |
| `Services/ExfiltrationMonitor.cs` | TCP ESTATS per-connection byte sampling |
| `Services/HostHistoryStore.cs` | Persistent host + listener baseline, threat log |
| `Services/WebhookNotifier.cs` | ntfy / Slack / Discord / generic JSON alerts |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | Windows Firewall rule create/list/remove (netsh, cached rule list); auto-block expiry sweep |
| `Services/AppSettings.cs` | Auto-block preferences + suppress list (JSON on disk) |
| `Services/DuckDnsUpdater.cs` | DuckDNS dynamic-DNS refresh loop; token file with an admins-only ACL |
| `Services/TlsCertificateProvider.cs` | Loads the console's PEM/`.pfx` and re-reads it after an ACME renewal |
| `Services/CertIssuanceService.cs` | Drives `issue-duckdns-cert.ps1` behind the **Issue certificate** button |
| `Services/LoginThrottle.cs` | Per-client-IP lockout for the console's password endpoints |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `Web/WebApp.cs` | Headless web console (Kestrel HTTP/HTTPS host + embedded single-page UI) |
| `Web/WebAuthStore.cs` | Master password hash + session tokens |
| `Web/WebTlsOptions.cs` | TLS values from the command line, overlaid on the saved settings |
| `scripts/issue-duckdns-cert.ps1` | Let's Encrypt DNS-01 issuance via Posh-ACME + renewal scheduled task |
| `Tui/TuiApp.cs` | Terminal UI (Spectre.Console) |
| `MainWindow.xaml` | Dashboard UI |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Scan/brute-force heuristics count **new inbound connections to ports this PC is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing. The only outbound rule is the beacon detector, which requires a regular cadence to an uncommon port on a public IP.
- Public IP geolocation uses the free `ipwho.is` endpoint over **HTTPS**, falling back to `ip-api.com` (plain HTTP) only if that fails. Both are rate-limited and best-effort. Toggle lookups off in **Settings** (desktop app or web console), or set `"GeoLookupEnabled": false` in `%ProgramData%\NetworkSentinel\settings.json`; reverse DNS still runs. LAN/private addresses are labeled as local.
- **Failed-logon detection** subscribes to the Windows Security event log (4625 / 4771), which requires Administrator or membership in the local **Event Log Readers** group. Without it the app keeps running and shows why under **Settings → Failed-logon monitoring**; set `"AuthLogMonitorEnabled": false` to turn the feature off. The web service runs as SYSTEM, so it always has access.
- **Closed-port scan detection** is off by default because it turns on Windows Firewall **dropped-packet logging** (a firewall setting, not a rule — nothing extra is blocked or allowed). Enable it under **Settings → Closed-port scan detection** while elevated, or set `"ProbeLogEnabled": true`. The watcher tails `%windir%\System32\LogFiles\Firewall\pfirewall.log` (readable by Administrators/SYSTEM), counts pure SYNs only, and the toggle turns the logging back off.
- **Monitor poll interval** (desktop **Settings**, default 1.2 s, `"MonitorPollMs"`) is also the activity-chart sample rate, so a slower interval widens the window the chart covers rather than thinning it.
- The allowlist remote feed can likewise be toggled in **Settings** or via `"AllowlistUseRemoteFeed": false` in the same file.
- **Threat-intel feeds** download FireHOL level1 and Spamhaus DROP once a day to `threat-intel-cache.json` and fall back to the cache when offline; turn them off with `"ThreatIntelEnabled": false`.
- The **honeypot** is off by default because it binds real ports — enable it under **Settings → Honeypot decoy ports** once you have confirmed the chosen ports are free. The decoy sockets bind exclusively, so a port already served by a real service is skipped rather than hijacked.
- The **exfiltration monitor** enables per-connection TCP ESTATS counters, which requires Administrator. Unelevated it reports itself unavailable and stays quiet; the web service (SYSTEM) is unaffected.
- **Connected UDP peers** are not tracked on Windows: the UDP table exposes only the local endpoint and owning PID, with no peer address for a connected socket (Linux reads it from `/proc/net/udp`). UDP **listeners** are still enumerated and still classify inbound traffic.
- If the app ever exits unexpectedly, check `%ProgramData%\NetworkSentinel\logs\crash.log` — unhandled errors are logged there with a stack trace.
- Some system sockets may show as `System` or `PID n` depending on permissions.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- A port that shows `LISTEN` locally but is unreachable from outside is usually a **network** firewall, not this app: on a cloud VM (Azure, AWS, …) the provider's security group can drop inbound traffic before it reaches the host. Open the port there too.

---

## License

Private project — all rights reserved unless you add a license file later.
