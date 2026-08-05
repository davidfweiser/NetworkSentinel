# Network Sentinel (Windows)

Native **Windows** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking**.

Three ways to run it (same idea as the Linux build):

| Mode | When to use |
|------|-------------|
| **Desktop GUI** | Interactive workstation (default) |
| **Terminal UI (`--tui`)** | Server Core, RDP console, SSH-style workflows |
| **Headless web UI (`-w`)** | Browser dashboard on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement. Version **0.5.1**.

---

## What's new in 0.5.1

The web console header's first button is now a single **Sleep ⇄ Wake** toggle. Sleeping stops *everything the console watches* — the connection and port poll plus the failed-logon, closed-port probe, ARP, startup-item, exfiltration and honeypot watchers — so asleep means nothing is being observed rather than a dashboard that stopped updating. Firewall blocks stay in force: sleeping stops watching, it never unblocks an address the machine is already protected from.

The page follows the same state — live tabs dim, a banner explains what stopped, and the 2.5-second refresh drops to a 30-second heartbeat, so a wake from another tab or client still reaches the page. Sleep is server state, so a reload while asleep still shows *Asleep*, and **Settings → Live monitoring** is the same control. See [Sleep / Wake](#sleep--wake).

---

## What's new in 0.5.0

Brings the Windows build level with the Linux and macOS 0.5.0 releases: the web console can now be reached from outside the LAN, over TLS, with a certificate it can issue itself.

| Area | What changed |
|------|--------------|
| **HTTPS** | The console serves TLS alongside plain HTTP — see [HTTPS and remote access](#https-and-remote-access). Certificate files are re-read when they change, so a renewal applies **without a restart**. Requests arriving by hostname redirect to TLS; requests to a bare IP stay on HTTP, because the certificate only covers the name. |
| **Kestrel** | `HttpListener` is gone. It can serve TLS on Windows, but only against a certificate in the machine store bound with `netsh http add sslcert` — admin-only, per-port, redone at every renewal. Kestrel reads the PEM or `.pfx` off disk, which is what a renewal rewrites. It also drops the `netsh http add urlacl` reservation that binding all interfaces used to need. |
| **DuckDNS** | A free hostname that follows your public IP, refreshed every 5 minutes by whichever front-end is running. Configure it in **Settings → Remote access** or with `--set-duckdns`. |
| **Issue certificate** | One button in the desktop app *and* the web console gets a free Let's Encrypt certificate for that name and fills in the paths. Uses a DNS-01 challenge through the DuckDNS API, so **nothing needs to be reachable on port 80**. Renewals run from a scheduled task. |
| **Login lockout** | Five wrong master-password guesses lock that client IP out, doubling to an hour, answered with `429` + `Retry-After`. The old fixed delay only slowed one connection at a time; this caps a parallel guesser. |

**Upgrading** is in place and now genuinely non-destructive: `%ProgramData%\NetworkSentinel` is both the install folder and the data directory, so the installer replaces **only files the package ships**. Settings, master password, allowlist, logs, host history, threat log, the DuckDNS token, `tls\`, and `acme\` all survive. Re-run the installer and confirm the web header reads `v0.5.0`.

Two Windows-specific notes:

- **Certificate issuance uses [Posh-ACME](https://poshac.me)**, not `acme.sh`. The script installs it per-user from the PowerShell Gallery on first run, and — unlike `acme.sh` — it does not register its own renewal job, so a `NetworkSentinel-CertRenew` scheduled task is created for that. Registering it needs elevation.
- **A framework-dependent build now needs the ASP.NET Core 8 Runtime** as well as the Desktop Runtime; the Desktop Runtime alone is no longer enough. The server package is self-contained and needs neither. See [Requirements](#requirements).

---

## What's new in 0.4.0

Brought the Windows build level with the Linux and macOS 0.4.0 releases.

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
- For a **framework-dependent** build (what `scripts\install.ps1` produces), the target machine needs **both**:
  - [.NET 8 **Desktop** Runtime](https://dotnet.microsoft.com/download) — the WPF GUI
  - [ASP.NET Core 8 Runtime](https://dotnet.microsoft.com/download) — Kestrel, which serves the web console. The Desktop Runtime alone is no longer enough; without this the app fails to start. Check with `dotnet --list-runtimes`.
  - The default **server package** (`scripts\package-server.ps1`) is self-contained and needs neither.
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
.\NetworkSentinel-windows-server-x64-0.5.1.install.cmd
# optional port:
.\NetworkSentinel-windows-server-x64-0.5.1.install.cmd -Port 18765
# unpack without installing:
.\NetworkSentinel-windows-server-x64-0.5.1.install.cmd --extract-only
```

The one-file installer is a `.cmd`, not a `.ps1`: `cmd.exe` stops reading the script at `exit /b`, so the ZIP appended to it is never parsed. PowerShell tokenizes an entire `-File` script before running any of it, and the cost on appended binary is quadratic (16 MB ≈ 5½ minutes) before it fails to parse at all — so the shell-style "payload after exit" trick only works with a `cmd` entry point.

**Or classic zip:**

```powershell
# Unzip, then either double-click INSTALL.cmd or:
powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1
powershell -ExecutionPolicy Bypass -File .\install-from-package.ps1 -Port 18765
```

That copies files to `%ProgramData%\NetworkSentinel\`, opens the firewall port, and registers **Scheduled Task** `NetworkSentinel-Web`:

```text
NetworkSentinel.exe -w 18765
```

#### Starting at boot

The task is what makes it survive a reboot, and it is configured for an unattended server:

| Setting | Value | Why |
|---------|-------|-----|
| Trigger | **At startup** | Runs at boot — **no one has to log in** |
| Principal | `SYSTEM`, **Highest** | Already elevated, so firewall rules work without a UAC prompt |
| `-StartWhenAvailable` | on | Catches up if the machine was off at the scheduled moment |
| `-RestartCount 3`, `-RestartInterval 1m` | on | Restarts the console if it exits unexpectedly |
| `-AllowStartIfOnBatteries` | on | A laptop-as-server does not silently skip startup |

Check it after install, and after the first reboot:

```powershell
schtasks /Query /TN "NetworkSentinel-Web" /V /FO LIST | findstr /C:"Status" /C:"Next Run" /C:"Last Result"
```

Restart it after changing HTTPS or certificate settings (Kestrel binds its endpoints at startup):

```powershell
schtasks /End /TN "NetworkSentinel-Web"
schtasks /Run /TN "NetworkSentinel-Web"
```

Open `http://localhost:18765/` (or `http://<server-ip>:18765/`). **First browser visit creates a master password.** Change it anytime under **Settings → Master password**.

#### HTTPS on the server

The installer also opens TCP **18443** so that turning HTTPS on later needs no second firewall change; pass `-HttpsPort 0` to skip it, or `-HttpsPort <n>` for a different one. Nothing listens there until you enable HTTPS — the scheduled task passes only `-w <port>`, and the TLS settings come from `settings.json`, so the GUI, TUI, and web console all drive it. See [HTTPS and remote access](#https-and-remote-access) for issuing a free certificate. Restart the task afterwards.

> **Changing the HTTPS port later needs its own inbound rule.** The installer only opens the port it was told about, so pointing the console at a different one — say because another machine already uses 18443 — leaves connections dying at the firewall before Kestrel sees them. It looks exactly like a broken certificate. Add the rule, **inbound**; an outbound rule does nothing here, since browsers connect *in* and Windows allows outbound by default:
>
> ```powershell
> netsh advfirewall firewall add rule name="NetworkSentinel-WebTls-19443" dir=in action=allow protocol=TCP localport=19443 enable=yes profile=any
> ```
>
> The certificate covers the **hostname**, not a port, so any port serves it equally well. Testing from inside your own LAN can also fail on routers that will not hairpin traffic back through their public IP — try `https://<server-lan-ip>:<port>` (a name-mismatch warning there is expected and harmless), and confirm the real thing from a phone on cellular data.

No URL ACL is reserved. That was an `HttpListener` requirement; Kestrel binds the socket directly. An uninstall clears any reservation an older install left behind.

#### Upgrades and uninstall

Re-running the installer **upgrades in place**: it stops the running task, replaces the binaries, and restarts. `%ProgramData%\NetworkSentinel` is both the install folder and the data directory, so the installer removes **only the files the package ships** — the master password hash, settings, allowlist, logs, host history, threat log, `duckdns.json`, `tls\`, and `acme\` all survive. The web page header shows the running version (e.g. `v0.5.1`) — check it after an upgrade to confirm the new build is live.

Uninstall keeps that same data by default so a reinstall picks up where you left off:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1
powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1 -PurgeData   # settings, certs, ACME account too
```

`-PurgeData` also deletes the Posh-ACME account, which cannot be recovered — a reinstall registers a new one, counting against Let's Encrypt's rate limits.

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

#### Sleep / Wake

The first button in the web console header is a single **Sleep ⇄ Wake** toggle:

- **Sleep** stops *everything the console watches* — the connection/port poll plus the failed-logon, closed-port probe, ARP, startup-item, exfiltration and honeypot watchers — and parks the page: the live tabs dim, a banner explains the state, and the browser drops its 2.5-second refresh so a sleeping console costs nothing on either end
- **Wake** starts monitoring again from live data and restores the normal refresh
- **Firewall blocks stay in force while asleep.** Sleeping stops watching; it never unblocks an address the machine is already protected from
- The state is the server's, not the browser's: reload or open a second tab and you still see *Asleep*, and the **Settings → Live monitoring** switch is the same control. While asleep the page keeps a 30-second heartbeat so a wake from anywhere shows up here
- Sleep is a runtime state — it is not written to `settings.json`, so restarting the service comes back up monitoring
- Sleep applies to the process you pressed it in; a desktop or TUI instance is a separate process and keeps running (the TUI has its own `p` key for the same thing)

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

It also copies `scripts\issue-duckdns-cert.ps1` next to the executable. That is what **Settings → Remote access → Issue certificate** runs, so the button works from an installed copy with no source tree present — see [Remote access from the desktop Settings](#remote-access-from-the-desktop-settings).

> **Moving the installed folder to another machine?** This publish is framework-dependent, and since 0.5.0 it needs the **ASP.NET Core 8 Runtime** (Kestrel) as well as the **.NET 8 Desktop Runtime** — the Desktop Runtime alone is no longer enough, and the app will not start without both. The build machine already has them, because the .NET SDK ships both shared frameworks, so installing from source here just works. Confirm elsewhere with `dotnet --list-runtimes`, or use the self-contained [server package](#server-package-no-compile-on-the-server), which needs no runtime at all.

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

Publish (framework-dependent — target needs the Desktop **and** ASP.NET Core 8 runtimes, see [Requirements](#requirements)):

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

Issuance goes through [**Posh-ACME**](https://poshac.me), which ships a DuckDNS plugin — it is the Windows counterpart to `acme.sh` on the Linux build. On first run the script installs it into `%ProgramData%\NetworkSentinel\modules`, and keeps ACME state in `%ProgramData%\NetworkSentinel\acme`. Both live with the app's data rather than in a user profile, because issuance runs from the desktop app as the signed-in user while renewal runs from a SYSTEM scheduled task — a per-profile copy would be visible to only one of them, and they would end up with separate accounts and separate certificates.

Getting the module installed is the step most likely to need help on a locked-down machine, so it has three routes, tried in order:

1. `Save-Module` from the PowerShell Gallery — the normal path.
2. A direct download of the `.nupkg`, which is just a zip. Windows ships PackageManagement/PowerShellGet **1.0.0.1 with no NuGet provider**, and bootstrapping one fails on plenty of otherwise healthy machines with `Unable to resolve package source` — this route needs none of that stack.
3. A package you supply yourself — see [restricted networks](#issuance-on-a-restricted-network) below.

The script also pre-compiles the small helper class Posh-ACME builds at import time. Left to the module, that compile resolves `X509Chain` against a .NET Core facade assembly on some machines and fails with *"This type has been forwarded to assembly 'System.Security.Cryptography'"*, taking the whole import down with it.

The script is non-interactive when it has everything it needs, which is how the button drives it:

```powershell
$env:NS_ASSUME_YES = '1'; $env:NS_ACME_EMAIL = 'you@example.com'
.\scripts\issue-duckdns-cert.ps1 myhost
```

`NS_ACME_EMAIL` is only used the first time, to register the Let's Encrypt account. Without a console the script never prompts — anything missing is a clear error instead of a hang.

Unlike `acme.sh`, Posh-ACME does not install its own renewal job, so the script registers a **`NetworkSentinel-CertRenew` scheduled task** that runs `Submit-Renewal` daily as SYSTEM and re-copies the files into place. Registering it needs elevation; run the script from an elevated prompt (or press the button in the elevated desktop app) or renewal stays manual.

The token is stored in `%ProgramData%\NetworkSentinel\duckdns.json`, is **never sent to the browser** (the settings page shows only whether one is saved), and is prompted for rather than passed as a flag so it stays out of shell history and the process list. Because `AppPaths` grants `BUILTIN\Users` Modify on the data directory so the GUI and the SYSTEM service can share state, that file and the `tls\` folder break inheritance and are restricted to **SYSTEM, Administrators, and the writer** — otherwise the token and private key would be readable by every local user. While the console runs it refreshes the A record every 5 minutes.

> **Before you forward a port.** This console can add and remove firewall rules on this machine, and anyone who guesses the master password gets that control. A VPN or [Tailscale](https://tailscale.com) is the safer way to reach it from outside — `tailscale serve` even supplies a valid certificate with no port-forwarding at all. If you do forward a port, forward **only** the HTTPS one and use a long unique password.

#### Issuance on a restricted network

Issuance is the one feature that needs the server to reach **out**. DNS-01 means nothing has to be reachable *inbound* on port 80 — but the order still goes to Let's Encrypt, and the TXT record still goes to DuckDNS.

| Host | Port | Needed for |
|------|------|-----------|
| `acme-v02.api.letsencrypt.org` | 443 out | Placing the certificate order — **issuance cannot work without this** |
| `www.duckdns.org` | 443 out | Writing the DNS-01 TXT record, and the hostname refresh |
| `www.powershellgallery.com` | 443 out | Installing Posh-ACME — first run only, and avoidable (below) |

Two escape hatches, for when those cannot all be opened:

- **Behind a proxy.** The download resolves the system proxy and authenticates with the process identity. Set `NS_PROXY` to override it. This matters more than it looks: `Invoke-WebRequest` resolves the *calling account's* proxy configuration, and issuance runs as **SYSTEM** from the web console, which does not inherit a signed-in user's settings — so it can fail on a machine where a browser reaches the gallery fine.
- **No outbound access to the gallery.** Download `Posh-ACME.<version>.nupkg` on a machine that has access and copy it into `%ProgramData%\NetworkSentinel\` — it is picked up automatically, no restart and no elevation. `NS_POSHACME_NUPKG` names a path explicitly if you would rather keep it elsewhere.

  ```powershell
  # on a machine with internet
  Invoke-WebRequest 'https://www.powershellgallery.com/api/v2/package/Posh-ACME' -OutFile Posh-ACME.nupkg
  ```

If Let's Encrypt itself is unreachable and cannot be opened, issue the certificate **on another machine** instead. DNS-01 proves control through the DuckDNS API, not through the server, so any machine with the same token can issue for the name — then copy the `.fullchain.cer` and `.key` into the server's `%ProgramData%\NetworkSentinel\tls\` and point **Settings → Remote access** at them. Renewal is manual that way, roughly every 60 days.

#### If issuance fails

Failures name the layer that broke rather than a generic error, and the full transcript is always written to `%ProgramData%\NetworkSentinel\logs\cert-issue.log`.

| What it says | What it means |
|--------------|---------------|
| `TCP 443 to www.powershellgallery.com is blocked` | Only the module download is blocked — use a local package, above |
| `could not reach Let's Encrypt` | The ACME endpoint is unreachable; check egress before anything else |
| `It presented a certificate issued by: <not Let's Encrypt>` | SSL inspection is rewriting the connection — exempt the host, or trust the product's root CA |
| `forbidden by its access permissions` | A firewall rule **on this machine** denied the outbound connect — check the console's own **Firewall** tab first |
| `DuckDNS refused the DNS record` | Almost always a wrong token or subdomain — confirm **Update now** reports OK first |
| `You cannot call a method on a null-valued expression` | Posh-ACME's error handler masking a lower-level failure; read the TLS probe verdict beside it, not this |

> **A wrong DuckDNS token looks like a certificate problem.** Control is proved by writing a TXT record through the DuckDNS API, so a bad token fails at the DNS step, not the TLS one. If issuance fails, check that **Update now** reports OK before looking anywhere else.

The app will not auto-block its own infrastructure: the ACME endpoints, DuckDNS, the threat-intel feeds, and the PowerShell Gallery ship in the built-in [allowlist](#known-good-allowlist-never-block). Without that, a threat feed listing the CDN range Let's Encrypt sits on could have the console firewall its own certificate renewal. Note that an existing `allowlist.json` survives upgrades, so a server installed before this change needs those names added by hand.

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
