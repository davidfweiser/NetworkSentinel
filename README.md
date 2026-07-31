# Network Sentinel (Windows)

Native **Windows** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking**.

Three ways to run it (same idea as the Linux build):

| Mode | When to use |
|------|-------------|
| **Desktop GUI** | Interactive workstation (default) |
| **Terminal UI (`--tui`)** | Server Core, RDP console, SSH-style workflows |
| **Headless web UI (`-w`)** | Browser dashboard on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement. Version **0.3.4**.

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
.\NetworkSentinel-windows-server-x64-0.3.4.install.cmd
# optional port:
.\NetworkSentinel-windows-server-x64-0.3.4.install.cmd -Port 18765
# unpack without installing:
.\NetworkSentinel-windows-server-x64-0.3.4.install.cmd --extract-only
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

Re-running the installer **upgrades in place**: it stops the running task, replaces the binaries, and restarts. Master password, settings, and allowlist are **preserved**. The web page header shows the running version (e.g. `v0.3.4`) — check it after an upgrade to confirm the new build is live.

#### Web console tabs

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers), monitoring/firewall status, recent threats |
| **Connections / Threats** | Live traffic with a **Block** button on every row |
| **Hosts** | Remote peers; block / unblock by row or by typed IP |
| **Ports** | Local listeners; one-click **Block port** |
| **Firewall** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, geo lookups, failed-logon monitoring, closed-port scan detection, the intrusion detectors (threat intel, new-listener, process reputation, ARP watch, startup-item watch, exfiltration, honeypot), webhook alerts, auto-block + minimum severity + expiry, block direction (in/out), allowlist feed, **change master password**, **Remove all rules** |

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
| **Settings** | Monitor poll interval, geo lookups, failed-logon monitoring, closed-port scan detection, allowlist feed, data folder |

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
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `Web/WebApp.cs` | Headless web console (HTTP server + embedded single-page UI) |
| `Web/WebAuthStore.cs` | Master password hash + session tokens |
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
