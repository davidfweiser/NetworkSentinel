# Network Sentinel (Windows)

Native **Windows** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking**.

Three ways to run it (same idea as the Linux build):

| Mode | When to use |
|------|-------------|
| **Desktop GUI** | Interactive workstation (default) |
| **Terminal UI (`--tui`)** | Server Core, RDP console, SSH-style workflows |
| **Headless web UI (`-w`)** | Browser dashboard on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement. Version **0.2.0**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via Windows IP Helper (`GetExtendedTcpTable` / `GetExtendedUdpTable`) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this PC, reverse DNS, geo/ISP when public |
| **Activity chart** | Live sparkline of connection samples |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance
- RDP, SSH, and SMB hammering
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- First-seen remote hosts

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo).

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Only manages rules named `NetworkSentinel-*` so other firewall rules are left alone
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Settings stored in `%LocalAppData%\NetworkSentinel\settings.json`
- **Run as Admin** when elevation is required

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `%LocalAppData%\NetworkSentinel\allowlist.json` |
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
```

Environment variables: `NETWORKSENTINEL_TUI=1`, `NETWORKSENTINEL_WEB=1`.

### Server web service (startup task)

Elevated PowerShell from the repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-service.ps1
# optional port:
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-service.ps1 -Port 18765
```

This publishes the app to `%ProgramData%\NetworkSentinel\`, opens the firewall port, reserves a URL ACL, and registers a **Scheduled Task** (`NetworkSentinel-Web`) that runs elevated at startup:

```text
NetworkSentinel.exe -w 18765
```

Then open `http://localhost:18765/` (or `http://<server-ip>:18765/`). **First browser visit creates a master password.**

Uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-web-service.ps1
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

Settings remain in `%LocalAppData%\NetworkSentinel\` until you delete that folder yourself.

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
- Later visits require that password
- Hash stored as PBKDF2-SHA256 in `%LocalAppData%\NetworkSentinel\web-master.json`
- Session cookie until sign-out, browser close, or 12 hours idle

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
           (origin details)              (MVVM + charts)               (COM / netsh)
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/IpHelper.cs` | P/Invoke into Windows IP Helper API |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | Windows Firewall rule create/list/remove |
| `Services/AppSettings.cs` | Auto-block preferences (JSON on disk) |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `MainWindow.xaml` | Dashboard UI |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Threat heuristics count **new inbound connections to ports this PC is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing.
- Public IP geolocation uses the free `ip-api.com` endpoint (rate-limited, best-effort, **plain HTTP** — remote IPs you talk to are visible on the wire). Set `"GeoLookupEnabled": false` in `%LocalAppData%\NetworkSentinel\settings.json` to disable it; reverse DNS still runs. LAN/private addresses are labeled as local.
- Set `"AllowlistUseRemoteFeed": false` in the same file to skip the GitHub allowlist feed and use only built-in/local lists.
- Some system sockets may show as `System` or `PID n` depending on permissions.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- For host hardening, also review Windows Security event **4625** (failed logons) and enable Firewall logging when needed.

---

## License

Private project — all rights reserved unless you add a license file later.
