# Network Sentinel

Native Windows desktop app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking** — with a modern dark UI.

> **Private repository.** Awareness / monitoring tooling — not a full IDS/IPS replacement.

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

Domains are **DNS-resolved** to current IPs (cloud addresses change often). On startup, **Restore good sites** removes any Network Sentinel blocks that hit allowlisted IPs (recovery if GitHub/Grok were blocked earlier).

> **Note:** Turning auto-block **off** does **not** remove rules already created. Use **Unblock**, **Restore good sites**, **Remove**, or **Remove All** on the Firewall tab.

---

## Requirements

- **Windows 10 or 11**
- [.NET 8 SDK](https://dotnet.microsoft.com/download) (or a runtime that can build `net8.0-windows`)
- **Administrator** rights to create or delete Windows Defender Firewall rules

---

## Quick start

```powershell
git clone https://github.com/davidfweiser/NetworkSentinel.git
cd NetworkSentinel
dotnet run
```

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

For firewall / auto-block, start the app **as administrator** (or use **Run as Admin** in the UI).

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
- Public IP geolocation uses the free `ip-api.com` endpoint (rate-limited, best-effort). LAN/private addresses are labeled as local.
- Some system sockets may show as `System` or `PID n` depending on permissions.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- For host hardening, also review Windows Security event **4625** (failed logons) and enable Firewall logging when needed.

---

## License

Private project — all rights reserved unless you add a license file later.
