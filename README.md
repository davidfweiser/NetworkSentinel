# Network Sentinel (Linux)

Native **Linux** desktop app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **host firewall blocking** — with a modern dark Avalonia UI.

> Awareness / monitoring tooling — not a full IDS/IPS replacement.

Linux port of the original Windows WPF Network Sentinel. Platform layers use `/proc/net`, `nftables`/`iptables` (elevated via **pkexec**), and XDG data paths. Version **0.2.0**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` |
| **Live connections** | Process name (via `/proc/*/fd` inode map), local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this PC, reverse DNS, geo/ISP when public |
| **Activity chart** | Live sparkline of connection samples |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance
- SSH and SMB hammering
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- First-seen remote hosts

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo).

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **nftables** table `inet networksentinel` when `nft` is available; otherwise **iptables** with `NetworkSentinel-*` comments
- Only manages rules owned by this app; other firewall rules are left alone
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Settings in `~/.local/share/NetworkSentinel/settings.json` (or `$XDG_DATA_HOME/NetworkSentinel`)
- **Authorize firewall** — elevates only `nft`/`iptables` via **pkexec** (password dialog). The GUI always runs as your user

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `~/.local/share/NetworkSentinel/allowlist.json` |
| **Remote feed** | Optional refresh from this repo’s `allowlist-default.json` on GitHub |

Domains are DNS-resolved to current IPs. Auto-block never touches allowlisted IPs. **Restore good sites** removes Network Sentinel blocks that hit allowlisted addresses.

---

## Requirements

- **Linux** (kernel `/proc` networking; tested on Pop!_OS / Ubuntu-class systems)
- [.NET 8 SDK or runtime](https://dotnet.microsoft.com/download)
- Desktop libraries for Avalonia (usual X11/Wayland desktop install)
- **policykit-1** (`pkexec`) recommended for firewall password prompts
- `nft` (nftables) or `iptables` for host firewall changes

---

## Quick start

```bash
git clone https://github.com/davidfweiser/NetworkSentinel.git
cd NetworkSentinel
dotnet run -c Release
```

If the .NET SDK was installed with the install script:

```bash
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_ROOT="$HOME/.dotnet"
dotnet run -c Release
```

### Release build

```bash
dotnet build -c Release
dotnet publish -c Release -r linux-x64 --self-contained false -o bin/publish
./bin/publish/NetworkSentinel
```

Self-contained (no system .NET runtime needed):

```bash
dotnet publish -c Release -r linux-x64 --self-contained true -o bin/publish-sc
./bin/publish-sc/NetworkSentinel
```

### Firewall / auto-block (important on Wayland)

**Do not** run the GUI with `sudo` on Wayland — root cannot open your display (`XOpenDisplay failed`).

```bash
# correct — app as your user
./NetworkSentinel
# or:  dotnet run -c Release

# wrong on Wayland:
# sudo ./NetworkSentinel
```

When you block an IP/port (or click **Authorize firewall**), only `nft`/`iptables` are elevated via **pkexec** and you get a password dialog. Monitoring works without elevation.

Optional desktop entry is provided as `networksentinel.desktop` (install under `~/.local/share/applications/` and adjust `Exec=` to your binary path).

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block, allowlist, managed rule list |

### Auto-block
1. Click **Authorize firewall** (or allow the first pkexec prompt when blocking).
2. Turn **Auto-block** **On**.
3. Choose **Minimum severity** (default **High**).
4. Public IPs that hit that severity get host firewall drop rules automatically.
5. Private/LAN addresses, “new host” info events, and allowlisted sites are **never** auto-blocked.

> Turning auto-block **off** does **not** remove rules already created. Use **Unblock**, **Restore good sites**, **Remove**, or **Remove All** on the Firewall tab.

---

## How it works (high level)

```text
┌─────────────────┐     poll ~1.2s      ┌──────────────────────┐
│  Linux /proc    │ ─────────────────► │ NetworkMonitorService │
│  net/* + fd map │                    └──────────┬───────────┘
└─────────────────┘                               │
                                                  ▼
                                       ┌──────────────────────┐
                                       │ IntrusionDetector    │
                                       │ (heuristics)         │
                                       └──────────┬───────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    ▼                             ▼                             ▼
           Geo / DNS lookup              Avalonia UI                   FirewallService
           (origin details)              (MVVM + charts)               pkexec → nft/iptables
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/LinuxNetTable.cs` | `/proc/net` parsing + socket inode → PID |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | nftables / iptables via pkexec; rule ledger |
| `Services/AppSettings.cs` / `AppPaths.cs` | XDG data dir + JSON settings |
| `Services/DialogService.cs` | Avalonia confirm/info dialogs |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |
| `Program.cs` | Entry point; refuses GUI-as-root on Wayland |

---

## Windows → Linux changes

| Windows | Linux |
|---------|--------|
| WPF (`net8.0-windows`) | Avalonia 11 (`net8.0`) |
| `iphlpapi` GetExtendedTcpTable | `/proc/net/tcp{,6}` + `/proc/*/fd` |
| Windows Firewall COM / netsh | `nft` table `inet networksentinel` or `iptables` |
| `%LocalAppData%\NetworkSentinel` | `~/.local/share/NetworkSentinel` |
| Run as Administrator (whole app) | GUI as user; elevate only firewall tools via pkexec |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Threat heuristics count **new inbound connections to ports this PC is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing.
- Public IP geolocation uses the free `ip-api.com` endpoint (rate-limited, best-effort, **plain HTTP**). Set `"GeoLookupEnabled": false` in settings to disable it; reverse DNS still runs.
- Set `"AllowlistUseRemoteFeed": false` to skip the GitHub allowlist feed and use only built-in/local lists.
- Non-root runs still monitor connections for processes you can see; other users’ sockets may show as `Kernel / unknown`.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- Override (rare): `NETWORKSENTINEL_ALLOW_ROOT_GUI=1` forces allowing a root GUI (only useful on some X11 setups with `xhost`).

---

## Troubleshooting

| Problem | What to do |
|---------|------------|
| `XOpenDisplay failed` after `sudo` | Run **without** sudo. Use **Authorize firewall** / pkexec for rules only. |
| No password dialog for block | Install `policykit-1` (`pkexec`). |
| `.NET location: Not found` | Set `DOTNET_ROOT` / `PATH` to your .NET install, or use a self-contained publish. |
| Process names missing | Expected for other users’ sockets without root; monitoring still works. |

---

## License

Private project — all rights reserved unless you add a license file later.
