# Network Sentinel (Linux)

Native **Linux** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **host firewall blocking**.

Three ways to run it:

| Mode | When to use |
|------|-------------|
| **Avalonia GUI** | Desktop with a display |
| **Terminal UI (`--tui`)** | SSH / keyboard-first |
| **Headless web UI (`-w`)** | Browser on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement.

Linux port of the original Windows WPF Network Sentinel. Platform layers use `/proc/net`, `nftables`/`iptables` (elevated via **pkexec**), and XDG data paths. Version **0.3.1**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` |
| **Live connections** | Process name (via `/proc/*/fd` inode map), local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this PC, reverse DNS, geo/ISP when public |
| **Activity chart** | Live sparkline of connection samples (GUI) |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance — fast (45 s window) **and slow/paced** (10 min window, catches `nmap -T1`-style scans)
- **Scans of closed ports** (opt-in) — a rate-limited firewall SYN-log rule makes probes visible that never appear as connections (the kernel answers closed-port SYNs with a RST before `/proc/net` ever sees them); a kernel-log watcher turns them into alerts within seconds
- SSH and SMB hammering
- **Failed logon bursts** from the system auth log (journald or `/var/log/auth.log`) — catches SSH/PAM brute-force even when it reuses one TCP session or paces below the connection-rate thresholds
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- **Outbound beaconing** — regular-interval new sessions to an uncommon remote port (C2 "calling home" signature); common client ports and LAN peers are excluded
- First-seen remote hosts

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo).

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **nftables** table `inet networksentinel` when `nft` is available; otherwise **iptables** with `NetworkSentinel-*` comments
- Only manages rules owned by this app; other firewall rules are left alone
- Block rules are created as an `-In`/`-Out` pair and **removed together** in one click
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Removing/unblocking a rule **suppresses auto-block for that IP for 24 h** (persisted), so removed rules stay gone across restarts
- The web console **refuses to block its own port** — that would cut off your browser mid-request and look like a crash
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

### Web console tabs

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers), monitoring/firewall status, recent threats |
| **Connections / Threats** | Live traffic with a **Block** button on every row |
| **Hosts** | Remote peers; block / unblock by row or by typed IP |
| **Ports** | Local listeners; one-click **Block port** |
| **Firewall** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, geo lookups, auto-block + minimum severity, block direction (in/out), allowlist feed, **change master password**, **Remove all rules** |

The page header shows the running version (e.g. `v0.3.1`) — check it after an upgrade to confirm the new build is live.

### Web UI security
- First browser visit **creates a master password** (min. 8 characters)
- Every later visit **requires that password**; change it under **Settings → Master password**
- Hash stored as PBKDF2-SHA256 (random salt, 200k iterations) in `~/.local/share/NetworkSentinel/web-master.json` — never plain text
- Session cookie until sign-out, browser close, or 12 hours idle

---

## Requirements

- **Linux** (kernel `/proc` networking; tested on Pop!_OS / Ubuntu-class systems)
- For **dev / `dotnet run`**: [.NET 8 SDK](https://dotnet.microsoft.com/download)
- For **server package**: nothing on the target — self-contained binary (no .NET install)
- Desktop libraries for Avalonia GUI (usual X11/Wayland desktop)
- **policykit-1** (`pkexec`) recommended for firewall password prompts
- `nft` (nftables) or `iptables` for host firewall changes
- **systemd** optional (used by `--web-service` installer)

---

## Server installer (recommended for production)

Build on a machine with the .NET SDK; install on the server **without** .NET:

```bash
./scripts/package.sh              # linux-x64 → dist/
./scripts/package.sh linux-arm64  # ARM / Raspberry Pi
```

| Artifact | Purpose |
|----------|---------|
| `dist/networksentinel-*-linux-x64.install.sh` | **One-file installer** (copy + run) |
| `dist/networksentinel-*-linux-x64.tar.gz` | Classic tarball |
| `dist/*.sha256` | Checksums |

### Installer flags vs app flags

| Flag | Used with | Meaning |
|------|-----------|---------|
| `--web-service` | **Installer only** (`*.install.sh` / `install.sh`) | Install app **and** enable systemd auto-start |
| `-w` / `--web` | **App** (`networksentinel`) | Run headless web UI in the foreground |
| `--tui` | **App** | Terminal UI |

`--web-service` is **not** a runtime flag for `networksentinel`. If install prints `Unknown option: --web-service`, your package is too old — rebuild with `./scripts/package.sh` and copy the new installer, or use [manual auto-start](#auto-start-on-boot-systemd) below.

### Install web UI + systemd (typical server)

```bash
# build machine
scp dist/networksentinel-0.3.1-linux-x64.install.sh user@server:

# server
chmod +x networksentinel-0.3.1-linux-x64.install.sh
sudo ./networksentinel-0.3.1-linux-x64.install.sh --web-service
```

Confirm the installer is current before using root:

```bash
./networksentinel-0.3.1-linux-x64.install.sh --help
# Should list: --web-service
```

What you get:

- App under `/usr/local`
- systemd unit `networksentinel-web.service` (starts on boot)
- Port **18765** (configurable)
- Process runs as **your user** (`SUDO_USER`), not as root — **do not** launch daily with `sudo`

```text
http://YOUR_SERVER_IP:18765/
```

First browser visit: create a **master password**. Every later visit: enter it.

```bash
systemctl status networksentinel-web
journalctl -u networksentinel-web -f
sudo systemctl restart networksentinel-web

# change port
sudoedit /etc/networksentinel/web.env   # WEB_PORT=…
sudo systemctl restart networksentinel-web
```

### Other install options

```bash
sudo ./….install.sh                         # app only (no systemd)
sudo ./….install.sh --web-service --port 18765
./….install.sh --user                       # ~/.local (no root)
./….install.sh --user --web-service         # user systemd unit

# classic tarball
tar xzf networksentinel-0.3.1-linux-x64.tar.gz
cd networksentinel-0.3.1-linux-x64
sudo ./install.sh --web-service
```

### Auto-start on boot (systemd)

**Preferred:** install with `--web-service` (new package). That enables the unit and **(re)starts** it — re-running the installer upgrades in place and restarts the service so the new binary actually runs (older installers used `enable --now`, which silently left an already-running old version in memory).

**If the app is already installed** (or the installer is too old and rejects `--web-service`), enable auto-start by hand:

```bash
# Config (port)
sudo mkdir -p /etc/networksentinel
echo 'WEB_PORT=18765' | sudo tee /etc/networksentinel/web.env

# Replace YOUR_USER with the account that should own data (~/.local/share/NetworkSentinel)
sudo tee /etc/systemd/system/networksentinel-web.service <<'EOF'
[Unit]
Description=Network Sentinel headless web console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USER
Group=YOUR_USER
EnvironmentFile=-/etc/networksentinel/web.env
WorkingDirectory=/usr/local/lib/networksentinel
ExecStart=/usr/local/bin/networksentinel -w ${WEB_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now networksentinel-web
systemctl status networksentinel-web
```

User install (no root for the service) after `./install.sh --user --web-service`:

```bash
systemctl --user enable --now networksentinel-web
# keep running after logout on a server:
sudo loginctl enable-linger "$USER"
```

### Daily commands (no sudo)

```bash
networksentinel --tui       # terminal UI over SSH
networksentinel -w          # web UI in foreground (auto free port)
networksentinel-web         # web UI on configured port (default 18765)
networksentinel --help
systemctl status networksentinel-web
```

`sudo` is only needed for **install**, **uninstall**, editing `/etc/…`, or restarting the **system** service — not for normal use of the app.

```bash
sudo networksentinel-uninstall
```

| Path | Role |
|------|------|
| `/usr/local/lib/networksentinel/` | App files (system install) |
| `/usr/local/bin/networksentinel` | Launcher |
| `/usr/local/bin/networksentinel-web` | Web UI helper |
| `/etc/systemd/system/networksentinel-web.service` | Auto-start unit |
| `/etc/networksentinel/web.env` | `WEB_PORT` for systemd |
| `~/.local/share/NetworkSentinel/` | Settings, allowlist, master-password hash |

Reset web master password:

```bash
rm ~/.local/share/NetworkSentinel/web-master.json
```

---

## Quick start (from source)

```bash
git clone https://github.com/davidfweiser/NetworkSentinel.git
cd NetworkSentinel
dotnet run -c Release
```

If the .NET SDK was installed with the official install script:

```bash
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_ROOT="$HOME/.dotnet"
dotnet run -c Release
```

### Terminal UI (TUI)

Same monitoring / firewall stack, in the terminal (SSH, headless, or keyboard-first):

```bash
dotnet run -c Release -- --tui
# or after publish / install:
./NetworkSentinel --tui
networksentinel --tui
# or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel
```

If there is **no** `DISPLAY` / `WAYLAND_DISPLAY` (typical SSH session), the app **auto-starts in TUI** mode. Force the GUI with `NETWORKSENTINEL_GUI=1`.

| Key | Action |
|-----|--------|
| `1`–`7` / `Tab` | Dashboard · Connections · Hosts · Threats · Ports · Firewall · **Allowlist** |
| `↑` `↓` / `j` `k` | Move selection |
| `/` or `f` | Filter |
| `p` | Pause / resume monitoring |
| `a` | Toggle auto-block |
| `m` | Cycle auto-block minimum severity |
| `b` / `x` | Block / unblock selected IP (or prompt) |
| `n` / `+` | **Add domain or IP to allowlist** (never block) |
| `d` | Remove selected allowlist Domain/IP (on Allowlist view) |
| `g` | Restore good sites (unblock allowlisted IPs) |
| `u` | Authorize firewall elevation (pkexec) |
| `c` | Clear threat alerts |
| `r` | Refresh firewall · on Allowlist: refresh DNS/feed |
| `h` / `F1` | Help |
| `q` | Quit |

### Headless web UI (`-w`)

```bash
dotnet run -c Release -- -w
./NetworkSentinel -w
./NetworkSentinel -w 18765          # explicit port
NETWORKSENTINEL_WEB=1 ./NetworkSentinel
```

The console prints the URL (e.g. `http://127.0.0.1:18765/`). Open it in a browser. Press **Ctrl+C** to stop.

Without an explicit port, the process prefers free high ports (**18765**, then nearby alternatives) that common services almost never use.

### Release build (developers)

```bash
dotnet build -c Release
dotnet publish -c Release -r linux-x64 --self-contained false -o bin/publish
./bin/publish/NetworkSentinel --tui
```

Self-contained (no system .NET runtime):

```bash
dotnet publish -c Release -r linux-x64 --self-contained true -o bin/publish-sc
./bin/publish-sc/NetworkSentinel -w
```

Prefer `./scripts/package.sh` when shipping to a server — it builds the installer and tarball.

---

## Firewall / auto-block (important on Wayland)

**Do not** run the GUI with `sudo` on Wayland — root cannot open your display (`XOpenDisplay failed`).

```bash
# correct — app as your user
./NetworkSentinel
# or:  dotnet run -c Release

# wrong on Wayland:
# sudo ./NetworkSentinel
```

When you block an IP/port (or click **Authorize firewall**), only `nft`/`iptables` are elevated via **pkexec** and you get a password dialog. Monitoring works without elevation.

---

## App icon

Assets live in `Assets/`:

| File | Use |
|------|-----|
| `Assets/icon.png` | 512×512 primary (window title bar + in-app) |
| `Assets/icon.ico` | Multi-size Windows-style / embed |
| `Assets/icons/icon-*.png` | 16–512px for Linux icon themes |

Install the FreeDesktop icon + launcher (adjust `Exec=` if needed):

```bash
for s in 16 24 32 48 64 128 256 512; do
  mkdir -p ~/.local/share/icons/hicolor/${s}x${s}/apps
  cp Assets/icons/icon-${s}.png ~/.local/share/icons/hicolor/${s}x${s}/apps/networksentinel.png
done
cp networksentinel.desktop ~/.local/share/applications/
# edit Exec= in the .desktop file to your published binary path
update-desktop-database ~/.local/share/applications 2>/dev/null || true
```

Optional desktop entry is provided as `networksentinel.desktop` (`Icon=networksentinel`). The server installer can install it under the chosen prefix.

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
| **Allowlist** | Domains/IPs that are never blocked |

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
          ┌───────────────────────────────────────┼───────────────────────────┐
          ▼                                       ▼                           ▼
   Geo / DNS lookup              Avalonia · TUI · Web UI           FirewallService
   (origin details)              (master password on web)          pkexec → nft/iptables
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/LinuxNetTable.cs` | `/proc/net` parsing + socket inode → PID |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/AuthLogMonitor.cs` | Failed-logon detection from journald / auth.log |
| `Services/ProbeLogMonitor.cs` | Closed-port scan detection from the kernel probe log |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | nftables / iptables via pkexec; rule ledger |
| `Services/AppSettings.cs` / `AppPaths.cs` | XDG data dir + JSON settings |
| `Services/DialogService.cs` | Avalonia confirm/info dialogs |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Tui/TuiApp.cs` | Spectre.Console terminal UI (`--tui`) |
| `Web/WebApp.cs` | Headless browser UI (`-w` / `--web`) |
| `Web/WebAuthStore.cs` | Master password hash + session tokens |
| `scripts/package.sh` | Build self-contained tarball + `.install.sh` |
| `scripts/install-from-package.sh` | Server/desktop installer (shipped as `install.sh`) |
| `scripts/systemd/` | `networksentinel-web` unit + `web.env` example |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |
| `Program.cs` | Entry point; GUI / TUI / web routing; refuses GUI-as-root on Wayland |

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
- Scan/brute-force heuristics count **new inbound connections to ports this PC is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing. The only outbound rule is the beacon detector, which requires a regular cadence to an uncommon port on a public IP.
- Public IP geolocation uses the free `ipwho.is` endpoint over **HTTPS**, falling back to `ip-api.com` (plain HTTP) only if that fails. Both are rate-limited and best-effort. Toggle lookups off in the web console's **Settings** tab, or set `"GeoLookupEnabled": false` in settings; reverse DNS still runs.
- Failed-logon detection reads journald (`journalctl -t sshd …`) or `/var/log/auth.log` without elevation. If neither is readable by your user (add yourself to the `adm` group, or `systemd-journal` for journald), the app keeps running and shows why under **Settings → Auth-log monitoring**; set `"AuthLogMonitorEnabled": false` to turn the feature off.
- **Closed-port scan detection** is off by default because it installs one firewall rule (rate-limited to 50 log lines/second — negligible overhead). Enable it under **Settings → Closed-port scan detection** (prompts for elevation once), or set `"ProbeLogEnabled": true` and click **Authorize firewall**. The rule is listed on the **Firewall** tab as `NetworkSentinel-ProbeLog` and is removed with the toggle. Reading the kernel log follows the same group rules as auth-log monitoring.
- The allowlist remote feed can likewise be toggled in **Settings** or via `"AllowlistUseRemoteFeed": false`.
- If the app ever exits unexpectedly, check `~/.local/share/NetworkSentinel/logs/crash.log` — unhandled errors are logged there with a stack trace.
- Non-root runs still monitor connections for processes you can see; other users’ sockets may show as `Kernel / unknown`.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- The web UI binds all interfaces when started with `-w`; protect it with the master password and host firewall if exposed.
- Override (rare): `NETWORKSENTINEL_ALLOW_ROOT_GUI=1` forces allowing a root GUI (only useful on some X11 setups with `xhost`).

---

## Status while minimized (top bar / tray)

While the GUI is running (including minimized):

| Where | What you see |
|-------|----------------|
| **Window title / dock / task list** | Live compact stats, e.g. `NS · 12 sess · 5 ports · 8 hosts · 3 evt` |
| **System tray / top-bar indicator** | App icon; hover for full summary; click menu for sessions, ports, remotes, threats, auto-block |
| **Tray actions** | Show window · Pause/Resume monitoring · Quit |

On GNOME / Pop!_OS the indicator appears in the top bar (StatusNotifier / AppIndicator). If the icon is missing, install an AppIndicator extension or `libayatana-appindicator` package for your DE.

---

## Troubleshooting

| Problem | What to do |
|---------|------------|
| `Unknown option: --web-service` | That flag is for the **installer**, and only in packages built after the web-service update. Rebuild with `./scripts/package.sh`, copy the new `*.install.sh`, and check `./….install.sh --help`. Or set up systemd [manually](#auto-start-on-boot-systemd). |
| `XOpenDisplay failed` after `sudo` | Run **without** sudo. Use **Authorize firewall** / pkexec for rules only. Or use `--tui` / `-w`. |
| Do I need `sudo` to launch? | **No.** Install with sudo if system-wide; run as your normal user. The web service also runs as your user. |
| No password dialog for block | Install `policykit-1` (`pkexec`). |
| `.NET location: Not found` | Use the **server installer** / self-contained package, or set `DOTNET_ROOT` / `PATH`. |
| Process names missing | Expected for other users’ sockets without root; monitoring still works. |
| No tray icon | DE must support StatusNotifier/AppIndicator; window title still updates when minimized. |
| Web UI asks for password every time | Expected after sign-out, browser close, or 12h idle. Reset: delete `web-master.json`. |
| `networksentinel-web` won’t start | `journalctl -u networksentinel-web -e`; check port in `/etc/networksentinel/web.env`; confirm binary exists at `/usr/local/bin/networksentinel`. |
| Port already in use | Change `WEB_PORT` or run `networksentinel -w` to auto-pick a free high port. |
| Service dies after logout (user unit) | `sudo loginctl enable-linger "$USER"` |

---

## License

Private project — all rights reserved unless you add a license file later.
