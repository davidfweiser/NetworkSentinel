# Network Sentinel

Native Windows desktop app that monitors open ports and live network sessions on the local machine, tracks remote computers, and flags break-in style activity with origin details.

## Features

- **Open ports** — TCP listeners and UDP endpoints via Windows `iphlpapi` (`GetExtendedTcpTable` / `GetExtendedUdpTable`)
- **Live connections** — process name, local/remote endpoints, state, and origin summary
- **Remote computers** — peers that have connected to (or from) this PC, with reverse DNS + optional geo/ISP lookup
- **Break-in heuristics**
  - Multi-port scans
  - RDP / SSH / SMB hammering patterns
  - Sensitive port probing
  - Short-lived / transitional TCP bursts
  - First-seen remote hosts
- **Modern UI** — dark cyber theme, animated nav/buttons, live sparkline, pulse indicator
- **Firewall & block**
  - Block / unblock remote IPs (inbound, outbound, or both) via Windows Defender Firewall
  - Block local TCP/UDP ports
  - Manage only rules created by this app (`NetworkSentinel-*` prefix)
  - **Auto-block** toggle (on/off) with minimum severity (Medium / High / Critical)
  - Setting is saved under `%LocalAppData%\NetworkSentinel\settings.json`
  - **Run as Admin** when elevation is required (firewall changes need Administrator)

## Requirements

- Windows 10/11
- [.NET 8 SDK](https://dotnet.microsoft.com/download) (or newer with `net8.0-windows` support)
- **Administrator** rights to add or remove firewall rules

## Run

```powershell
cd NetworkSentinel
dotnet run
```

Release build:

```powershell
dotnet publish -c Release -r win-x64 --self-contained false
```

## Notes

- This is an **awareness / monitoring** console, not a full intrusion-prevention system.
- Public IP geolocation uses the free `ip-api.com` endpoint (rate-limited, best-effort). Private LAN addresses are labeled as local/private.
- Process names for some system sockets may show as `System` or `PID n` depending on permissions.
- For the richest view of inbound attacks against your box, also enable Windows Firewall logging and review Security event 4625 (failed logons) in Event Viewer when hardening a host.

## Project layout

| Path | Role |
|------|------|
| `Native/IpHelper.cs` | P/Invoke into Windows IP Helper API |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | DNS + geo origin lookup |
| `ViewModels/MainViewModel.cs` | UI state / commands |
| `MainWindow.xaml` | Modern dashboard UI |
