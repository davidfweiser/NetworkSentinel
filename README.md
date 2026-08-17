# Network Sentinel (Linux)

Native **Linux** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **host firewall blocking**.

Three ways to run it:

| Mode | When to use |
|------|-------------|
| **Avalonia GUI** | Desktop with a display |
| **Terminal UI (`--tui`)** | SSH / keyboard-first |
| **Headless web UI (`-w`)** | Browser on a server (master-password protected) |

> **Host-based** intrusion detection and prevention. It detects on its own heuristics and, with Suricata attached (0.6.0), on signature/payload inspection — then enforces in the kernel via `nftables`. It is not an inline network appliance: it protects the machine it runs on, not a segment, and it does not sit in the forwarding path.

Linux port of the original Windows WPF Network Sentinel. Platform layers use `/proc/net`, `ss`, conntrack netlink, `nftables`/`iptables` (elevated via **pkexec**), and XDG data paths. Version **0.7.0**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` |
| **Live connections** | Process name (via `/proc/*/fd` inode map), local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this PC, reverse DNS, geo/ISP when public |
| **Activity chart** | Live sparkline of connection samples (GUI) |
| **Data-flow charts** (0.7.0) | Bytes in/out sampled from `/proc/net/dev`: live throughput, this month's totals, and paired bars per day or per month (GUI) |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance — fast (45 s window) **and slow/paced** (10 min window, catches `nmap -T1`-style scans)
- **Scans of closed ports** (opt-in) — a rate-limited firewall SYN-log rule makes probes visible that never appear as connections (the kernel answers closed-port SYNs with a RST before `/proc/net` ever sees them); a kernel-log watcher turns them into alerts within seconds
- SSH and SMB hammering
- **Failed logon bursts** from the system auth log (journald or `/var/log/auth.log`) — catches SSH/PAM brute-force even when it reuses one TCP session or paces below the connection-rate thresholds
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- **Outbound beaconing** — regular-interval new sessions to an uncommon remote port (C2 "calling home" signature); common client ports and LAN peers are excluded
- First-seen remote hosts — tracked **across restarts** (30-day persistent host history), so relaunching doesn't make every known peer look new again
- **UDP peers** — connected UDP sockets with a real remote address (from `/proc/net/udp{,6}`) count toward the scan/probe heuristics and the Remote Computers view; multicast/broadcast chatter (mDNS, SSDP) is excluded

### Intrusion detection (0.4.0)
| Detector | What it catches |
|----------|-----------------|
| **New-listener alerts** | A new port starts listening after the baseline (backdoor/implant signature), or a known port changes owner process (service replaced/impersonated). Baseline persists in `host-history.json`; loopback-only and ephemeral (49152+) listeners are skipped. Owner-change detection needs the socket→PID map, so it only works for sockets your user can see unless you run as root. |
| **Threat-intel blocklists** | Remote IPs checked against **FireHOL level1** and **Spamhaus DROP** (fetched daily over HTTPS, cached offline). A match is an instant **Critical** — those ranges are attack infrastructure. |
| **Process reputation** | Shells/interpreters (`bash`, `python`, `nc`, …) holding outbound connections to public hosts (reverse-shell signature, High); **fileless** processes running from `memfd` or a deleted binary staged in `/tmp` (High); binaries running from `/tmp`, `/dev/shm`, `~/Downloads` with network activity; **system** binaries that no installed package owns (`dpkg`/`rpm`/`pacman`/`apk`). Executable paths come from `/proc/PID/exe` — no per-poll shelling out, and package queries are cached per path off the poll loop. |
| **Honeypot decoy ports** (opt-in) | Binds decoy TCP ports (default `2323,3389,5900`). Nothing legitimate connects to a decoy, so any completed connection is a **zero-false-positive Critical**. Busy ports are skipped automatically. |
| **ARP / gateway watch** | The default gateway's MAC address changing (**Critical** — classic ARP-spoof MITM opener) or another LAN IP claiming the gateway's MAC (High). Reads `/proc/net/route` and `/proc/net/arp`; no elevation, no subprocess. |
| **Startup-item watch** | New or modified files under `/etc/systemd/system` (including `*.wants` symlinks), `~/.config/systemd/user`, `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron`, `/etc/init.d`, `/etc/xdg/autostart` and `~/.config/autostart` — the standard persistence step right after a successful intrusion. Root-only folders are skipped when running unprivileged. |
| **Exfiltration monitor** | `ss -tinp` per-socket byte counters; alerts when outbound traffic to a single non-allowlisted public host exceeds a threshold (default **250 MB / 10 min**). LAN destinations (NAS backups) and allowlisted hosts stay quiet. TCP only — UDP/QUIC carries no equivalent kernel counter. |

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo). Threat events and the host/listener baseline **persist across restarts** (`threat-log.jsonl`, `host-history.json`).

### Every warning says whether the address is blocked (0.6.5)

A warning that names an address and stops there sends you to the console to find out whether anything was actually done about it. So each batch of threats is run past the prevention engine **before** any alert about it leaves the machine, and the alert carries the verdict:

| Verdict | When |
| --- | --- |
| `BLOCKED — auto-block rule added` | A rule was just written for the address |
| `BLOCKED — a rule for this address is already in place` | It was already blocked |
| `NOT blocked — the firewall refused the rule: …` | A block was attempted and failed |
| `NOT blocked — dry run (it would have been blocked)` | Prevention is in dry-run mode |
| `NOT blocked — auto-block is off` / `no firewall privileges` / `you released this address manually` / `allowlisted` / `below the auto-block level (≥High)` / … | The gate that stopped it — see [Prevention engine](#prevention-engine-060) |

Desktop notifications lead with it in the title (`Blocked · critical threat: Port Scan`, or `3 critical threats — 2 of 3 blocked`), the web console's browser notifications say the same, webhooks carry it in the message body, and generic JSON payloads add `blocked`, `block_state` and `block_status` fields. Threats that name no blockable address (a startup-item change, a new local listener) say nothing about blocking rather than guessing.

The threat tables answer it too, so the screen you land on after a warning agrees with the warning: a **Blocked** column in the GUI (hover for the full reason) and the web console, and a `Blk` column in the TUI — red when the address is being dropped, amber for a block that failed or was only simulated, muted when it was deliberately left alone. A row whose address is already blocked offers **Unblock** in place of **Block**, as the Remote Computers views do; re-blocking would only rewrite a rule that is already in force.

Every status line that reports auto-block state — the GUI hero subtitle and tray tooltip, the TUI footer, the web console's header pill, and the message each shows when you flip the toggle — comes from the engine itself, so **DRY RUN** is never mistaken for armed.

### Remote alerting (webhook)
Set **Settings → Webhook URL** to push Critical threats off the machine — the payload adapts automatically: **ntfy** (plain text + `Title`/`Priority` headers), **Slack** (`{"text": …}`), **Discord** (`{"content": …}`), anything else gets a generic JSON document. Per-source/type cooldown stops a burst from flooding the channel.

### Prevention engine (0.6.0)

Every automatic block — from any detector, in any of the three frontends — goes through **one** enforcement engine (`PreventionService`). It used to be three near-identical copies of the same logic in the GUI, TUI and web console, and they had drifted: only the web console honoured the manual-unblock suppression list, so releasing an address in the GUI or TUI could be silently undone by the next detection. Detection sources keep multiplying; the decision to drop traffic must not.

Gates, in order — a threat must clear all of them before a rule is written:

| Gate | Why |
|------|-----|
| Severity ≥ minimum | The configured `Medium`/`High`/`Critical` threshold |
| Not `New Remote Host` | First contact is not evidence of anything |
| Routable public address | LAN, loopback, CGNAT (100.64/10 — Tailscale and many VPN tunnels) and multicast are never auto-blocked. CGNAT can still be blocked **manually**, behind a confirmation — a hostile tunnel peer is a real case, and only LAN/loopback/link-local/multicast are refused outright |
| Not allowlisted | Known-good stays reachable |
| Not this machine | A detector that attributes a threat to the wrong end of a flow can never firewall the host off from itself — matters most on a VPS whose own address is public |
| Not a WireGuard tunnel endpoint | A peer's public endpoint is where its tunnel packets come from; blocking it does not drop an attacker, it drops the tunnel and everything reached through it. Independent of the WireGuard *monitoring* setting, and remembered for 24 h — see [tunnel endpoints are never auto-blocked](#tunnel-endpoints-are-never-auto-blocked) |
| Not protected | See lockout protection below |
| Not already blocked | No duplicate rules |
| Not suppressed | An address you deliberately released stays released for 24 h |
| Not retried too soon | An address is claimed for 10 minutes once a batch acts on it. A block that fails for a reason other than elevation (a timed-out `nft`, xtables lock contention) retries after **45 s** instead — one transient error should not leave an active attacker alone for ten minutes. Elevation failures pause auto-block globally for 5 minutes, lifted as soon as you authorize elevation |

- **Dry run** (**Settings → Auto-block → Dry run**) runs every gate and reports what it *would* have dropped, without writing a single rule. Blocking turns a false positive from noise into an outage, so a new detection source — a fresh Suricata ruleset especially — belongs here first. The console shows `Would block …` lines exactly where it would otherwise show `Auto-blocked …`.
- **Lockout protection** — the address of whoever is signed into the web console is shielded from auto-block for a rolling 30 minutes. Prevention that firewalls the operator away from the box it protects has done more damage than the attack it stopped. Manual blocking is deliberately unaffected, and the shield lapses on its own once you stop working.
- Direction fallback is now consistent: with neither **Block inbound** nor **Block outbound** ticked, all three frontends block **both** (the GUI used to block inbound only).

### DNS hygiene (0.6.0)

Almost nothing connects without resolving a name first, so DNS is where a compromise usually shows earliest — and it is a standard exfiltration channel the exfiltration monitor cannot see, since that counts TCP socket bytes and DNS is UDP. Until now this app had no view of DNS at all.

| Detection | Level | Why |
|-----------|-------|-----|
| **Plaintext DNS egress** | Medium | Queries leaving on port 53 can be read *and rewritten* by anything on the path |
| **Encrypted DNS stopped** | High | Resolvers usually fall back to plaintext rather than fail, so a blocked port 853 or an expired certificate silently removes the protection you configured. Nobody notices this one |
| **Unapproved resolver** | High | Something changed the resolver configuration, or answers are being redirected |
| **VPN client bypassing your resolver** | Medium | A tunnel client querying externally in the clear defeats the thing the VPN was for |
| **Allowlisted domain moved networks** | High | See below — this one is about protecting Network Sentinel itself |

**Why the allowlist matters here.** `AllowlistService` resolves allowlisted domains over whatever DNS the host is using, and the prevention engine **never auto-blocks a resolved allowlist address**. Poison the host's DNS and an attacker's address is written into the allowlist under a trusted domain's name — permanently immune to blocking, by design. The drift detector compares every answer against the networks that domain has resolved into before (a /24 for IPv4, /48 for IPv6) and alerts only when the new answer shares *nothing* with that history, so ordinary CDN rotation stays quiet. The history persists, because a restart that silently re-seeded would adopt a poisoned answer as the new truth.

**What it can and cannot see.** Port 53 is plaintext and detected wherever it goes. Port 853 is DoT and recognised as encrypted. **DoH is HTTPS on 443 and is indistinguishable from ordinary web traffic** — it is only counted as encrypted DNS when the destination is a resolver you list under **Approved resolvers**. Without that list a DoH setup looks like no DNS at all rather than like a leak.

Flows come from the conntrack event source, so this covers traffic the socket tables never show — including DNS forwarded on behalf of VPN clients. That needs **root**; without it the status says so and no detection runs.

> **The arrangement to aim for.** Run a local resolver and encrypt only the *upstream* hop:
> `host + clients → local resolver → [DoT/DoH] → upstream`.
> Queries to a local address are never flagged, because that is the wanted design: you keep full visibility here while the network sees nothing. Pointing everything straight at an external DoH endpoint hides your queries from your ISP *and* from this program — and from Suricata's DNS rules.

Network Sentinel does not configure your resolver. Installing one and pointing it upstream over DoT is a fifteen-minute job you do once; getting it wrong costs name resolution for the host and every VPN client at the same time, possibly while you are remote and depending on that tunnel to fix it. Detection and enforcement are what this program is for.

### VPN peer monitoring — WireGuard (0.6.0)

WireGuard is invisible to everything else in this app. It uses a single **unconnected** UDP socket, so the socket table files it as a listener with no peer and **no VPN client ever becomes a tracked connection** — nothing reaches the intrusion heuristics, the Remote Computers list, threat intel, or the prevention engine. On a VPN server that is a hole straight through the middle of the monitoring.

This reads WireGuard's own state (`wg show all dump`) instead:

| Detection | Level | Why |
|-----------|-------|-----|
| **New peer** | High | A peer entry grants standing access to your network. If you didn't add it, someone with root edited the WireGuard config |
| **Endpoint moved** | Low | Roaming between wifi and cellular is ordinary WireGuard behaviour — the value is the geo lookup patched into the alert's origin. The same key appearing from another country is not roaming |
| **Peer removed** | Low | Expected after revoking access; unexpected means the config changed underneath you |
| **Per-peer transfer** | High | Optional (0 = off). Forwarded tunnel traffic has no local socket, so the exfiltration monitor cannot see it — this is the only place it is counted |

- The first run adopts the existing peer list silently; the baseline persists in `wireguard-peers.json`, so a restart doesn't re-alert on peers you already know.
- **Key material never leaves the parser.** `wg show ... dump` prints the interface *private* key and each peer's *preshared* key. Both are dropped at parse time — they are never stored, logged, shown in the console, written to the baseline file, or sent to a webhook. Only public keys are used.
- The peer table in **Settings → VPN (WireGuard)** is read-only by design. Revoking a peer is `wg set <iface> peer <key> remove` — a WireGuard configuration change, not something a monitoring console should do behind your back.
- Needs **root** (`CAP_NET_ADMIN`); `wg show` cannot read device state otherwise. Without it the setting explains why rather than failing quietly.
- Per-peer transfer alerting is **off by default**: a VPN user streaming video legitimately moves gigabytes, so any threshold low enough to catch a slow leak would fire constantly on normal use.

#### Tunnel endpoints are never auto-blocked

Tunnel addresses are private-range (RFC1918 or CGNAT 100.64/10), so auto-block will never act on a VPN client's tunnel IP — by design, since blocking a tunnel IP would be both ineffective and confusing.

A peer's **public endpoint** — the address its encrypted packets actually arrive from — is protected separately, and this protection does **not** depend on peer monitoring being switched on. It has to be unconditional, because the failure is silent and self-inflicted: dropping an endpoint does not stop an attacker, it severs the tunnel and every service behind it, while the console keeps answering happily on the LAN. On a gateway you administer *through* that tunnel, the block also takes away the way back in. (0.6.3 — until then the gate read the live peer list, so it was inert unless WireGuard monitoring was on, which is off by default.)

Endpoints are collected from three places, so there is no window where one is blockable:

| Source | Covers |
|--------|--------|
| `wg show all dump`, sampled every 60 s | Live peers, including a client that has just roamed to a new address |
| `Endpoint =` in `/etc/wireguard/*.conf` | The server a client dials — still named there when the interface is **down** |
| A persisted 24 h memory (`wireguard-endpoints.json`) | Restarts, a momentary `wg` failure, a peer that went quiet, and the case that matters most: a tunnel that has **already** dropped, where `wg` reports no endpoint at all and the one address that would restore it otherwise looks like any other stranger |

- **Hostnames in a config are deliberately not resolved.** `Endpoint = vpn.example.org:51820` contributes nothing, because anyone able to answer DNS could otherwise write their own address into a never-block list — the same reasoning as the allowlist drift detector above. The live dump reports the resolved address anyway.
- WireGuard interfaces are detected from sysfs (`DEVTYPE=wireguard`) — no root, no subprocess — so a host with no tunnel spends nothing. A host that *has* one but cannot read its peers says so in **Settings → VPN (WireGuard)** rather than staying quiet: an unprivileged run can still write rules through pkexec, so silence there would be the dangerous case.
- When a detector does flag a peer endpoint, the console now says so — `Not blocking 203.0.113.9 (Critical: …) — it is a VPN tunnel endpoint` — instead of leaving you to wonder why no rule appeared. Rate-limited per address.
- **Manual blocking is unaffected**, here as with the operator shield: a hostile tunnel peer is a real case. Cutting off a peer for good belongs in WireGuard's own configuration (`wg set <iface> peer <key> remove`).

#### The same shield for IPSec, including site-to-site (0.6.6)

The argument above is not WireGuard's; it is any tunnel's, and until 0.6.6 only WireGuard got it. **IPSec peers are now shielded from auto-block on the same terms**, which matters most for a **site-to-site** tunnel — the case where the peer cannot phone you to say it went down:

- the far end is another site's router at a **fixed public address**, indistinguishable from any stranger's to every heuristic here;
- its traffic is the exact shape the heuristics look for — one remote address holding long-lived flows to whatever the tunnel carries, re-keying on a timer, and **retrying hard whenever the link flaps**, which reads like a brute-force or scan pattern;
- so a single auto-block drops the tunnel for **both** sites at once, and nothing at this end looks wrong afterwards: the rule applied, the console still answers, and the other office simply loses the VPN.

Peers are collected the same belt-and-braces way, on the same 60 s cadence, and remembered for the same 24 h:

| Source | Covers |
|--------|--------|
| `ip xfrm state` | Live kernel SAs. This is the source that matters most because it is **implementation-independent** — strongSwan, libreswan and Openswan all install the same XFRM state |
| `swanctl --list-sas`, else `ipsec status` | The window where IKE is up but no child SA is installed yet — where a flapping tunnel spends most of its time, and where `ip xfrm state` shows nothing |
| `left=` / `right=` in `/etc/ipsec.conf` and `/etc/ipsec.d/*.conf`; `local_addrs` / `remote_addrs` in `/etc/swanctl/swanctl.conf` and `/etc/swanctl/conf.d/*.conf` | The peer named in configuration — still there with the tunnel **down**, which is the state a site is in after the very block this prevents |
| A persisted 24 h memory (`ipsec-endpoints.json`) | Restarts, re-keying windows, a momentary command failure, and a tunnel that has **already** dropped |

- **Traffic selectors are never read.** `leftsubnet`, `rightsubnet`, `local_ts` and `remote_ts` routinely hold `0.0.0.0/0`, and a shield that swallowed a default route would silently disable auto-block for the whole internet. Only `left`, `right`, `local_addrs` and `remote_addrs` are read, only when the value is a bare address — the match is on the whole key, so `rightsourceip` and friends cannot slip through.
- `%any` and hostnames contribute nothing, for the same reason as WireGuard's `Endpoint =`.
- Both ends of an SA are kept rather than guessing which is remote: `left` being the local end is a convention configs are routinely written against, and this host's own addresses are refused by an earlier gate anyway.
- Reading live SAs needs **root** (CAP_NET_ADMIN). A host that clearly runs IPSec but cannot read its peers says so in the console's VPN status rather than staying quiet — an unprivileged run can still write rules through pkexec, so silence would be the dangerous case.
- Detection is unchanged: this gate only stops the machine deciding on its own. **Manual blocking still works**, and a peer that really is hostile belongs in the IPSec configuration, not in a firewall rule that also takes the tunnel down.

### Signature detection — Suricata (0.6.0)

Connection heuristics see *who* is talking and *how often*; they can never see *what is being said*. That gap is closed by attaching **Suricata** rather than writing a detection engine: protocol decoders, stream reassembly and the target-based defragmentation that stops an attacker evading inspection are a multi-year project whose failure mode is a bypass nobody notices. Suricata already does all of it, already runs inline via NFQUEUE, and already has ET Open rules maintained full time.

So Network Sentinel is the **manager**, not the engine — Suricata decides what matched, this app decides what happens next:

| | |
|---|---|
| **Input** | Suricata's EVE JSON (`/var/log/suricata/eve.json` by default; set `eve-log` to enabled in `suricata.yaml`) |
| **Severity mapping** | Suricata counts down — sev 1 → **Critical**, 2 → **High**, 3 → **Medium**, 4 → **Low**. A sev-1 match therefore clears the default `High` auto-block threshold |
| **Threat source** | The *remote* end of the flow, not the packet source — for an outbound C2 callback the attacker is the destination, and blocking the source would firewall the host off from itself |
| **Noise control** | A maximum severity number, a per-signature mute list (`sids`), and a 2-minute per-signature-per-peer cooldown so one rule matching every packet can't bury every other alert |
| **IPS mode** | When Suricata dropped the packet itself, the alert detail says `already dropped by Suricata` |

Alerts arrive as ordinary `Signature Match` threat events, so the whole existing pipeline applies unchanged: the threat list, the persistent log, geo/origin enrichment, webhooks, the allowlist, and auto-block. Log rotation is handled — the tailer reopens rather than sitting on a deleted inode.

Suricata is **not bundled**; install and run it yourself, then switch on **Settings → Signatures (Suricata)**. Reading `eve.json` needs group access (`suricata`) or root.

### Kernel flow events (0.6.0)

Polling `/proc/net` can only ever describe the moment the file was read — on the default 1.2 s cycle an attacker gets a free window before anything is sampled. Network Sentinel now also subscribes to **conntrack `NEW` events** over `NETLINK_NETFILTER` and takes its snapshot *because something happened* rather than because a timer fired.

- Reaction to an inbound connection on a served port drops from up to a full poll interval to well under a second
- The heuristics are unchanged — they are snapshot-based by design, and a snapshot is still what they consume. Only the *timing* of the snapshot changes
- A 150 ms floor coalesces bursts, so a port scan of a thousand ports does not become a thousand snapshots
- Only flows aimed at a port this machine actually serves cut the interval short, so ordinary outbound client traffic doesn't make a busy machine poll flat out
- Subscribing needs **root** (`CAP_NET_ADMIN`). Without it the bind fails, the console explains why, and the timer cadence continues — no functionality is lost, only reaction time

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **nftables** table `inet networksentinel` when `nft` is available; otherwise **iptables** with `NetworkSentinel-*` comments
- Only manages rules owned by this app; other firewall rules are left alone
- The rule ledger is **reconciled with the kernel at startup**: nft/iptables rules don't survive a reboot while the ledger file does, so entries with no live kernel rule are dropped instead of masquerading as active blocks (runs only when elevation is silent — root or passwordless/cached sudo — never a startup password prompt)
- Block rules are created as an `-In`/`-Out` pair and **removed together** in one click (config rules are never paired, so their names are exempt from that)
- Your own rules, written on the **Firewall Config** page (0.7.0) — see below
- **App-minted blocks always win** (0.7.0): auto-block and manual blocks are *inserted at the head* of their chain while config rules are *appended*, so a config `Allow` can never reopen an address auto-block just shut
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Removing/unblocking a rule **suppresses auto-block for that IP for 24 h** (persisted), so removed rules stay gone across restarts
- **Auto-block expiry** (1 h … 7 days, off by default) — an expired address stops counting as blocked immediately; the `nft`/`iptables` rule itself is dropped by a background sweep as soon as it can elevate without a prompt (running as root, or cached/passwordless sudo). Manual blocks are always permanent
- The web console **refuses to block its own port** — that would cut off your browser mid-request and look like a crash
- Settings in `~/.local/share/NetworkSentinel/settings.json` (or `$XDG_DATA_HOME/NetworkSentinel`)
- **Authorize firewall** — elevates only `nft`/`iptables` via **pkexec** (password dialog). The GUI always runs as your user

### Data flow — how much, not just who (0.7.0)

The dashboard has always answered *who is talking to this machine*. It now also answers *how much went in and out*.

`TrafficMeterService` reads the kernel's cumulative per-interface byte counters from `/proc/net/dev` every 5 s and diffs them — no packet capture, no root, no subprocess. Three cards on the dashboard: live in/out throughput on one shared zero-based scale (two independent scales would make a trickle of uploads look like a saturated download), this month's totals, and paired bars per day of the month or per month of the year.

Three details decide whether the numbers are right, and each has a test:

- **Physical links only.** `en*`, `eth*`, `wl*`, `ww*`. A tunnel (`wg0`, `tun0`, `ipsec0`), a VLAN sub-interface (`eth0.100`), a bridge, a bond master and a container `veth` all carry bytes that already crossed a physical link — counting both would double every tunnelled byte. `lo` never leaves the machine. Bond *slaves* are metered and the master is not, which gives the total exactly once.
- **The name/counter boundary.** The kernel pads the interface name to six characters, so a long name with a wide counter leaves no space after the colon (`enp0s31f6:7590338536`). Splitting the row on whitespace alone would shift every column.
- **Counters reset.** A reboot or an interface bounce restarts them at zero; a counter that moved backwards is treated as a fresh start and its current value is the delta.

Daily totals and the last raw counters persist to `traffic-history.json`, so the diff continues across a restart — but that first catch-up delta spans however long the app was shut, so it counts toward the day and is deliberately **not** charted as a rate.

Turn it off with `TrafficMeterEnabled` (Settings → Traffic metering); the history is kept but stops growing.

The charts are on the **GUI dashboard**. The meter itself runs wherever the app runs, so a headless server still records the daily history into `traffic-history.json` — the web console and TUI just have no chart for it yet.

> **Difference from the macOS build:** that one meters `ppp*` too. Here it does not — a PPPoE link is carried by an Ethernet interface that is already metered, so counting both would double every byte on a DSL connection.

### Firewall Config — write your own rules (0.7.0)

A **Firewall Config** page under *Firewall & Block* that adds, edits and deletes inbound and outbound rules, shaped like the Linode Cloud Manager firewall page (and [FireWallConfig](https://github.com/davidfweiser/FireWallConfig) on Ubuntu): one list per direction, Label / Action / Protocol / Port range / Sources, one form for both add and edit, and labels minted from the port's service (`block-inbound-ssh`) when you leave the field blank.

Rules land in the same `inet networksentinel` table (or the same `NetworkSentinel-*` iptables comments) and the same ledger as the app's own blocks.

The **editor is GUI-only** for now. The rules it writes are ordinary kernel rules and ordinary ledger entries, so they apply system-wide and show up in the TUI's and web console's existing Firewall rule lists, where they read as kind **Config rule** — those two just cannot add or edit them yet.

**Precedence is fixed rather than incidental.** The chains are first-match-wins and rules are added one at a time, so ledger order decides nothing — a config *Allow* written today would otherwise sit ahead of a block auto-block appends tomorrow, and the accept would win. So app-minted blocks are **inserted at the head** of their chain (`nft insert`, `iptables -I … 1`) while config rules are **appended**. Every auto-block and manual block therefore precedes every config rule, whichever was created first.

One consequence, accepted deliberately: the probe-log rule is appended too, so a SYN from an address that is already blocked is now dropped before it reaches the log. Probe logging exists to catch scans from hosts that are *not* blocked yet.

Other details:

- The page states plainly that the managed chains **accept** anything no rule matches, so an Allow rule opens a path through the rules above it rather than granting access on its own.
- Blocking everything, or blocking inbound SSH, is **confirmed before it loads**.
- A rule the kernel rejects is rolled back out of the ledger instead of being left there claiming to be in force.
- One rule can need more than one kernel rule: a mixed IPv4/IPv6 address list splits by family (v6 goes to `ip6tables` when nft is unavailable), and a port range under protocol *Any* splits into TCP and UDP, because a port match without a protocol is not expressible in iptables.

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
| **Settings** | Monitoring on/off, poll interval, geo lookups, auth-log and closed-port scan detection, the 0.4.0 detectors (threat intel, new-listener alerts, process reputation, ARP/gateway watch, startup-item watch, exfiltration threshold, honeypot ports), **kernel flow events**, **DNS hygiene** (with approved resolvers), **WireGuard peer monitoring** (with a live peer table), **Suricata signature ingestion** (EVE path, maximum severity, muted sids), **auto-block dry run**, **HTTPS + DuckDNS remote access** (including **Issue certificate**), webhook URL, auto-block + minimum severity + expiry, block direction (in/out), allowlist feed, **change master password**, **Remove all rules** |

The page header shows the running version (e.g. `v0.7.0`) — check it after an upgrade to confirm the new build is live.

### Sleep / Wake

The first button in the web console header is a single **Sleep ⇄ Wake** toggle:

- **Sleep** stops *everything the console watches* — the connection/port poll plus the auth-log, closed-port probe, ARP, startup-item, exfiltration and honeypot watchers — and parks the page: the live tabs dim, a banner explains the state, and the browser drops its 2.5-second refresh so a sleeping console costs nothing on either end
- **Wake** starts monitoring again from live data and restores the normal refresh
- **Firewall blocks stay in force while asleep.** Sleeping stops watching; it never unblocks an address the machine is already protected from
- The state is the server's, not the browser's: reload or open a second tab and you still see *Asleep*, and the **Settings → Live monitoring** switch is the same control. While asleep the page keeps a 30-second heartbeat so a wake from anywhere shows up here
- Sleep is a runtime state — it is not written to `settings.json`, so restarting the service comes back up monitoring
- Sleep applies to the process you pressed it in; a desktop or TUI instance is a separate process and keeps running (the TUI has its own `p` key for the same thing)

### Web UI security
- First browser visit **creates a master password** (min. 8 characters)
- Creating it from **another machine** additionally asks for a one-time **setup code**, printed where the console runs (the terminal, or `journalctl -u networksentinel-web`). Without this, whoever reached the port first — the console binds all interfaces before any password exists — could claim the master password and with it firewall control. Setup from localhost needs no code
- Every later visit **requires that password**; change it under **Settings → Master password**
- Can't reach a browser yet (e.g. still opening the port in a cloud firewall)? Set/reset it from the terminal instead: `sudo networksentinel --set-master-password`
- Hash stored as PBKDF2-SHA256 (random salt, 200k iterations) in `~/.local/share/NetworkSentinel/web-master.json` — never plain text
- Session cookie until sign-out, browser close, or 12 hours idle
- Failed attempts are throttled **per client IP**: five wrong guesses trigger a lockout that doubles with each further attempt (1 minute up to 1 hour), answered with `429` and a `Retry-After`. A fixed delay alone only slows one connection at a time — this caps a parallel guesser

### HTTPS and remote access (0.5.0)

The console is served by **Kestrel**, so it terminates TLS itself (`HttpListener` cannot). HTTP and HTTPS are served side by side: the LAN keeps working on plain HTTP while requests that arrive **by hostname** are redirected to TLS — requests to a bare IP are left alone, since the certificate only covers the name and redirecting an IP would trade a working page for a certificate warning.

```bash
networksentinel -w --https \
    --tls-cert ~/.local/share/NetworkSentinel/tls/myhost.duckdns.org.fullchain.cer \
    --tls-key  ~/.local/share/NetworkSentinel/tls/myhost.duckdns.org.key
```

| Flag | Meaning |
|------|---------|
| `--https` | Serve TLS in addition to HTTP |
| `--https-port PORT` | TLS port (default **18443**; below 1024 needs root or `CAP_NET_BIND_SERVICE`) |
| `--tls-cert PATH` | PEM fullchain, or a `.pfx` / `.p12` bundle |
| `--tls-key PATH` | PEM private key (omit for `.pfx`) |
| `--tls-password PW` | Password for a `.pfx` / `.p12` |
| `--no-https` | Force plain HTTP for this run |

Flags win over `settings.json` for that run **without overwriting it**, so `--https` is safe to try. The same values live under **Settings → Remote access** in *both* front-ends — the desktop app and the web console — so you never have to hand-edit a config file; endpoint changes take effect at the console's next restart. Certificate files are re-read when they change on disk (checked every 5 minutes), so an **ACME renewal applies without restarting** the console. Session cookies gain the `Secure` flag automatically when the request arrives over TLS.

Under systemd, HTTPS and DuckDNS are **not** set in `web.env` — they persist in `settings.json`, so the service picks up whatever the GUI, TUI, or console saved. Only `WEB_PORT` lives in the env file.

#### Free trusted certificate for a duckdns.org name

[DuckDNS](https://www.duckdns.org) gives a free hostname that follows your public IP. The certificate comes from Let's Encrypt via a **DNS-01** challenge — proving control by writing a TXT record through the DuckDNS API, so **nothing has to be reachable on port 80**.

Easiest route is either front-end: fill in the subdomain and token under **Settings → Remote access** (desktop app or web console), then press **Issue certificate**. It runs the same script below and fills the two path fields in for you. From a terminal:

```bash
networksentinel --set-duckdns                 # subdomain + token (token is prompted, not a flag)
./scripts/issue-duckdns-cert.sh               # installs acme.sh if needed, issues + installs the cert
```

Entering the subdomain and token only sets up **dynamic DNS** — it keeps the name pointed at your current IP. Issuing the certificate is a separate step, whether you press the button or run the script.

The script is non-interactive when it has everything it needs, which is how the button drives it:

```bash
NS_ASSUME_YES=1 NS_ACME_EMAIL=you@example.com ./scripts/issue-duckdns-cert.sh myhost
```

`NS_ACME_EMAIL` is only used the first time, to register the Let's Encrypt account when `acme.sh` is installed. Without a terminal the script never prompts — anything missing is a clear error instead of a hang.

Run both as your normal user — **not** under `sudo`. They write into *your* `~/.local/share/NetworkSentinel` (or `$XDG_DATA_HOME`), which is where the GUI and the console read from; under `sudo` the files would land in root's home instead and be invisible to the app.

The token is stored in `~/.local/share/NetworkSentinel/duckdns.json` with mode `0600`, is **never sent to the browser** (the settings page shows only whether one is saved), and is prompted for rather than passed as a flag so it stays out of shell history and the process list. While the console runs it refreshes the A record every 5 minutes. `acme.sh` installs its own renewal cron entry.

> **Before you forward a port.** This console can add and remove firewall rules on this machine, and anyone who guesses the master password gets that control. A VPN or [Tailscale](https://tailscale.com) is the safer way to reach it from outside — `tailscale serve` even supplies a valid certificate with no port-forwarding at all. If you do forward a port, forward **only** the HTTPS one and use a long unique password.

---

## Requirements

- **Linux** (kernel `/proc` networking; tested on Pop!_OS / Ubuntu-class systems)
- For **dev / `dotnet run`**: [.NET 8 SDK](https://dotnet.microsoft.com/download)
- For **server package**: nothing on the target — self-contained binary (no .NET install)
- Desktop libraries for Avalonia GUI (usual X11/Wayland desktop)
- **policykit-1** (`pkexec`) recommended for firewall password prompts
- `nft` (nftables) or `iptables` for host firewall changes
- `ss` (iproute2) for the exfiltration monitor — present on essentially every distro; without it that one feature reports itself unavailable
- Read access to the system auth log (`adm` / `systemd-journal` group) for failed-logon and closed-port scan detection — optional, the app runs without it
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
| `--desktop-shortcut` | **Installer only** | Also drop an icon on the Desktop (opt-in; desktops only) |
| `--no-desktop` | **Installer only** | Skip the application-menu entry entirely |
| `-w` / `--web` | **App** (`networksentinel`) | Run headless web UI in the foreground |
| `--tui` | **App** | Terminal UI |
| `--https` (+ `--tls-cert` / `--tls-key`) | **App**, with `-w` | Serve the console over TLS — see [HTTPS and remote access](#https-and-remote-access-050) |
| `--set-duckdns` | **App** | Configure the DuckDNS hostname (run as your normal user, **not** `sudo`) |

`--web-service` is **not** a runtime flag for `networksentinel`. If install prints `Unknown option: --web-service`, your package is too old — rebuild with `./scripts/package.sh` and copy the new installer, or use [manual auto-start](#auto-start-on-boot-systemd) below.

### Install web UI + systemd (typical server)

```bash
# build machine
scp dist/networksentinel-0.5.0-linux-x64.install.sh user@server:

# server
chmod +x networksentinel-0.5.0-linux-x64.install.sh
sudo ./networksentinel-0.5.0-linux-x64.install.sh --web-service
```

Confirm the installer is current before using root:

```bash
./networksentinel-0.5.0-linux-x64.install.sh --help
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
./….install.sh --user --desktop-shortcut    # ~/.local + icon on the Desktop

# classic tarball
tar xzf networksentinel-0.5.0-linux-x64.tar.gz
cd networksentinel-0.5.0-linux-x64
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

`sudo` is only needed for **install**, **uninstall**, editing `/etc/…`, restarting the **system** service, or `--set-master-password` — not for normal use of the app.

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
| `~/.local/share/NetworkSentinel/` | Settings, allowlist, master-password hash, firewall ledger, `host-history.json` (known peers + listener baseline), `threat-log.jsonl`, `threat-intel-cache.json`, `wireguard-peers.json` + `wireguard-endpoints.json` (peer baseline and the never-block tunnel endpoints — public keys and addresses only), `duckdns.json` (`0600`), `tls/` (certificate + key) |

Set or reset the web master password (requires root — resolves the real service user via `SUDO_USER`, not root's own home):

```bash
sudo networksentinel --set-master-password
sudo systemctl restart networksentinel-web   # so the running service picks it up
```

Or delete it outright and let the next browser visit create a fresh one:

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
| `s` | Toggle auto-block **dry run** (report what would be blocked, write nothing) |
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

### Firewall elevation on a headless server (no pkexec)

`pkexec` needs a graphical polkit session (D-Bus + auth agent), which doesn't exist for a `systemd`-run web service with no display. On a headless box, block/unblock and **Authorize firewall** will fail with *"Elevation failed... Need admin rights for firewall changes"* until you grant the service user **passwordless sudo scoped to just `nft`/`iptables`**:

```bash
# 1. Confirm which user the service runs as
systemctl show networksentinel-web -p User

# 2. Find the exact binary paths (varies by distro)
which nft iptables ip6tables

# 3. Add a scoped sudoers rule (replace YOUR_USER and the paths below)
sudo visudo -f /etc/sudoers.d/networksentinel
```
```
YOUR_USER ALL=(root) NOPASSWD: /usr/sbin/nft, /usr/sbin/iptables, /usr/sbin/ip6tables
```
```bash
sudo visudo -c                              # verify syntax
sudo systemctl restart networksentinel-web  # retry block/unblock afterwards
```

This keeps the service itself running as your unprivileged user for everything else, and only elevates the two firewall binaries — the headless equivalent of the pkexec prompt the desktop GUI uses.

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

### Desktop shortcut

The installer writes an application-menu entry by default. Add `--desktop-shortcut` to also drop an icon on the Desktop:

```bash
./install.sh --user --desktop-shortcut
```

It is opt-in because a server has no Desktop directory and no use for an icon; `--no-desktop` skips the menu entry as well. The shortcut is a copy of the menu entry, so its `Exec=` already points at the installed launcher (`<bindir>/networksentinel`) rather than a build directory — a hand-written `.desktop` pointing into a source tree keeps launching whatever is left in `bin/` after an upgrade.

Two things the installer handles that a plain `cp` does not:

- GNOME and COSMIC ignore a desktop file that is not **both** executable and marked trusted — it shows as an inert text file. The installer sets `chmod +x` and `gio set … metadata::trusted true`.
- Under `sudo` the icon goes to `SUDO_USER`'s Desktop, not root's. `xdg-user-dir DESKTOP` is consulted first, so a localised or relocated Desktop still works.

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block, managed rule list, and the **allowlist** panel (domains/IPs that are never blocked) |
| **Settings** | Monitoring · Intrusion detection · Alerting & auto-block · Allowlist · Data — every toggle described below |

The GUI **Settings** view groups the same options the web console exposes:

| Group | Options |
|-------|---------|
| **Monitoring** | Live monitoring on/off, poll interval, geo lookups, auth-log monitoring, closed-port scan detection, Critical desktop notifications |
| **Intrusion detection** | Threat-intel blocklists, new-listener alerts, process reputation, ARP/gateway watch, startup-item watch, exfiltration threshold (MB / 10 min), honeypot decoy ports |
| **Remote access (web console)** | DuckDNS subdomain + token, HTTPS on/off and TLS port, certificate and key paths, HTTP→HTTPS redirect, **Update now** |
| **Alerting & auto-block** | Webhook URL, auto-block expiry |
| **Allowlist** | Remote allowlist feed |
| **Data** | Where settings, allowlist, and the master-password hash live |

Each toggle shows a live status line underneath (e.g. why auth-log monitoring is unavailable, or which honeypot ports actually bound), so a feature that can't run says so instead of failing silently.

#### Remote access from the desktop Settings (0.5.0)

**Settings → Remote access (web console)** configures HTTPS and DuckDNS without touching a config file or the command line:

| Field | What goes in it |
|-------|-----------------|
| **DuckDNS subdomain** | Just the label — `myhost`, not `myhost.duckdns.org`. The switch arms the 5-minute refresh. |
| **DuckDNS token** | Your token from duckdns.org, masked as you type. **Update now** tests it immediately and reports the result. |
| **Serve the console over HTTPS** | On/off, with the TLS port beside it |
| **Issue certificate** | Gets a free Let's Encrypt certificate for the DuckDNS name above and **fills in the two paths below**. The email box beside it is only used the first time, to register the account when `acme.sh` is installed. |
| **Certificate** / **Private key** | Filled in by **Issue certificate**; still editable if your certificate lives elsewhere. Validated as you enter them |
| **Redirect HTTP to HTTPS** | On by default |

**Issue certificate** shells out to `issue-duckdns-cert.sh` — the installer puts a copy beside the binary so it works without a source tree. It runs the script non-interactively, so it needs the subdomain and token saved first; issuance waits on DNS propagation and takes a few minutes, during which the button reads *Issuing…*. Failures name the likely cause where acme.sh's wording identifies one — a rejected DuckDNS token, slow propagation, a Let's Encrypt rate limit — quote the last few acme.sh lines, and point at the full transcript in `~/.local/share/NetworkSentinel/logs/cert-issue.log`.

> **A wrong DuckDNS token looks like a certificate problem.** Issuance proves control by writing a TXT record through the DuckDNS API, so a bad token fails at the DNS step, not the TLS one. If issuance fails, check that **Update now** reports OK before looking anywhere else.

Pressing the button again when the certificate is still valid is safe: acme.sh skips a renewal that is not due (it reports *Domains not changed / Skipping*), and the existing certificate is installed and the paths filled in as usual. To re-issue early — rarely needed, and rate-limited by Let's Encrypt — run the script with `NS_FORCE_RENEW=1`.

The same button is in the **web console's** Settings tab. There it runs in the background and the page polls for the result, because holding an HTTP request open for the length of an ACME run would time out the browser. It needs an authenticated session like every other action, and only one run happens at a time — concurrent ACME runs for the same name fight over the same TXT record. Be aware of what the button is: an authenticated browser session can start a shell script that, on first use, downloads and runs the acme.sh installer and registers a Let's Encrypt account. That is a real capability to expose remotely — the master password is the only thing in front of it, so make it a long unique one, and prefer a VPN or Tailscale over a forwarded port.

A status line at the top of the card shows certificate expiry, the live DuckDNS result, and the full console URL once both halves are configured. Certificate and port changes apply the next time the **web console** starts — the desktop app doesn't serve anything itself — but the **DuckDNS refresh runs in the desktop app too**, so the hostname stays current whenever either front-end is open.

The token is written to `duckdns.json` (mode `0600`), not `settings.json`; the GUI, TUI, and web console all read the same file.

### Settings keys

All three UIs write the same `~/.local/share/NetworkSentinel/settings.json`, so anything you can toggle in the GUI can also be set on a headless box by editing the file (restart the app or service afterwards):

| Key | Default | Meaning |
|-----|---------|---------|
| `MonitorPollMs` | `1200` | Poll interval, ms — also the activity chart's sample rate |
| `GeoLookupEnabled` | `true` | Country/city lookups for public IPs (reverse DNS runs either way) |
| `AuthLogMonitorEnabled` | `true` | Failed-logon bursts from journald / `auth.log` |
| `ProbeLogEnabled` | `false` | Closed-port scan detection (installs one firewall SYN-log rule) |
| `CriticalAlertsEnabled` | `true` | Desktop notification on Critical (GUI) |
| `ThreatIntelEnabled` | `true` | FireHOL level1 + Spamhaus DROP matching |
| `NewListenerAlertsEnabled` | `true` | New / re-owned listening ports vs. the baseline |
| `ProcessReputationEnabled` | `true` | Reverse-shell, fileless, throwaway-path, unpackaged-binary checks |
| `ArpWatchEnabled` | `true` | Gateway MAC change / duplicate MAC |
| `PersistenceWatchEnabled` | `true` | systemd / cron / autostart folder watch |
| `ExfilMonitorEnabled` | `true` | Per-socket outbound byte monitoring via `ss` |
| `ExfilMbPer10Min` | `250` | Exfiltration alert threshold, MB per 10 minutes |
| `TrafficMeterEnabled` | `true` | Sample `/proc/net/dev` for the dashboard's data-flow charts and the monthly history |
| `HoneypotEnabled` | `false` | Bind decoy TCP ports |
| `HoneypotPorts` | `"2323,3389,5900"` | Which ports to decoy (busy ones are skipped) |
| `WebHttpsEnabled` | `false` | Serve the console over TLS as well as HTTP (needs `WebTlsCertPath`) |
| `WebHttpsPort` | `18443` | TLS port; below 1024 needs root or `CAP_NET_BIND_SERVICE` |
| `WebTlsCertPath` | `""` | PEM fullchain, or a `.pfx` / `.p12` bundle |
| `WebTlsKeyPath` | `""` | PEM private key (leave empty for `.pfx`) |
| `WebTlsPfxPassword` | `""` | Password for a `.pfx` / `.p12` |
| `WebHttpsRedirect` | `true` | Redirect hostname requests to HTTPS (bare-IP requests stay on HTTP) |
| `AcmeAccountEmail` | `""` | Address the Let's Encrypt account is registered against; first issuance only |
| `WebhookUrl` | `""` | Push alerts to ntfy / Slack / Discord / generic JSON; empty disables |
| `WebhookMinLevel` | `"Critical"` | Minimum severity that fires the webhook |
| `AutoBlockEnabled` | `false` | Create firewall rules automatically |
| `AutoBlockMinLevel` | `"High"` | Minimum severity for auto-block |
| `AutoBlockInbound` / `AutoBlockOutbound` | `true` / `true` | Direction of auto-created rules |
| `AutoBlockExpiryMinutes` | `0` (off) | Auto-block lifetime; manual blocks are always permanent |
| `AllowlistUseRemoteFeed` | `true` | Refresh the known-good list from the online feed |

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
| `Services/ProcessReputationService.cs` | Shell / fileless / throwaway-path / unpackaged binary checks |
| `Services/ThreatIntelService.cs` | FireHOL + Spamhaus feed download, cache, CIDR matching |
| `Services/HoneypotService.cs` | Decoy TCP listeners |
| `Services/ArpWatchService.cs` | Gateway MAC watch from `/proc/net/route` + `/proc/net/arp` |
| `Services/PersistenceWatcher.cs` | systemd / cron / autostart folder watch |
| `Services/ExfiltrationMonitor.cs` | `ss` per-socket byte sampling |
| `Services/HostHistoryStore.cs` | Persistent host + listener baseline, threat log |
| `Services/WebhookNotifier.cs` | ntfy / Slack / Discord / generic JSON alerts, each carrying the block verdict |
| `Services/DesktopNotifier.cs` | Critical desktop popups (notify-send / gdbus), blocked-or-not in the title |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | nftables / iptables via pkexec; rule ledger; auto-block expiry sweep |
| `Services/FirewallRuleSpec.cs` | Firewall Config rule parsing, validation and nft/iptables rendering (no privilege, no I/O) |
| `Services/TrafficMeterService.cs` | `/proc/net/dev` byte-counter sampling + daily history behind the data-flow charts |
| `Services/AppSettings.cs` / `AppPaths.cs` | XDG data dir + JSON settings |
| `Services/DialogService.cs` | Avalonia confirm/info dialogs |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring, Settings view (incl. Remote access) |
| `ViewModels/MainViewModel.FirewallConfig.cs` / `.Traffic.cs` | Firewall Config page; data-flow chart series and legends |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Tui/TuiApp.cs` | Spectre.Console terminal UI (`--tui`) |
| `Web/WebApp.cs` | Headless browser UI (`-w` / `--web`, Kestrel) |
| `Services/TlsCertificateProvider.cs` | Loads the console's PEM/PFX certificate; hot-reloads on renewal |
| `Services/DuckDnsUpdater.cs` | DuckDNS dynamic-DNS refresh; token stored `0600` |
| `Services/CertIssuanceService.cs` | Runs the issuance script for the Settings **Issue certificate** button |
| `Services/LoginThrottle.cs` | Per-IP lockout for the console's password endpoints |
| `Services/WireGuardEndpointGuard.cs` / `IpsecEndpointGuard.cs` | Tunnel endpoints that must never be auto-blocked |
| `scripts/issue-duckdns-cert.sh` | Let's Encrypt DNS-01 issuance for a duckdns.org name |
| `scripts/diagnose-ipsec.sh` | Read-only triage for a site-to-site tunnel that won't come up |
| `Web/WebAuthStore.cs` | Master password hash + session tokens |
| `scripts/package.sh` | Build self-contained tarball + `.install.sh` |
| `scripts/install-from-package.sh` | Server/desktop installer (shipped as `install.sh`) |
| `scripts/systemd/` | `networksentinel-web` unit + `web.env` example |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |
| `Controls/TrafficChart.cs` | Dual sparkline + paired bar chart for the data-flow cards |
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
- **Threat-intel feeds** download FireHOL level1 and Spamhaus DROP once a day to `threat-intel-cache.json` and fall back to the cache when offline; turn them off with `"ThreatIntelEnabled": false`.
- The **honeypot** is off by default because it binds real ports — enable it under **Settings → Honeypot decoy ports** once you have confirmed the chosen ports are free.
- The **exfiltration monitor** needs `ss` (iproute2, present on essentially every distro); without it the feature reports itself unavailable and stays quiet.
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
| `Elevation failed... Need admin rights` on a **headless server** | `pkexec` can't work without a display/polkit session. Grant the service user passwordless sudo for `nft`/`iptables` — see [Firewall elevation on a headless server](#firewall-elevation-on-a-headless-server-no-pkexec). |
| `.NET location: Not found` | Use the **server installer** / self-contained package, or set `DOTNET_ROOT` / `PATH`. |
| Process names missing | Expected for other users’ sockets without root; monitoring still works. |
| No tray icon | DE must support StatusNotifier/AppIndicator; window title still updates when minimized. |
| Web UI asks for password every time | Expected after sign-out, browser close, or 12h idle. Reset: delete `web-master.json`. |
| `networksentinel-web` won’t start | `journalctl -u networksentinel-web -e`; check port in `/etc/networksentinel/web.env`; confirm binary exists at `/usr/local/bin/networksentinel`. |
| Port already in use | Change `WEB_PORT` or run `networksentinel -w` to auto-pick a free high port. |
| Port shows `LISTEN` locally but unreachable from outside | On a cloud VPS (Linode, AWS, DigitalOcean, …), the process listening (`sudo ss -ltnp \| grep 18765`) only proves the app is up — the provider's network firewall/security group can still drop inbound traffic before it reaches the box. Open the port in the provider's dashboard. |
| Service dies after logout (user unit) | `sudo loginctl enable-linger "$USER"` |
| Site-to-site VPN tunnel dropped and won't come back | Run `sudo bash scripts/diagnose-ipsec.sh <peer-ip>` — see [below](#a-site-to-site-tunnel-that-wont-come-up). |

### A site-to-site tunnel that won't come up

```bash
sudo bash scripts/diagnose-ipsec.sh 203.0.113.7    # the peer's public address
```

Read-only, takes about 25 s, changes nothing. It answers three questions in order: **is this host blocking the peer or the IKE ports**, **is the peer's traffic arriving at all and from which address**, and **what does the IKE daemon say**. Where that lands tells you which of these it is:

| What the script shows | What it means |
|---|---|
| A firewall rule naming the peer | This host blocked it. Allowlist the address (TUI `n`, or the web console's Allowlist tab) — that also removes the rule. A plain unblock only suppresses re-blocking for 24 h, so the tunnel would drop again tomorrow |
| No local rule, and **no packets captured** | Nothing is reaching the box, so the drop is upstream. On a cloud VPS this is nearly always the **provider's** firewall, which is invisible from inside the machine — see the note below |
| Packets arriving from a **different address** than the config names | The far end's WAN address changed. Classic on a dynamic residential line, and it looks exactly like a failure with no cause: worked for months, then stopped, nobody touched either end |
| Packets from the right address, IKE still failing | A negotiation problem — the log section names it (auth failure, proposal mismatch, no matching peer config) |

**On a cloud VPS, check the provider firewall first.** IPSec needs **UDP 500** (IKE) and **UDP 4500** (NAT-T) inbound, and these are not open by default. Two traps here:

- **Some providers cannot express ESP at all.** Linode's Cloud Firewall offers TCP, UDP, ICMP and IPENCAP — there is no protocol-50 option, so raw ESP can never be allowed. If IKE completes but no traffic crosses the tunnel, force UDP encapsulation (`forceencaps=yes` in `ipsec.conf`, or `encap = yes` for swanctl) so ESP travels inside UDP 4500, then `sudo ipsec restart`.
- **A peer on a dynamic address outgrows a pinned rule.** Scoping the source to the peer's `/32` is the right instinct, but every ISP rotation then breaks the tunnel until someone edits both the provider firewall *and* `right=`. Identify the peer by identity instead — `right=%any` with `rightid=`, authenticated by a strong PSK or certificate — and the address stops mattering. The provider firewall rule still has to widen to all sources, so the authentication is doing the work the address filter used to.

**This app never auto-blocks a tunnel endpoint** — see [Tunnel endpoints are never auto-blocked](#tunnel-endpoints-are-never-auto-blocked). If the script does find a rule naming your peer, it was a manual block or predates 0.6.6.

---

## License

Private project — all rights reserved unless you add a license file later.
