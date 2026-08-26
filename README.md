# Network Sentinel (Windows)

Native **Windows** app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **Windows Firewall blocking**.

Three ways to run it (same idea as the Linux build):

| Mode | When to use |
|------|-------------|
| **Desktop GUI** | Interactive workstation (default) |
| **Terminal UI (`--tui`)** | Server Core, RDP console, SSH-style workflows |
| **Headless web UI (`-w`)** | Browser dashboard on a server (master-password protected) |

> Awareness / monitoring tooling — not a full IDS/IPS replacement. Version **0.7.17**.

---

## What's new in 0.7.17

One fix: trusting a resolver in one place now trusts it in the other. This is the first number the Windows line reaches ahead of Linux, which carries the same change on top of its 0.7.16.

| Area | What changed |
|------|--------------|
| **The allowlist answers "is this resolver mine?"** | Adding a resolver to the known-good sites did nothing for the DNS hygiene check. The unapproved-resolver test read **Settings → Approved resolvers** and nothing else, so a resolver you had already told the app to trust still alerted at **High** as a suspected hijack, and the only way to quiet it was to type the same address into a second list. A destination now counts as approved if **either** list has it — the typed list first, since it is a hash lookup and this runs per flow, with the allowlist consulted only on a miss. A failing allowlist falls through to unapproved rather than silencing the check. |
| **What deliberately did not change** | **Approved resolvers** stays the arming switch: empty still means "not configured" rather than "nothing is approved", because the allowlist ships populated and arming off it would flag every host on first use. And allowlist entries still do **not** make HTTPS count as DoH — that branch reads the typed list alone, or every connection to a trusted site would register as encrypted DNS and **Encrypted DNS stopped** would never fire again. |
| **Allowlisted clears the hijack alert, and nothing else** | Trusting who answers says nothing about whether the question was readable in transit, so plaintext to an allowlisted resolver is still **Plaintext DNS egress** at Medium — now naming the allowlist entry that spared it the hijack verdict. The unapproved alert says the same thing from the other side: add it to Approved resolvers if it is yours, and note that only that list makes HTTPS to it count as DoH. |

The setting's description is corrected on all three front-ends, including the desktop Settings page the Linux build does not have, and the empty-list message now names the destination check as the thing being switched off. Seven new tests cover both lists, neither list, the arming switch, a throwing allowlist, and both directions of the DoH rule — **352 total**.

## What's new in 0.7.16

The first control here that can stop a connection before it is attempted — and a VPN alert that was calling ordinary tunnel use an attack. The number jumps from 0.7.13 to stay level with the Linux line, where this shipped as two releases: the filter and the WireGuard demotion as 0.7.15, Blocked Sites as 0.7.16. Neither line has a 0.7.14.

| Area | What changed |
|------|--------------|
| **DNS filtering** | Everything else in this app acts on a flow that already exists: the prevention engine writes a rule for an address the socket tables have already seen. On a VPN gateway a client's forwarded traffic never becomes a tracked connection at all, so **nothing here could block where a client goes**. A resolver refuses to answer, so the client learns no address and dials nothing. **Settings → DNS filtering** is that switch, over an AdGuard Home on this node's tunnel address. See [DNS filtering](#dns-filtering). |
| **The switch is the setup** | Unlike the Linux build, where an administrator runs a shell script first and the switch only means anything afterwards, here **turning the switch on is what installs it**. With no resolver present the switch names everything it would change — a Windows service, port 53, firewall rules, this host's own resolver — and only proceeds if you accept, with Windows asking again for Administrator consent. The script is still shipped and still runnable by hand (`scripts\setup-dns-filter.ps1`, with `-Uninstall`), for anyone who would rather read it first. |
| **Blocked Sites** | A new view, in the desktop app and the web console, listing the names the resolver actually refused: time, name, client, why, and the rule that did it. Read when you open it and when you press Refresh — never on the dashboard poll, because the query log is the busiest thing AdGuard serves and every tunnel client depends on that resolver answering. The rail item appears only once a resolver is configured. |
| **The switch reports the resolver, not itself** | Filtering state is read back from AdGuard rather than mirrored into `settings.json`. Anyone can flip protection in AdGuard's own UI, and a switch that says "on" while nothing is filtered is worse than no switch. "Cannot reach it" stays distinct from "deliberately off" — those need opposite responses. And it switches *filtering*, not the resolver: turning it off leaves DNS answering normally, so no client loses name resolution. |
| **Per-peer transfer is a note, not a threat** | Bytes to a WireGuard peer were filed as a **High** `DataExfiltration`. All that counter sees is encrypted volume, so a client pulling a backup looks exactly like a leak — and filing it as exfiltration aimed a threat at the peer's *endpoint*, the one address the prevention engine must never block and the reason `WireGuardEndpointGuard` exists. It is now an **Info** `VpnPeerChange` that says how much moved, at the figure you asked to hear about. |
| **An upgrade stops moving the web console** | `install-web-service.ps1` registered the scheduled task with the default port every time, so a console on any other port vanished from the address that was bookmarked — and reinstalling the previous version wrote the same default again. The port is now read back from the installed task and kept; `-Port` still wins, and the banner says which happened. A port you *do* move away from has its stale firewall rule removed. |

Seventeen more tests arrive with the setup handoff, and the resolver's own API is covered by the parse and wire suites ported from the Linux build — **345 total**.

## What's new in 0.7.13

The window can be drawn at whatever size suits the screen, and the web console stops offering an editor it cannot honour. The number jumps from 0.7.9 to stay level with the Linux line, where these shipped as four releases.

| Area | What changed |
|------|--------------|
| **Choose the text size** | Every size in the desktop window is an absolute device-independent pixel, so the only thing setting how large it draws was whatever Windows scales the display by. **Settings → Display → Text size** is a second multiplier on top of that, in six steps from 100% to 250%, applied straight away without a restart. It scales the whole window — text, tables, charts and spacing together — rather than the font sizes alone, so nothing is left clipped by text that outgrew the column holding it. Unlike the Linux build, which defaults to 175% because a desktop session that does not scale leaves it rendering 9px labels on a 4K panel, this one **defaults to 100%**: `app.manifest` declares PerMonitorV2, so Windows has already told the app the monitor's scale factor and applied it. Turn it up only to make this window larger than the rest of the desktop. Read through a clamp of 1.0–2.5, so a hand-edited `settings.json` cannot draw one stat tile across the screen with the Settings page that would undo it somewhere off the bottom right. |
| **The navigation rail scrolls** | The rail is the sidebar's fill child, and neither the DockPanel nor the card around it clips, so when the window was shorter than the list of entries the navigation drew straight over the STATUS block beneath it. Reachable already with a short enough window and certain once the text size goes up, so the list scrolls now. |
| **Firewall Config says it is read-only, before the form** | The web console decided whether to offer **Add**, **Edit** and **Delete** without asking whether a write could land, so a console that is not running elevated drew the whole editor, accepted a rule and refused it at Save — with a message naming “Run as Admin”, which is not a thing anyone has in a browser pointed at a service. The page now carries a read-only notice with the commands that fix it for this host, and disables the buttons behind it, so the failure arrives before the form rather than after it. `CanApplyRules` is the gate, and `FirewallService.Surface` says which front-end is asking: the desktop and the TUI keep their UAC advice, and the console — the one surface where a consent dialog would be raised on a server nobody is sitting at — gets commands it can paste. |
| **Firewall Config looks like the desktop page** | The two front-ends were already the same product carrying the same columns, but not the same page. Each section is a card now — the desktop's 18px radius and padding — with its name, a line of context, and that section's action pinned to the right of the same row, so **Add an Inbound Rule** sits on the list it adds to instead of in a shared strip above everything. Column headers take the desktop's sentence case, the zebra banding gives way to the flat card and its horizontal rules, and Delete becomes the solid danger gradient rather than an outline. The rail draws the same selection bar the desktop rail does. |

## What's new in 0.7.9

The terminal can configure the app now, not just watch it — and a rule you added twice can be deleted again. The number skips 0.7.8 to stay level with the Linux line, where these shipped as two releases.

| Area | What changed |
|------|--------------|
| **Settings from the terminal** | The TUI could watch and block but not configure: every setting meant reaching for the desktop window or the web console, neither of which is at hand on a server you only ever meet over a remote session. **Settings** is the eighth view (`8`), carrying the same catalogue the web console's Settings tab does — monitoring and poll interval, every detector and its thresholds, auto-block with its severity, direction, dry run and rule expiry, the webhook, and the whole remote-access group: HTTPS, port, TLS paths, redirect, HTTPS-only, DuckDNS, and Let's Encrypt issuance. Two rows go further than the console: Suricata's severity ceiling and its muted signature list, which no front-end here exposed before — hand-editing `settings.json` was the only way to change them. See [Settings from the terminal](#settings-from-the-terminal-079). |
| **A rule added twice can be deleted** | The web console names the row a **Delete** or an **Edit** meant by a key built from the rule's shape — direction, action, protocol, ports, sources, label, origin. Two rules can share every one of those and still be two rules: adding the same Firewall Config rule twice is enough, and the app names the second one `…-2` while both keep the label you typed. Either row's key then matched both, the lookup found two and refused with *"Several rules on this host have exactly that shape"*, and from that point neither row could be deleted or edited again — the one remedy it suggested, giving them distinct names, being something you do by editing them. The rule's name and its raw local/remote port constraints now go into the key, which makes it a superset of the fields the duplicate-fold groups on, so every row the list shows can be addressed. Rows that still agree on all of it are indistinguishable — Windows lets the same rule be added over and over — so the lookup takes the first rather than refuse a delete that could never be made unambiguous. |
| **Keys keep up with the cursor** | Drawing and reading the keyboard shared one 200ms tick in the TUI, so at most five keys a second were retired and the rest sat in the terminal buffer — holding an arrow down moved the cursor long after you let go. Input is polled ten times per draw and every key waiting is handled per pass, so a press lands within ~20ms and forces an immediate redraw, while an idle screen still refreshes on the slow tick. |

## What's new in 0.7.7

Two ways the master password and the peer IPs this app watches used to leave the machine in the clear, closed — and the dashboard boxes the desktop window has always had, given to the web console.

| Area | What changed |
|------|--------------|
| **HTTPS only** | **Settings → Remote access → HTTPS only** turns the plain-HTTP listener off entirely, rather than merely redirecting to TLS. Redirecting still means the password crosses the wire in the clear when a browser reaches the console by bare IP, because a redirect on a name-only certificate would trade a working page for a warning — with no HTTP listener bound there is nothing left to reach that way. Deliberately fail-open: honored only when HTTPS is on *and* the certificate loads at startup, so a broken or expired cert falls back to plain HTTP with a warning in the console banner and on the settings page instead of locking you out. Turning it on needs HTTPS already on, in the desktop app and the web console alike; the listen banner then hands out `https://` URLs, and a bind failure names only the port actually bound. |
| **Both geo endpoints are HTTPS** | The primary lookup (`ipwho.is`) was already TLS, but any failure — a rate limit, an outage — fell back to `http://ip-api.com`, broadcasting every public peer IP this app observes in cleartext and letting anyone on the path forge the country/city/ISP strings that land in threat alerts and webhooks. ip-api.com sells TLS only on its paid tier, so the fallback moves to `ipapi.co`, which is free over HTTPS. The parser takes both the full payload and the abbreviated one, and treats the documented `{"error": true}` body as a failure; anything unexpected degrades to the same *lookup unavailable* cache entry and 10-minute cooldown as before. |
| **The console's two dashboard boxes** | The desktop pairs each chart with the one number that summarises it — **Threat intensity** beside the activity chart, **This month**'s data in and out beside the data flow — and the web console paired them with nothing. Both panels are ported, so the two front-ends say the same thing on the page people actually leave open. Neither needed a new API field: all five month values were already being sent and spent on the footer sentence under the chart, which states the month's whole story in a line too long to read at a glance. The console's pulse reads **IDLE** rather than LIVE while asleep, because the count beneath it is then the last one measured; the desktop has no sleep mode and so no equivalent. With metering off the month box shows em dashes rather than zeros, because nothing was measured. The monthly bar chart, drawn unlabelled until now, gained the desktop's **Monthly data in and out** heading above its range dropdown. Below 900px — the same breakpoint the navigation rail folds at — each pair stacks instead of splitting a phone's width between two unreadable columns. |

## What's new in 0.7.5

One row is one rule now, in both front-ends and on the phone — plus the cut-off text and buttons that came with the 0.7.4 page.

| Area | What changed |
|------|--------------|
| **A rule appears once** | Windows stores its built-in groups once per profile: *File and Printer Sharing* arrives for Domain and again for Private,Public, *Cast to Device* three times over, identical in every field a rule list shows. The 0.7.4 fold kept them apart because its key included the profile, and nothing downstream did — so the console drew each rule twice, an iOS browser logged duplicate row identities, and Edit or Delete on any of them was refused as ambiguous, a rule being addressed by the shape it shows. They fold into one row carrying the union of their profiles. A rule live on less than the whole machine now says which profiles those are; one live on all three says nothing, because "Domain,Private,Public" down three hundred rows buries the handful that are actually scoped. |
| **Program and service are part of a rule's identity** | The other half of the same fix: what the fold keeps apart, the row has to be addressable by. One rule admitting `svchost` and one admitting `System` are two rules, and are now two rules you can edit and delete separately. |
| **The desktop and the console say the same thing** | Both build the same three lines from the same fields, in the same order — summary, listening sockets, policy. The desktop gained the *Scanned HH:mm:ss, not live* stamp the console had; the console gained the listener count line the desktop had, and its policy paragraph moved below the summary where the desktop keeps it. |
| **Nothing is cut off** | The rail title wrapped instead of reading "Network Sentine"; the Firewall Config grids were the only ones in the app not using the shared cell style, so long labels and IPv6 ranges stopped mid-value with no ellipsis and no way to read the rest — they trim and carry the full value as a tooltip now; and the action column was pinned at 150px where its two buttons need 164, which sliced the rounded edge off **Delete**. |
| **The Firewall Config tab says what it is doing** | It is the one page whose contents arrive on a second request (`/api/hostfirewall`, because a Windows host carries some 670 rules where a Linux one carries a dozen). Between the tap and the answer, and on failure, it used to be blank — which reads exactly like a firewall with no rules in it. It now shows a reading notice, then the rules, or the reason it could not and what to press; the request has a 60s deadline. |

## What's new in 0.7.4

The Firewall Config page stops being a list of this app's own rules and becomes the machine's firewall, and the web console is laid out like the desktop window.

| Area | What changed |
|------|--------------|
| **The whole host firewall** | Firewall Config used to list the `NetworkSentinel-*` rules and nothing else — a handful of rows sitting beside the *fifteen hundred* rules Windows, your installers and your games have written into the same firewall. One machine has one firewall; the page now reads all of it (`netsh advfirewall firewall show rule name=all verbose`), with a **Created by** column naming who wrote each rule, so a foreign rule is never mistaken for one this app is responsible for. Edit and Delete work on any of them. |
| **Listening services** | Under the rule lists: every TCP LISTEN and bound UDP socket with its bind address, owning process and service name, and the verdict the inbound rules pass on it — **Open**, **Restricted**, **Blocked**, **Not allowed**, **Local only**. A rule list on its own cannot answer *is this port reachable*; the two together do. **New rule** on a row opens the editor with that socket's protocol and port filled in. |
| **Duplicate rules are counted, not repeated** | Windows does not stop a setup script adding its rule on every run. The development machine this was written on holds **685 identical copies** of one rule; the page folds them into a single row marked `×685`, and deleting it removes all of them. |
| **Profiles, read rather than assumed** | The default policy shown is the one the *active* profile actually holds, and rules scoped to a profile that is not in force do not count towards a listener's verdict. "Block all inbound connections, including those in the list of allowed apps" is called out where it applies, because under it no allow rule below is doing anything. |
| **The console has the desktop's menus** | The web console is laid out like the desktop window: a navigation rail with the same menu names and hierarchy (Firewall Config and Allowlist indented under **Firewall & Block**), a **STATUS** block pinned to its foot with the auto-block toggle, and the desktop's hero header — clock, title, and the `high/critical · blocked · auto-block` subtitle from the same three numbers. |

Reading the firewall needs no elevation on Windows, so the whole list is there whether or not the app is running as Administrator — only writing needs **Run as Admin**.

## What's new in 0.7.2

Brings the Windows build level with the Linux 0.7.2 release, plus the IPSec half of the tunnel shield. Two new features, one new guard, and a fix to a write path that was losing data quietly.

| Area | What changed |
|------|--------------|
| **Data-flow charts** | The dashboard has always answered *who* is talking to this machine; it now also answers *how much went in and out*. Live in/out throughput on one shared zero-based scale (two independent scales draw a trickle of uploads at the same height as a saturated download), this month's totals, and paired bars per day of the month or per month of the year — in the desktop app **and** the web console. Sampled from the per-adapter octet counters every 5 s: no capture, no elevation, no subprocess. |
| **Physical adapters only** | A tunnel, a Hyper-V or VMware switch port, a teaming multiplexor and an OpenVPN TAP adapter all carry bytes that already crossed a real adapter, so counting both would double every tunnelled byte. The adapter *type* does not settle it — Wintun, Hyper-V switch ports and the KM-TEST loopback adapter all claim to be Ethernet — so the driver description is read too. Team **members** are metered and the multiplexor is not, which gives the total exactly once. |
| **Firewall Config** | A page in the desktop app and a tab in the web console for writing your own rules: Label / Action / Protocol / Port range / Sources, one form for both add and edit, service presets, and labels minted from the port (`block-inbound-rdp`) when you leave the field blank. Rules are ordinary `NetworkSentinel-Rule-*` Windows Firewall rules, so they apply system-wide and show up in `wf.msc`. |
| **Precedence needs no work here** | Windows Firewall groups rules by type and evaluates **blocks before allows**, so a config *Allow* can never reopen an address auto-block just shut, whichever was written first. (The Linux build has to insert app blocks at the head of a first-match-wins chain to get the same guarantee.) What no rule can change is a profile's default action — the page says so rather than implying an Allow rule is what grants access. |
| **Rules that would cut you off** | Blocking everything, or blocking inbound RDP, is confirmed before it is written. The **web console refuses outright** an inbound block that matches every source and covers its own port: the desktop app can ask you to confirm, but over the web the confirmation would travel down the connection being cut. A rule the firewall rejects is rolled back rather than left behind claiming to be in force. |
| **A typo'd port range no longer means "every port"** | Validation now runs *before* canonicalisation. The other order silently dropped a range the parser rejected — and an empty port field means every port, so `443-80` armed a catch-all block. |
| **IPSec tunnel endpoints are never auto-blocked** | The shield that already covered WireGuard now covers IPSec, which matters most for **site-to-site**: the peer is another site's router at a fixed public address, holding long-lived flows and retrying hard whenever the link flaps — the exact shape the heuristics look for. One auto-block drops the tunnel for both sites, and nothing at this end looks wrong afterwards. Peers are learned from live SAs, connection-security rules and the RAS phonebooks, and remembered for 24 h across restarts. Subnets, ranges and hostnames are never taken: a shield that swallowed `0.0.0.0/0` would disable auto-block for the whole internet. |
| **The upgrade banner** | A tab left open across an upgrade keeps its old markup — the page polls `/api/state` but never re-requests its own HTML, so no cache header can deliver the new UI and the new features simply look absent. The page now carries the build it was served from, and when the server reports a different one a banner offers a reload. It never reloads on its own: you may be mid-rule in the editor. |
| **Atomic writes stop losing bursts** | `WriteAtomic` retried a lost publish on a flat 15 ms sleep for 12 attempts — it gave up after ~165 ms, and every loser of a race woke at the same instant and collided again in lockstep. Since the callers swallow exceptions, that meant a **silently dropped write**; the firewall ledger has three concurrent writers and every frontend saves settings. Now randomised backoff to a 2 s deadline. |

A hundred more tests arrive with it (**188 total**), including the netsh rule round-trip, the adapter filter, the IPSec parsers, the console's self-block guard, and a concurrency test rebuilt so it actually fails on the bug it guards (32 writers released together: 8 failures in 8 runs before the fix, 0 in 15 after).

**Upgrading** is in place and non-destructive, as in 0.5.x. Re-run the installer and confirm the web header reads `v0.7.2` — and if a console tab was already open, it will now tell you itself.

---

## What's new in 0.6.5

Brings the Windows build level with the Linux 0.6.5 release. Two independent pieces: a tunnel-endpoint shield that stops auto-block severing your own VPN, and a block verdict carried into every warning.

| Area | What changed |
|------|--------------|
| **Tunnel endpoints are never auto-blocked** | The never-block gate for WireGuard peer endpoints read the *live* peer list, so it was inert unless **WireGuard peer monitoring** was switched on — off by default, and therefore off on exactly the VPN gateways that needed it. It also went blind whenever the tunnel was already down: `wg` reports no endpoint then, so the one address that would restore the tunnel looked like any other stranger. Blocking an endpoint does not drop an attacker; it drops the tunnel and every service behind it, while the console keeps answering on the LAN. The new shield runs regardless of that setting, samples every 60 s, and **remembers every endpoint for 24 h** across restarts. Hostnames in a config are deliberately not resolved — whoever answers DNS could otherwise write their own address into a never-block list. |
| **The gate stops being silent** | A threat against a protected endpoint now reports `Not blocking <ip> … it is a WireGuard tunnel endpoint` instead of leaving you to hunt for a rule that was never made. Rate-limited per address. |
| **Every warning says whether the address is blocked** | A toast or webhook named an address and stopped there, and the alert went out *before* the prevention engine had looked at the batch — so at alert time there was no answer to give. Enforcement now runs before any alert leaves the machine, and the verdict rides along: toast titles (`Blocked · critical threat: Port Scan`), webhook bodies, ntfy first lines, generic JSON (`blocked` / `block_state` / `block_status`), and the web console's browser notifications. |
| **Blocked column on every threat table** | The screen you land on after a warning now agrees with the warning — GUI (hover for the full reason), TUI and web console, red for a dropped address, amber for a block that failed or was only simulated, muted for one deliberately left alone. |
| **Unblock in place of Block** | A threat row whose address is already blocked offers **Unblock**, as the Remote Computers grid already did. Re-blocking only rewrites a rule already in force — and because the manual path passes no expiry, a stray click turned an expiring auto-block into a permanent manual one. |
| **Dry run means dry run** | Every frontend built its own auto-block status line and every one dropped the same thing: dry run. A console could read `Auto-block ON (≥High)` while the engine was deliberately writing nothing. All of them now come from the engine. Dry run also no longer demands elevation — it writes no rule, and refusing to *simulate* blocked the one workflow the mode exists for. |

Twenty more tests arrive with it (88 total), including the tunnel-endpoint gate end to end and a `wg show all dump` parse asserting neither the interface private key nor a peer's preshared key survives.

**Upgrading** is in place and non-destructive, as in 0.5.x. Re-run the installer and confirm the web header reads `v0.6.5`.

---

## What's new in 0.6.2

Brings the Windows build level with the Linux 0.6.2 release — the prevention engine's safety rails, and the composition root behind them.

| Area | What changed |
|------|--------------|
| **Never block yourself** | Two new auto-block gates: this machine's own interface addresses, and any current **WireGuard peer endpoint**. A detector that attributes a threat to the wrong end of a flow could previously firewall the host off from itself — most likely on a cloud VM, whose own address is public and so passes the "routable public address" gate. Manual blocking is deliberately unaffected. |
| **Retry that fits the failure** | An address is claimed for 10 minutes once a batch acts on it, but a block that fails for a reason *other* than elevation now retries after **45 s** — one transient error used to leave an actively hammering host alone for ten minutes. Elevation failures instead pause auto-block globally for 5 minutes, since they are never per-address. Dry run no longer consumes an address's retry slot, so reviewing a batch in dry run and then switching blocking on no longer skips exactly the attackers you just reviewed. |
| **Carrier-grade NAT** | 100.64/10 (Tailscale, many VPN tunnels) is out of auto-block, but can still be blocked **manually** behind a confirmation naming what it costs. Only LAN/loopback/link-local/multicast are refused outright — a hostile tunnel peer is a real case. |
| **Web console** | First-visit password setup **from another machine** now requires a one-time setup code printed where the console runs. The console binds all interfaces before any password exists, so without it whoever reached the port first could claim the master password and with it firewall control. Setup from localhost is unchanged. Also adds `X-Frame-Options`/HSTS, and stops returning raw exception text to anonymous clients. |
| **Durability** | Every JSON store is written via temp-sibling + rename, so a crash mid-write can no longer truncate a file that the loader would then treat as empty. The expiry ledger is reconciled with the firewall at startup: a rule deleted via wf.msc or Group Policy used to leave its entry behind forever, with the sweep retrying a delete every minute. |
| **Connection identity** | The PID is no longer part of a connection's identity. It flips 0 → real once the owning process resolves, so every new connection changed identity one poll in — counted twice by the host stats and seen twice by the intrusion heuristics, effectively halving their rate thresholds. |
| **`SentinelCore`** | The GUI, TUI and web console each built the monitor/firewall/allowlist/prevention graph with a copied wiring block, and the copies had drifted. One composition root now owns construction and disposal; the TUI and web console pick up the configured poll interval and allowlist disposal they were missing. |

A test project (`Tests\NetworkSentinel.Tests`, 68 tests) and a CI workflow arrive with it.

**Upgrading** is in place and non-destructive, as in 0.5.x. Re-run the installer and confirm the web header reads `v0.6.2`.

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
| **Data-flow charts** | Bytes in/out sampled from the adapter counters: live throughput, this month's totals, and paired bars per day or per month — desktop app and web console |

**Local sockets are listed once, not twice.** A connection between two processes on this machine is two rows in the kernel's TCP table, one owned by each end, and Live Connections showed both — so a browser talking to its own helper, or Docker Desktop's services talking among themselves, filled the list with what read as duplicate rows. They are one conversation, and the two halves sort apart, so the repetition was rarely even visibly a pair. The client's end survives — the one whose local port is the ephemeral one, which reads the way the connection was made — and the process on the far end is carried onto it, so the row names both. That also displaces the hostname for those rows, which is an improvement: reverse-resolving `127.0.0.1` returns whatever the hosts file maps it to, and on a machine running Docker Desktop that is `kubernetes.docker.internal`, making every local socket look like it is talking to a container. Display only — the detectors and the host accounting read the poll's own tables, so nothing here changes what is measured or blocked.

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

### Every warning says whether the address is blocked

A warning that names an address and stops there sends you to the console to find out whether anything was actually done about it. So each batch of threats is run past the prevention engine **before** any alert about it leaves the machine, and the alert carries the verdict:

| Verdict | When |
| --- | --- |
| `BLOCKED — auto-block rule added` | A rule was just written for the address |
| `BLOCKED — a rule for this address is already in place` | It was already blocked |
| `NOT blocked — the firewall refused the rule: …` | A block was attempted and failed |
| `NOT blocked — dry run (it would have been blocked)` | Prevention is in dry-run mode |
| `NOT blocked — auto-block is off` / `Administrator rights are required` / `you released this address manually` / `allowlisted` / `below the auto-block level (≥High)` / … | The gate that stopped it — see [Prevention engine](#prevention-engine) |

Windows toasts lead with it in the title (`Blocked · critical threat: Port Scan`, or `3 critical threats — 2 of 3 blocked`), the web console's browser notifications say the same, webhooks carry it in the message body, and generic JSON payloads add `blocked`, `block_state` and `block_status` fields. Threats that name no blockable address (a startup-item change, a new local listener) say nothing about blocking rather than guessing.

The threat tables answer it too, so the screen you land on after a warning agrees with the warning: a **Blocked** column in the GUI (hover for the full reason) and the web console, and a `Blk` column in the TUI — red when the address is being dropped, amber for a block that failed or was only simulated, muted when it was deliberately left alone. A row whose address is already blocked offers **Unblock** in place of **Block IP**, as the Remote Computers grid does; re-blocking would only rewrite a rule that is already in force, and would quietly turn an expiring auto-block into a permanent manual one.

Every status line that reports auto-block state — the GUI hero subtitle, the TUI footer, the web console's sidebar status block, and the message each shows when you flip the toggle — comes from the engine itself, so **DRY RUN** is never mistaken for armed.

### Prevention engine

Every automatic block — from any detector, in any of the three frontends — goes through **one** enforcement engine (`PreventionService`). It used to be three near-identical copies of the same logic in the GUI, TUI and web console, each with its own blocked-IP cache and retry map. Detection sources keep multiplying; the decision to drop traffic must not.

Gates, in order — a threat must clear all of them before a rule is written:

| Gate | Why |
|------|-----|
| Severity ≥ minimum | The configured `Medium`/`High`/`Critical` threshold |
| Not `New Remote Host` | First contact is not evidence of anything |
| Routable public address | LAN, loopback, CGNAT (100.64/10 — Tailscale and many VPN tunnels) and multicast are never auto-blocked. CGNAT can still be blocked **manually**, behind a confirmation — a hostile tunnel peer is a real case, and only LAN/loopback/link-local/multicast are refused outright |
| Not allowlisted | Known-good stays reachable |
| Not this machine | A detector that attributes a threat to the wrong end of a flow can never firewall the host off from itself — matters most on a cloud VM whose own address is public |
| Not a WireGuard tunnel endpoint | A peer's public endpoint is where its tunnel packets come from; blocking it does not drop an attacker, it drops the tunnel and everything reached through it. Independent of the WireGuard *monitoring* setting, and remembered for 24 h — see [tunnel endpoints are never auto-blocked](#tunnel-endpoints-are-never-auto-blocked) |
| Not protected | See lockout protection below |
| Not already blocked | No duplicate rules |
| Not suppressed | An address you deliberately released stays released for 24 h |
| Not retried too soon | An address is claimed for 10 minutes once a batch acts on it. A block that fails for a reason other than elevation (a timed-out `netsh`, a briefly locked rule store) retries after **45 s** instead — one transient error should not leave an active attacker alone for ten minutes. Elevation failures pause auto-block globally for 5 minutes |

- **Dry run** (**Settings → Prevention and deep inspection → Auto-block dry run**, or `s` in the TUI) runs every gate and reports what it *would* have dropped, without writing a single rule. Blocking turns a false positive from noise into an outage, so a new detection source — a fresh Suricata ruleset especially — belongs here first. The console shows `Would block …` lines exactly where it would otherwise show `Auto-blocked …`.
- **Lockout protection** — the address of whoever is signed into the web console is shielded from auto-block for a rolling 30 minutes. Prevention that firewalls the operator away from the box it protects has done more damage than the attack it stopped. Manual blocking is deliberately unaffected, and the shield lapses on its own once you stop working.
- Direction fallback is now consistent: with neither **Block inbound** nor **Block outbound** ticked, all three frontends block **both** (the GUI used to block inbound only).

### Kernel flow events

Polling the TCP/UDP tables can only ever describe the moment they were read — on the default 1.2 s cycle an attacker gets a free window before anything is sampled. Network Sentinel also subscribes to the **`Microsoft-Windows-Kernel-Network` ETW provider** and takes its snapshot *because something happened* rather than because a timer fired.

- Reaction to an inbound connection on a served port drops from up to a full poll interval to well under a second
- The heuristics are unchanged — they are snapshot-based by design, and a snapshot is still what they consume. Only the *timing* of the snapshot changes
- A 150 ms floor coalesces bursts, so a port scan of a thousand ports does not become a thousand snapshots
- Only flows aimed at a port this machine actually serves cut the interval short, so ordinary outbound client traffic doesn't make a busy machine poll flat out
- It is also the **only source of UDP peer addresses**. `GetExtendedUdpTable` reports unconnected sockets with no remote address, so a DNS query has no representation in the socket table at all — DNS hygiene below is fed entirely from here
- Event payloads are decoded through **TDH against the provider's own schema**, looked up by field name rather than by hard-coded offsets. A wrong offset would not throw; it would yield a plausible but wrong address that the prevention engine then firewalls. If the schema is not what is expected, the event is dropped rather than guessed at
- Starting a real-time ETW session needs **Administrator**. Without it the session fails to start, the console explains why, and the timer cadence continues — no functionality is lost, only reaction time

### Signature detection — Suricata

Connection heuristics see *who* is talking and *how often*; they can never see *what is being said*. That gap is closed by attaching **Suricata** rather than writing a detection engine: protocol decoders, stream reassembly and the target-based defragmentation that stops an attacker evading inspection are a multi-year project whose failure mode is a bypass nobody notices. Suricata already does all of it, and already has ET Open rules maintained full time.

So Network Sentinel is the **manager**, not the engine — Suricata decides what matched, this app decides what happens next:

| | |
|---|---|
| **Input** | Suricata's EVE JSON (`C:\Program Files\Suricata\log\eve.json` by default; set `eve-log` to enabled in `suricata.yaml`) |
| **Severity mapping** | Suricata counts down — sev 1 → **Critical**, 2 → **High**, 3 → **Medium**, 4 → **Low**. A sev-1 match therefore clears the default `High` auto-block threshold |
| **Threat source** | The *remote* end of the flow, not the packet source — for an outbound C2 callback the attacker is the destination, and blocking the source would firewall the host off from itself |
| **Noise control** | A maximum severity number, a per-signature mute list (`sids`), and a 2-minute per-signature-per-peer cooldown so one rule matching every packet can't bury every other alert |
| **IPS mode** | When Suricata dropped the packet itself, the alert detail says `already dropped by Suricata` |

Alerts arrive as ordinary `Signature Match` threat events, so the whole existing pipeline applies unchanged: the threat list, the persistent log, geo/origin enrichment, webhooks, the allowlist, and auto-block. Log rotation is handled — the tailer reopens rather than sitting on a stale handle.

Suricata is **not bundled**; install and run it yourself, then switch on **Settings → Suricata signature alerts**. The log directory under `Program Files` is not world-readable, so this usually needs Administrator.

### VPN peer monitoring — WireGuard

WireGuard is invisible to everything else in this app. It uses a single **unconnected** UDP socket, so the socket table files it as a UDP endpoint with no peer and **no VPN client ever becomes a tracked connection** — nothing reaches the intrusion heuristics, the Remote Computers list, threat intel, or the prevention engine. On a VPN server that is a hole straight through the middle of the monitoring.

This reads WireGuard's own state (`wg show all dump`, via the `wg.exe` that WireGuard for Windows installs) instead:

| Detection | Level | Why |
|-----------|-------|-----|
| **New peer** | High | A peer entry grants standing access to your network. If you didn't add it, someone with Administrator rights edited the WireGuard config |
| **Endpoint moved** | Low | Roaming between wifi and cellular is ordinary WireGuard behaviour — the value is the geo lookup patched into the alert's origin. The same key appearing from another country is not roaming |
| **Peer removed** | Low | Expected after revoking access; unexpected means the config changed underneath you |
| **Per-peer transfer** | Info | Optional (0 = off). An accounting note, not a finding: volume through a tunnel is the tunnel working. Forwarded tunnel traffic has no local socket, so the exfiltration monitor cannot see it — this is the only place it is counted |

- The first run adopts the existing peer list silently; the baseline persists in `wireguard-peers.json`, so a restart doesn't re-alert on peers you already know. Endpoint addresses are kept separately in `wireguard-endpoints.json` — see [tunnel endpoints are never auto-blocked](#tunnel-endpoints-are-never-auto-blocked).
- **Key material never leaves the parser.** `wg show ... dump` prints the interface *private* key and each peer's *preshared* key. Both are dropped at parse time — they are never stored, logged, shown in the console, written to the baseline file, or sent to a webhook. Only public keys are used.
- The web console shows a live peer table under **Settings → VPN (WireGuard)**: peer key (hover for the full key), interface, endpoint, allowed IPs, last handshake, and Rx/Tx. It is **read-only by design** — revoking a peer is a WireGuard configuration change, not something a monitoring console should do behind your back.
- Needs **Administrator**; `wg.exe` cannot read the WireGuard service's device state otherwise. Without it the setting explains why rather than failing quietly.
- Per-peer transfer noting is **off by default**, and informational when on: a VPN user streaming video legitimately moves gigabytes, so any threshold low enough to catch a slow leak would fire constantly on normal use. What comes out is a volume notice at the figure you picked, not a judgement that the traffic was wrong. Until 0.7.16 it was a **High** `DataExfiltration`, which also pointed a threat at the peer's endpoint — the one address that must never be auto-blocked.

#### Tunnel endpoints are never auto-blocked

Tunnel addresses are private-range (RFC1918 or CGNAT 100.64/10), so auto-block will never act on a VPN client's tunnel IP — by design, since blocking a tunnel IP would be both ineffective and confusing.

A peer's **public endpoint** — the address its encrypted packets actually arrive from — is protected separately, and this protection does **not** depend on peer monitoring being switched on. It has to be unconditional, because the failure is silent and self-inflicted: dropping an endpoint does not stop an attacker, it severs the tunnel and every service behind it, while the console keeps answering happily on the LAN. On a gateway you administer *through* that tunnel, the block also takes away the way back in. (Until now the gate read the live peer list, so it was inert unless WireGuard monitoring was on, which is off by default.)

Endpoints are collected from three places, so there is no window where one is blockable:

| Source | Covers |
|--------|--------|
| `wg show all dump`, sampled every 60 s | Live peers, including a client that has just roamed to a new address |
| `Endpoint =` in any plain-text `.conf` under `…\WireGuard\Data\Configurations` | The server a client dials — still named there when the tunnel is **down** |
| A persisted 24 h memory (`wireguard-endpoints.json`) | Restarts, a momentary `wg.exe` failure, a peer that went quiet, and the case that matters most: a tunnel that has **already** dropped, where `wg` reports no endpoint at all and the one address that would restore it otherwise looks like any other stranger |

- **Hostnames in a config are deliberately not resolved.** `Endpoint = vpn.example.org:51820` contributes nothing, because anyone able to answer DNS could otherwise write their own address into a never-block list — the same reasoning as the allowlist drift detector. The live dump reports the resolved address anyway.
- WireGuard for Windows keeps imported tunnels as `<name>.conf.dpapi`, encrypted for the tunnel manager's own account. Those are **never** decrypted here, so the config source only sees a plain `.conf` you left in place. The live dump and the 24 h memory cover the rest.
- WireGuard adapters are detected from the NIC table — no elevation, no subprocess — so a host with no tunnel spends nothing. A host that *has* one but cannot read its peers says so in **Settings → VPN (WireGuard)** rather than staying quiet: an unelevated run can still gain rights through UAC and start writing rules, so silence there would be the dangerous case.
- When a detector does flag a peer endpoint, the console now says so — `Not blocking 203.0.113.9 (Critical: …) — it is a WireGuard tunnel endpoint` — instead of leaving you to wonder why no rule appeared. Rate-limited per address.
- **Manual blocking is unaffected**, here as with the operator shield: a hostile tunnel peer is a real case. Cutting off a peer for good belongs in WireGuard's own configuration (`wg set <iface> peer <key> remove`), not in a monitoring console acting behind your back.

#### The same shield for IPSec, including site-to-site

The argument above is not WireGuard's; it is any tunnel's. **IPSec peers are shielded from auto-block on the same terms**, which matters most for a **site-to-site** tunnel — the case where the peer cannot phone you to say it went down:

- the far end is another site's router at a **fixed public address**, indistinguishable from any stranger's to every heuristic here;
- its traffic is the exact shape the heuristics look for — one remote address holding long-lived flows to whatever the tunnel carries, re-keying on a timer, and **retrying hard whenever the link flaps**, which reads like a brute-force or scan pattern;
- so a single auto-block drops the tunnel for **both** sites at once, and nothing at this end looks wrong afterwards: the rule applied, the console still answers, and the other office simply loses the VPN.

Peers are collected the same belt-and-braces way, on the same 60 s cadence, and remembered for the same 24 h:

| Source | Covers |
|--------|--------|
| `netsh advfirewall monitor show mmsa` / `qmsa` | Live security associations. **Implementation-independent** — an IKEv2 client VPN, an RRAS site-to-site tunnel and a domain-isolation policy all install SAs the same Windows Filtering Platform reports. Main mode is up before quick mode, so reading both covers the window a flapping tunnel spends most of its time in |
| `netsh advfirewall consec show rule name=all` | Connection-security rules — the peer named in *configuration*, still there with the tunnel **down**, which is the state a site is in after the very block this prevents |
| `Ras\router.pbk` (RRAS demand-dial) and `rasphone.pbk` (client VPNs) | The far end of a site-to-site interface or a dialled VPN, read straight from the phonebook with no subprocess and no elevation |
| A persisted 24 h memory (`ipsec-endpoints.json`) | Restarts, re-keying windows, a momentary command failure, and a tunnel that has **already** dropped |

- **Subnets and ranges are never read.** A tunnel rule's endpoint can be a whole network, and a shield that swallowed `0.0.0.0/0` would silently disable auto-block for the entire internet. Only bare single addresses are taken; anything with a prefix or written as a range is skipped, as is a rule's own name, which is operator-chosen text that can be anything at all.
- Hostnames contribute nothing — a phonebook overwhelmingly holds them — for the same reason as WireGuard's `Endpoint =`. The live SA views report the address itself.
- Both ends of an SA are kept rather than guessing which is remote: which one is the peer depends on who initiated, and this host's own addresses are refused by an earlier gate anyway.
- The parser is deliberately **label-blind**. netsh output is localized, so keying on "Remote IP Address" would make the shield work on English installs only.
- Reading SA state needs **Administrator**. A caveat worth knowing: `netsh` reports that refusal on stdout and still **exits 0**, so a naive reading would call an unelevated host "no IPSec configured" — precisely the silence this guard exists to prevent. The privilege is checked up front instead, and the status says what is true on Windows: a process that cannot read the tunnel state cannot write a firewall rule either, so nothing is at risk while it is off.
- Detection is unchanged: this gate only stops the machine deciding on its own. **Manual blocking still works**, and a peer that really is hostile belongs in the IPSec configuration, not in a firewall rule that also takes the tunnel down.

### Data flow — how much, not just who

The dashboard has always answered *who is talking to this machine*. It also answers *how much went in and out*.

`TrafficMeterService` reads the cumulative per-adapter octet counters Windows keeps (`NetworkInterface.GetIPStatistics`) every 5 s and diffs them — no packet capture, no elevation, no subprocess. Three cards: live in/out throughput on one shared zero-based scale (two independent scales would make a trickle of uploads look like a saturated download), this month's totals, and paired bars per day of the month or per month of the year.

Two details decide whether the numbers are right, and each has a test:

- **Physical links only.** A tunnel, a Hyper-V or VMware virtual switch port, a teaming multiplexor above its own members, and an OpenVPN TAP adapter all carry bytes that already crossed a physical adapter — counting both would double every tunnelled byte. Loopback never leaves the machine. The adapter *type* does not settle it: a WireGuard (Wintun) adapter, a Hyper-V switch port and the KM-TEST loopback adapter all present as ordinary Ethernet, so the driver description is read too, and the marker list names families (`vEthernet`, `TAP-`, `Multiplexor`) rather than products. Team **members** are metered and the multiplexor is not, which gives the total exactly once.
- **Counters reset.** A reboot or an adapter bounce restarts them at zero; a counter that moved backwards is treated as a fresh start and its current value is the delta.

Daily totals and the last raw counters persist to `traffic-history.json`, so the diff continues across a restart — but that first catch-up delta spans however long the app was shut, so it counts toward the day and is deliberately **not** charted as a rate.

Turn it off with `TrafficMeterEnabled` (Settings → Traffic metering); the history is kept but stops growing. The web console's toggle takes effect immediately rather than at the next restart.

### DNS hygiene

Almost nothing connects without resolving a name first, so DNS is where a compromise usually shows earliest — and it is a standard exfiltration channel the exfiltration monitor cannot see, since that counts TCP socket bytes and DNS is UDP. Until now this app had no view of DNS at all.

| Detection | Level | Why |
|-----------|-------|-----|
| **Plaintext DNS egress** | Medium | Queries leaving on port 53 can be read *and rewritten* by anything on the path |
| **Encrypted DNS stopped** | High | Resolvers usually fall back to plaintext rather than fail, so a blocked port 853 or an expired certificate silently removes the protection you configured. Nobody notices this one |
| **Unapproved resolver** | High | Something changed the resolver configuration, or answers are being redirected. A destination counts as approved if it is under **Approved resolvers** *or* already on the allowlist |
| **VPN client bypassing your resolver** | Medium | A tunnel client querying externally in the clear defeats the thing the VPN was for |
| **Allowlisted domain moved networks** | High | See below — this one is about protecting Network Sentinel itself |

**Why the allowlist matters here.** `AllowlistService` resolves allowlisted domains over whatever DNS the host is using, and the prevention engine **never auto-blocks a resolved allowlist address**. Poison the host's DNS and an attacker's address is written into the allowlist under a trusted domain's name — permanently immune to blocking, by design. The drift detector compares every answer against the networks that domain has resolved into before (a /24 for IPv4, /48 for IPv6) and alerts only when the new answer shares *nothing* with that history, so ordinary CDN rotation stays quiet. The history persists in `dns-domain-networks.json`, because a restart that silently re-seeded would adopt a poisoned answer as the new truth.

**What it can and cannot see.** Port 53 is plaintext and detected wherever it goes. Port 853 is DoT and recognised as encrypted. **DoH is HTTPS on 443 and is indistinguishable from ordinary web traffic** — it is only counted as encrypted DNS when the destination is a resolver you list under **Approved resolvers**. Without that list a DoH setup looks like no DNS at all rather than like a leak. Allowlist entries deliberately do **not** count for this: every HTTPS connection to a trusted site would register as encrypted DNS and the **Encrypted DNS stopped** detector would never fire again.

**Which resolvers count as approved.** Both lists are consulted. **Approved resolvers** is the explicit one, and it is also the arming switch — leave it empty and the check stays off entirely, because the allowlist ships populated and would otherwise flag every host on first use. Anything the allowlist already trusts also counts, so a resolver you added to your known-good sites does not have to be typed in twice. Being allowlisted only clears the `Unapproved resolver` alert, though; the query is still judged on whether it was encrypted, so plaintext to a trusted resolver is still reported as **Plaintext DNS egress** at Medium, and only the **Approved resolvers** list makes HTTPS to an address count as DoH.

Flows come from the ETW flow event source, so this covers traffic the socket tables never show — most importantly UDP peers, which have no remote address in the UDP table at all. That needs **Administrator**; without it the status says so and no detection runs.

> **One difference from the Linux build.** `Microsoft-Windows-Kernel-Network` reports *this host's own* socket activity. The Linux port reads conntrack, which also sees **forwarded** packets, so it catches a VPN client querying an external resolver as that traffic is routed through. On Windows that traffic never touches a local socket, so the **VPN client bypassing your resolver** detection only fires when the query terminates on this machine. The other four detections are unaffected.

> **The arrangement to aim for.** Windows 11 and Server 2022 can encrypt DNS themselves — `netsh dns add encryption server=<resolver> dohtemplate=<url>`, then set the adapter to DoH. Queries to a local address are never flagged, because a local resolver forwarding upstream over DoT/DoH is the wanted design: you keep full visibility here while the network sees nothing. Pointing everything straight at an external DoH endpoint hides your queries from your ISP *and* from this program — and from Suricata's DNS rules.

Detection is what this section is for. Doing something about it is the next one.

### DNS filtering

Every other control in this app acts on a flow that **already exists**. The prevention engine writes a firewall rule for an address the socket tables have already reported, which means the connection was made first. On a VPN gateway it is worse than that: a client's forwarded traffic never becomes a tracked connection at all, so nothing described above can block **where a client goes**.

A resolver can. It refuses to answer, the client learns no address, and nothing is dialled. That is the only control here that stops a connection *before* it is attempted.

**Settings → DNS filtering** is that switch, over an [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) running on this node's tunnel address:

```
host + tunnel clients -> AdGuard Home (this node) -> [DoT] -> upstream
```

Queries never leave the node in the clear, and because the resolver is local you keep full visibility while the network sees nothing — the arrangement the section above asks for.

#### Turning it on installs it

**This is the one place the feature is turned on.** Flip the switch with no resolver present and it names everything it is about to change before anything happens:

- download AdGuard Home and register it as a Windows service
- bind its admin UI to this node's tunnel address (port 3000)
- serve DNS on port 53 to tunnel clients only
- add Windows Firewall rules for both
- point this machine's own resolver at it

Accept and Windows asks again for Administrator consent; decline either and nothing is changed and the switch goes back to off. Everything replaced is backed up first, and `-Uninstall` puts it back — including this host's original resolver settings, because a machine left pointing at a resolver that no longer exists loses name resolution entirely.

The download is verified against AdGuard's published `checksums.txt` before it is unpacked; a hash that differs stops the install, and a *missing* line is reported as the packaging change it probably is rather than as tampering.

This differs from the Linux build on purpose. There, `setup-dns-filter.sh` is run by hand and the switch only means anything afterwards. The script is still here and still runnable directly — `powershell -ExecutionPolicy Bypass -File .\scripts\setup-dns-filter.ps1`, with `-DryRun`, `-Uninstall`, `-TunnelAddress`, `-Upstream`, `-StrayDns` and `-NoFirewall` — for a headless server, or for reading before running.

**Only the desktop switch installs.** The TUI and the web console change filtering on a resolver that already exists, and otherwise name the command instead of running it. Installing needs Administrator consent at that machine's own desktop, which is exactly what is not there when the console is being driven over the network — the same reason the console says it cannot write firewall rules rather than offering an editor that fails at Save.

#### What the switch actually switches

Filtering, not the resolver. Stopping the service would take DNS away from every tunnel client at once — an outage, not "filtering off". Switching protection off leaves the resolver answering normally but unfiltered, which is what AdGuard's own **Disable protection** does and the only reading that cannot strand a client.

The state shown is **read back from AdGuard**, not from `settings.json`. Anyone can flip protection in AdGuard's own UI, and a switch that claims "on" while nothing is being filtered is worse than no switch — the same reason the auto-block status comes from the engine rather than the settings. "Cannot reach the resolver" stays distinct from "deliberately off": they need opposite responses from whoever is reading.

#### Blocked Sites

A view in the desktop app and the web console listing what the resolver refused, newest first: time, name, client, why, and the rule. It is read when you open it and when you press **Refresh**, never on the dashboard poll — the query log is the busiest thing AdGuard serves, and every tunnel client depends on that resolver answering. The rail item appears only once a resolver is configured, and takes itself away if you clear it.

#### The gap this leaves

**It blocks by name.** Malware that dials a hard-coded IP makes no DNS query and passes straight through — which is exactly the case the threat-intel feeds and the prevention engine catch. Neither half covers the other; keep both on.

Two Windows-specific limits are worth knowing. The Linux build can DNAT a client's hard-coded `8.8.8.8` back to the local resolver, so filtering holds even for a client that ignores the pushed setting. Windows Firewall has no DNAT and `netsh portproxy` is TCP-only, so **that mode is not offered here** rather than half-implemented; `-StrayDns Block` fails such a client's DNS instead of silently letting it bypass the filter. And whether that block reaches RRAS-*forwarded* client traffic depends on your routing setup — verify it with a client rather than assuming.

Finally: the resolver's admin password is stored in `settings.json`, which on Windows lives in `%ProgramData%\NetworkSentinel` with `BUILTIN\Users` granted Modify so the desktop app, the TUI and the SYSTEM web service share one state. Any local user can read it. That is already true of the DuckDNS token and the TLS key password; it is written down here because a resolver admin password is worth knowing it about.

### Remote alerting (webhook)
Set **Settings → Webhook URL** to push Critical threats off the machine — the payload adapts automatically: **ntfy** (plain text + `Title`/`Priority` headers), **Slack** (`{"text": …}`), **Discord** (`{"content": …}`), anything else gets a generic JSON document. Per-source/type cooldown stops a burst from flooding the channel.

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both) — rules are created as an `-In`/`-Out` pair and removed together (config rules are never paired, so their names are exempt from that)
- Your own rules, written on the **Firewall Config** page — see below
- **Block local ports** (TCP/UDP)
- Only *manages* rules named `NetworkSentinel-*` — auto-block, manual blocks and expiry never touch anything else. Since 0.7.4 the Firewall Config page can also **show and edit the rest of the host firewall** on request, but nothing automatic acts on a rule this app did not write
- All firewall changes go through **`netsh` in a separate process** (never firewall COM — COM from web/thread-pool threads can crash the host)
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Removing/unblocking a rule **suppresses auto-block for that IP for 24 h** (persisted), so removed rules stay gone across restarts
- **Auto-block expiry** (1 h … 7 days, off by default) — an expired address stops counting as blocked immediately; the `netsh` rule itself is deleted by a background sweep, which needs the app to be running elevated. Manual blocks are always permanent
- The expiry side-file is **reconciled with the firewall at startup**: a rule deleted outside the app (wf.msc, Group Policy, another administrator) would otherwise leave its expiry entry behind forever, and the sweep would retry a delete every minute for a rule that is already gone. Listing rules needs no elevation, so this never raises a UAC prompt at startup
- Settings stored machine-wide in `%ProgramData%\NetworkSentinel\settings.json` — shared by the GUI, TUI, and the web service (which runs as SYSTEM); falls back to `%LocalAppData%` if ProgramData is not writable
- **Run as Admin** when elevation is required

### Firewall Config — the whole host firewall (rebuilt in 0.7.4)

A **Firewall Config** page under *Firewall & Block* (and a tab in the web console) that adds, edits and deletes inbound and outbound rules, shaped like the Linode Cloud Manager firewall page (and [FireWallConfig](https://github.com/davidfweiser/FireWallConfig) on Ubuntu): one list per direction, Label / Action / Protocol / Port range / Sources, one form for both add and edit, and labels minted from the port's service (`block-inbound-rdp`) when you leave the field blank.

Rules are written as ordinary `NetworkSentinel-Rule-*` Windows Firewall rules, so they apply system-wide, show up in `wf.msc`, and appear in every one of this app's rule lists.

**Since 0.7.4 the page reads the host firewall rather than this app's own rules.** Until then it listed the `NetworkSentinel-*` rules and nothing else, which on a real Windows box is a handful of rows sitting beside a firewall holding well over a thousand — Windows' own **Core Networking** and **File and Printer Sharing** groups, every installer that ever asked for an exception, and whatever a `netsh` line in a setup script left behind. One machine has one firewall; the page now shows all of it, named after the host:

| Source | Read with |
|---|---|
| **Rules** | `netsh advfirewall firewall show rule name=all verbose` — verbose because *Grouping*, *Program* and *Service* are what "who wrote this" is read from |
| **Profiles** | `netsh advfirewall show allprofiles` and `show currentprofile` — both default actions, and which profile is in force |
| **Listeners** | the same IP Helper tables the monitor already polls, so no second inventory of the machine can disagree with the first |

None of those reads needs elevation, which is the one place Windows is kinder than the Linux build: the rule list is complete whether or not you are running as Administrator, and only writing needs UAC.

**Created by** names the rule's group (`Core Networking`, `Microsoft Teams`), or the program it is scoped to when it has no group, or the service, or `Local rule` for one typed in by hand. Store-app rules carry a package identity where a name should be — `@{Microsoft.People_10.2202.100.0_x64__8wekyb3d8bbwe?ms-resource://…}` — so the package name is lifted out of it; every other rule keeps the name `wf.msc` shows.

**Disabled rules are counted, not listed.** They are configuration, not enforcement, and listing them beside the rules in force would describe a firewall this host is not running. The summary line says how many were left out.

**Identical rules are folded into one row and counted.** Windows does not stop a setup script adding its rule on every run: the machine this was written on holds 685 rules called `allow 9009`. One row marked `×685` says so, and deleting it removes every copy — which is the point, but not something to discover afterwards, so the confirmation says it too.

**The profile is part of that fold (0.7.5).** Windows stores its built-in groups once per profile — *File and Printer Sharing* for Domain and again for Private,Public, *Cast to Device* three times over — identical in every field a rule list displays. They used to arrive as separate rows that nothing could tell apart: the web console drew each one twice, the iOS app's list logged duplicate row identities, and a delete aimed at either was refused as ambiguous, because a rule is addressed by the shape it shows and the shape was the same. They fold into one row now, carrying the union of the profiles they came from, and a row live on less than the whole machine says which profiles those are. Nothing is hidden by the fold: a delete already filtered on the fields the row shows and no profile, so it always took every copy.

A rule's identity gained its program and service at the same time, for the same reason: those the fold *does* keep apart, so they have to be visible to whatever addresses a row. One rule admitting `svchost` and one admitting `System` are two rules and are now two addressable rules.

**A Program column, because the field that separates those rows was the one nothing displayed.** Identity knew about the program; the table did not show it, so rules the fold had correctly kept apart still arrived as rows identical in every visible column — same label, action, protocol, ports, sources and *Created by* — and read as duplicates of one another. The machine this was written on holds 21 `Microsoft Edge (mDNS-In)` rules, one per retained EdgeWebView version, and a `Steam Web Helper` pair split across `cef.win64` and `cef.win7x64`; all of them collapse to the same *Created by* text. The column shows the executable (or the Windows service, or `Any`), **trimmed from the left** — colliding paths share a long prefix and differ at the tail, so trimming the usual way would keep precisely the half that is the same on every row. Hovering gives the full path, because no column width disambiguates every case: two build outputs under different configurations still agree on their last two segments. On that host it takes the rule list from 72 groups of look-alike rows down to nothing but genuine duplicates, which is what the `×N` fold is for.

**Listening services.** Under the two rule lists, what is actually listening — protocol, bind address, port, service name, owning process — with the verdict the rules above pass on it: **Open** (an allow rule admits it from anywhere), **Restricted** (admitted only from named addresses, e.g. `LocalSubnet`), **Blocked** (a block rule covers it, and Windows evaluates blocks first), **Local only** (bound to loopback), **Not allowed** (listening into a closed door), **No firewall**. Every socket is listed separately, so a service like NetBIOS shows its rows on `0.0.0.0`, the LAN address and the broadcast address rather than one collapsed entry.

Three things decide whether a rule counts towards that verdict, and each of them was a wrong answer before it was handled:

- **Address scope.** A block rule scoped to one address closes that address, not the port. Auto-block writes one rule per attacker, so reading those as "this port is blocked" marked every socket on the machine Blocked.
- **Program and service scope.** A rule scoped to a program only admits that program's sockets, matched by image name; a rule scoped to a Windows service is credited to a service host, since which service inside `svchost.exe` owns a socket is not visible from here.
- **Store-app rules.** Windows scopes those to a package SID, which `netsh` does not print — the row names no program, no service and no port. Reading them as "every socket" marked all 159 listeners on a live host **Open**, SMB and RDP included, so a foreign rule with none of the three is not credited to anything.

**New rule** on a listener row opens the editor with that socket's protocol and port already filled in. The bind address deliberately does *not* carry into Sources: that field matches the far end of a connection, so seeding it with `0.0.0.0`, `::` or this host's own LAN address would write a rule that matches nothing an attacker sends. The editor note says so on the spot.

**Editing a rule this app did not write** deletes it and writes the new values as a `NetworkSentinel-Rule-*` rule — Windows has no edit-in-place for somebody else's rule, and rewriting one under its own name would leave two rules claiming it. If the delete fails the save stops rather than leaving both in force. Deletes name the rule's whole shape (direction, protocol, both port fields, remote addresses, program), because Windows rule names are not unique and a delete by name alone would take the neighbours with it.

**The scan is cached.** The web console polls `/api/state` every 2.5 s, and shelling out to `netsh` twice at that rate would be absurd; the host firewall rides on its own endpoint (`/api/hostfirewall`), fetched when the tab is opened, invalidated by any write, and re-read on demand by **Rescan the host firewall**. The desktop page runs the same scan off the UI thread with a *Scanning…* indicator.

**Precedence needs no work here, unlike the other builds.** Windows Firewall is not evaluated in creation order: it groups rules by type and evaluates connection-security rules, then authenticated bypass, then **block**, then **allow**, then the profile default. A block therefore beats an allow whichever was written first, so a config *Allow* can never reopen an address auto-block just shut. (The Linux build has to insert app blocks at the head of a first-match-wins chain to get the same guarantee.) The one rule type that *would* outrank a block is an authenticated bypass, and this page offers no way to author one.

What no rule can change is a **profile's default action** for traffic nothing matches — that is a per-profile setting in Windows Firewall (inbound blocked, outbound allowed on a stock install), and the page says so rather than implying an Allow rule is what grants access.

Other details:

- Blocking everything, or blocking inbound **RDP**, is **confirmed before it is written**.
- The **web console refuses** an inbound block that matches every source and covers its own port. The desktop app can ask you to confirm cutting the machine off; over the web the confirmation would travel down the connection being cut. Rules scoped to named addresses go through — the Firewall tab's *Block IP* already does exactly that.
- A rule the firewall rejects is **rolled back** instead of being left behind claiming to be in force.
- An unparseable port range is **rejected, not dropped**: validation runs before canonicalisation, because canonicalising first would turn a typo'd `443-80` into an empty port field — and an empty port field means *every port*.
- One rule usually needs exactly one firewall rule: `remoteip` takes a whole address list, IPv4 and IPv6 together. Two cases still split, because netsh rejects them outright — a port range under protocol *Any* becomes one TCP and one UDP rule, and ICMP becomes icmpv4 and icmpv6. Every fragment shares one rule name and is folded back together on read, so you see the one rule you wrote.

The navigation rail shows the running version — check it after an upgrade to confirm the new build is live. An open web console tab now says so itself: the page carries the build it was served from, and when the server reports a different one a banner offers a reload (it never reloads on its own — you may be mid-rule in the editor).

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
.\NetworkSentinel-windows-server-x64-0.7.13.install.cmd
# optional port:
.\NetworkSentinel-windows-server-x64-0.7.13.install.cmd -Port 18765
# unpack without installing:
.\NetworkSentinel-windows-server-x64-0.7.13.install.cmd --extract-only
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

Re-running the installer **upgrades in place**: it stops the running task, replaces the binaries, and restarts. `%ProgramData%\NetworkSentinel` is both the install folder and the data directory, so the installer removes **only the files the package ships** — the master password hash, settings, allowlist, logs, host history, threat log, `duckdns.json`, `tls\`, and `acme\` all survive. The web console's navigation rail shows the running version (e.g. `v0.7.13`) — check it after an upgrade to confirm the new build is live.

Uninstall keeps that same data by default so a reinstall picks up where you left off:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1
powershell -ExecutionPolicy Bypass -File .\uninstall-web-service.ps1 -PurgeData   # settings, certs, ACME account too
```

`-PurgeData` also deletes the Posh-ACME account, which cannot be recovered — a reinstall registers a new one, counting against Let's Encrypt's rate limits.

#### Web console layout

The console is laid out like the desktop window (0.7.4), because they are the same product and the menus should not be a different shape in each: a **230px navigation rail** on the left carrying the desktop's menu names and hierarchy — Firewall Config and Allowlist indented under **Firewall & Block**, Help under **Settings** — with a **STATUS** block pinned to its foot (monitor state, firewall privilege, and the **Enable auto-block** checkbox with the engine's own wording under it). To the right, the same hero header the desktop carries: clock, **Network Defense Console**, the `high/critical · blocked · auto-block` subtitle from the same three numbers, and the action row. Below ~900px the rail folds into a wrapping row above the content.

#### Web console tabs

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers) beside **Threat intensity**, **data-flow charts** (live in/out throughput, paired bars per day or per month) beside the running month's totals, **Monthly data in and out**, recent threats |
| **Live Connections / Break-in Attempts** | Live traffic with a **Block** button on every row |
| **Remote Computers** | Remote peers; block / unblock by row or by typed IP |
| **Open Ports** | Local listeners; one-click **Block port** |
| **Firewall & Block** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Firewall Config** (rebuilt 0.7.4) | The whole host firewall — Windows' own rules, Network Sentinel's, and everyone else's — plus listening services and their firewall verdict; add / edit / delete any of them |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, geo lookups, failed-logon monitoring, closed-port scan detection, the intrusion detectors (threat intel, new-listener, process reputation, ARP watch, startup-item watch, exfiltration, honeypot), **kernel flow events**, **DNS hygiene** (with approved resolvers), **DNS filtering** (resolver address, user and password), **WireGuard peer monitoring**, **Suricata signature ingestion** (EVE path), **auto-block dry run**, **HTTPS + DuckDNS remote access** (including **Issue certificate**), webhook alerts, auto-block + minimum severity + expiry, block direction (in/out), allowlist feed, **change master password**, **Remove all rules** |

The console protects itself: it refuses to remove its own firewall access rule, block its own port, or write a Firewall Config rule that would do the same (doing so would cut off your browser mid-request and look exactly like a crash).

A tab left open across an upgrade keeps its old markup — the page polls `/api/state` but never re-requests its own HTML, so no cache header can deliver the new UI, and the new features simply look absent. The page now carries the build it was served from, and when the server reports a different one a banner offers a reload. It never reloads on its own: you may be mid-rule in the Firewall Config editor.

#### Sleep / Wake

The first button in the web console's hero action row is a single **Sleep ⇄ Wake** toggle:

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

The app starts **without** forcing UAC (so TUI/web work on servers). Desktop install shortcuts are still marked **Run as administrator**. TUI key **`u`** and the web **Authorize** button relaunch elevated via UAC when firewall changes need it; the elevated TUI window is also where the [Settings view](#settings-from-the-terminal-079) is available. The web scheduled-task installer runs as **SYSTEM** (already elevated).

### Web UI security
- First browser visit **creates a master password** (min. 8 characters)
- Creating it from **another machine** additionally asks for a one-time **setup code**, printed where the console runs (the terminal, or the service log when it runs as a scheduled task). Without this, whoever reached the port first — the console binds all interfaces before any password exists — could claim the master password and with it firewall control. Setup from localhost needs no code
- Later visits require that password; change it under **Settings → Master password**
- Can't reach a browser yet (e.g. still opening the port in a cloud firewall), or lost the password? Set/reset it from the terminal instead — see below
- Hash stored as PBKDF2-SHA256 (random salt, 200k iterations) in `%ProgramData%\NetworkSentinel\web-master.json` — never plain text
- Session cookie until sign-out, browser close, or 12 hours idle
- Failed attempts are throttled **per client IP**: five wrong guesses trigger a lockout that doubles with each further attempt (1 minute up to 1 hour), answered with `429` and a `Retry-After`. A fixed delay alone only slows one connection at a time — this caps a parallel guesser

### HTTPS and remote access

The console is served by **Kestrel** rather than `HttpListener`. On Windows `HttpListener` *can* do TLS, but only against a certificate imported into the machine store and bound to the port with `netsh http add sslcert` — per-port, admin-only, and redone at every renewal. Kestrel reads the PEM or `.pfx` straight off disk, which is exactly what an ACME renewal rewrites. It also removes the `netsh http add urlacl` reservation that binding to all interfaces used to need, so the console no longer falls back to localhost-only when it isn't elevated.

HTTP and HTTPS are served side by side: the LAN keeps working on plain HTTP while requests that arrive **by hostname** are redirected to TLS — requests to a bare IP are left alone, since the certificate only covers the name and redirecting an IP would trade a working page for a certificate warning.

Once HTTPS works, **Settings → Remote access → HTTPS only** (0.7.7) turns the plain-HTTP listener off entirely, so the master password can never cross the wire in the clear — the strongest setting for a console reachable beyond localhost. Bare-IP visits then get a certificate warning but still connect encrypted. The switch is deliberately fail-open: it is honored only when the certificate actually loads at startup, so a broken or expired cert means the console falls back to plain HTTP (with a warning in the banner and on the settings page) instead of leaving you locked out. The setting is `"WebHttpsOnly": true` in `%ProgramData%\NetworkSentinel\settings.json`; like the other endpoint settings it is read when the console starts, so restart it to apply.

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
| **Settings** | **Text size** (how large this window draws), monitor poll interval, geo lookups, failed-logon monitoring, closed-port scan detection, **remote access (HTTPS + DuckDNS)**, allowlist feed, data folder |

### Settings from the terminal (0.7.9)

The TUI (`--tui`) could watch and block but not configure: every setting meant
reaching for the desktop window or the web console, neither of which is at hand on
a Server Core box or an RDP console you only ever meet remotely. **Settings** is the
eighth view — press `8` — and it carries the same catalogue the web console's
Settings tab does: monitoring and poll interval, every detector and its thresholds,
auto-block and its severity, direction, dry run and rule expiry, the webhook, and
the whole remote-access group — HTTPS, port, TLS paths, redirect, HTTPS-only,
DuckDNS, and Let's Encrypt issuance.

**It is locked unless the TUI is elevated.** The screen shows nothing — not even
current values — to an unelevated run: it writes the same `settings.json` the
desktop and web console read, and that is not something to leave open on a terminal
somebody walked away from. Press `u` to relaunch through UAC; **Settings opens in
that elevated window**, and the process you pressed it in stays locked, which is
right — it is the one that could not have applied the change anyway. Starting
Network Sentinel elevated skips the extra step.

**Enter is the only edit key.** It flips a toggle and cycles a choice in place;
anything that has to be typed opens a prompt below the display, seeded with the
current value. In that prompt **Enter alone keeps the value and `-` clears it** — on
a terminal, a stray Return must not silently empty a webhook URL. A rejected value
(a port out of range, a certificate path that does not exist) is reported in the
footer and **nothing is written**, so a bad entry cannot leave the file half changed.

Each change is pushed into the running service *and* saved, the way the web console
applies them, so a detector switched on here starts working without a restart. The
file is the same `%ProgramData%\NetworkSentinel\settings.json` the desktop and web
console read — but a console already running in another process keeps its in-memory
copy until it restarts.

Two rows go beyond what the web console offers: **Suricata max severity** and
**Muted Suricata signatures**. Both are settings the monitor already applies, and no
front-end on this platform exposed them — until now, hand-editing `settings.json`
was the only way to change them.

| Key | Action (Settings view) |
|-----|------------------------|
| `8` | Open Settings (`9` / `h` / `F1` is now Help) |
| `↑` `↓` / `j` `k` | Move between rows |
| `Enter` | Flip a toggle, cycle a choice, or open the edit prompt |
| `u` | Relaunch as Administrator — Settings opens in the new window |

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
| `Native/FlowEvents.cs` | Real-time ETW session on `Microsoft-Windows-Kernel-Network`; TDH schema-driven payload decoding |
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
| `Services/PreventionService.cs` | The single auto-block enforcement engine: gates, dry run, operator shield |
| `Services/SuricataService.cs` | Tails Suricata EVE JSON and converts alerts to threat events |
| `Services/WireGuardMonitor.cs` | WireGuard peer baseline, endpoint drift, per-peer transfer |
| `Services/WireGuardEndpointGuard.cs` / `IpsecEndpointGuard.cs` | Tunnel endpoints that must never be auto-blocked |
| `Services/TrafficMeterService.cs` | Adapter byte-counter sampling + daily history behind the data-flow charts |
| `Services/DnsHygieneMonitor.cs` | Plaintext/encrypted DNS, unapproved resolvers, allowlist resolution drift |
| `Services/DnsFilterService.cs` | The DNS filtering switch: AdGuard Home's status, protection and query log |
| `Services/DnsFilterSetup.cs` | Runs `setup-dns-filter.ps1` elevated for the switch, and reads back what it built |
| `scripts/setup-dns-filter.ps1` | Installs AdGuard Home as the filtering resolver for this node's tunnel clients; `-Uninstall` reverses it |
| `Services/HostHistoryStore.cs` | Persistent host + listener baseline, threat log |
| `Services/WebhookNotifier.cs` | ntfy / Slack / Discord / generic JSON alerts, each carrying the block verdict |
| `Services/DesktopNotifier.cs` | Critical Windows toasts, blocked-or-not in the title |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | Windows Firewall rule create/list/remove (netsh, cached rule list); auto-block expiry sweep; delete of a rule this app did not write |
| `Services/HostFirewallScan.cs` | Reads the whole host firewall — every rule, the profile defaults, and the listening sockets with the verdict the rules pass on them |
| `Services/FirewallRuleSpec.cs` | Firewall Config rule parsing, validation and netsh rendering (no privilege, no I/O) |
| `Services/AppSettings.cs` | Auto-block preferences + suppress list (JSON on disk) |
| `Services/DuckDnsUpdater.cs` | DuckDNS dynamic-DNS refresh loop; token file with an admins-only ACL |
| `Services/TlsCertificateProvider.cs` | Loads the console's PEM/`.pfx` and re-reads it after an ACME renewal |
| `Services/CertIssuanceService.cs` | Drives `issue-duckdns-cert.ps1` behind the **Issue certificate** button |
| `Services/LoginThrottle.cs` | Per-client-IP lockout for the console's password endpoints |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `ViewModels/MainViewModel.FirewallConfig.cs` / `.Traffic.cs` | Firewall Config page; data-flow chart series and legends |
| `Web/WebApp.cs` | Headless web console (Kestrel HTTP/HTTPS host + embedded single-page UI) |
| `Web/WebAuthStore.cs` | Master password hash + session tokens |
| `Web/WebTlsOptions.cs` | TLS values from the command line, overlaid on the saved settings |
| `scripts/issue-duckdns-cert.ps1` | Let's Encrypt DNS-01 issuance via Posh-ACME + renewal scheduled task |
| `scripts/diagnose-ipsec.ps1` | Read-only triage for a site-to-site tunnel that won't come up |
| `Tui/TuiApp.cs` | Terminal UI (Spectre.Console) |
| `Tui/TuiSettings.cs` | The TUI Settings catalogue — one list of editable settings, applied and saved the way the web console applies them |
| `MainWindow.xaml` | Dashboard UI |
| `Themes/` | Colors and control styles |
| `Controls/Sparkline.cs` | Live activity chart |
| `Controls/TrafficChart.cs` | Dual sparkline + paired bar chart for the data-flow cards |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Scan/brute-force heuristics count **new inbound connections to ports this PC is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing. The only outbound rule is the beacon detector, which requires a regular cadence to an uncommon port on a public IP.
- Public IP geolocation uses the free `ipwho.is` endpoint, falling back to `ipapi.co` only if that fails — **both over HTTPS** (0.7.7), so the peer IPs this app observes never cross the wire in cleartext (the fallback was previously plain-HTTP `ip-api.com`). Both are rate-limited and best-effort. Toggle lookups off in **Settings** (desktop app or web console), or set `"GeoLookupEnabled": false` in `%ProgramData%\NetworkSentinel\settings.json`; reverse DNS still runs. LAN/private addresses are labeled as local.
- **Failed-logon detection** subscribes to the Windows Security event log (4625 / 4771), which requires Administrator or membership in the local **Event Log Readers** group. Without it the app keeps running and shows why under **Settings → Failed-logon monitoring**; set `"AuthLogMonitorEnabled": false` to turn the feature off. The web service runs as SYSTEM, so it always has access.
- **Closed-port scan detection** is off by default because it turns on Windows Firewall **dropped-packet logging** (a firewall setting, not a rule — nothing extra is blocked or allowed). Enable it under **Settings → Closed-port scan detection** while elevated, or set `"ProbeLogEnabled": true`. The watcher tails `%windir%\System32\LogFiles\Firewall\pfirewall.log` (readable by Administrators/SYSTEM), counts pure SYNs only, and the toggle turns the logging back off.
- **Monitor poll interval** (desktop **Settings**, default 1.2 s, `"MonitorPollMs"`) is also the activity-chart sample rate, so a slower interval widens the window the chart covers rather than thinning it.
- The allowlist remote feed can likewise be toggled in **Settings** or via `"AllowlistUseRemoteFeed": false` in the same file.
- **Traffic metering** samples the adapter byte counters for the data-flow charts and the monthly history in `traffic-history.json`. On by default (unprivileged and cheap); turn it off in **Settings → Traffic metering** or with `"TrafficMeterEnabled": false`, which keeps the history but stops it growing.
- **Threat-intel feeds** download FireHOL level1 and Spamhaus DROP once a day to `threat-intel-cache.json` and fall back to the cache when offline; turn them off with `"ThreatIntelEnabled": false`.
- The **honeypot** is off by default because it binds real ports — enable it under **Settings → Honeypot decoy ports** once you have confirmed the chosen ports are free. The decoy sockets bind exclusively, so a port already served by a real service is skipped rather than hijacked.
- The **exfiltration monitor** enables per-connection TCP ESTATS counters, which requires Administrator. Unelevated it reports itself unavailable and stays quiet; the web service (SYSTEM) is unaffected.
- **Connected UDP peers** are not tracked on Windows: the UDP table exposes only the local endpoint and owning PID, with no peer address for a connected socket (Linux reads it from `/proc/net/udp`). UDP **listeners** are still enumerated and still classify inbound traffic.
- If the app ever exits unexpectedly, check `%ProgramData%\NetworkSentinel\logs\crash.log` — unhandled errors are logged there with a stack trace.
- Some system sockets may show as `System` or `PID n` depending on permissions.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by the firewall.
- A port that shows `LISTEN` locally but is unreachable from outside is usually a **network** firewall, not this app: on a cloud VM (Azure, AWS, …) the provider's security group can drop inbound traffic before it reaches the host. Open the port there too.

---

## A site-to-site tunnel that won't come up

```powershell
powershell -ExecutionPolicy Bypass -File scripts\diagnose-ipsec.ps1 203.0.113.7   # the peer's public address
```

Run it from an **elevated** prompt. Read-only, takes about 25 s, changes nothing. It answers three questions in order: **is this host blocking the peer or the IKE ports**, **is the peer's traffic arriving at all and from which address**, and **what does Windows say about the negotiation**. Where that lands tells you which of these it is:

| What the script shows | What it means |
|---|---|
| A firewall rule naming the peer | This host blocked it. Allowlist the address (TUI `n`, or the web console's Allowlist tab) — that also removes the rule. A plain unblock only suppresses re-blocking for 24 h, so the tunnel would drop again tomorrow |
| No local rule, and **no packets captured** | Nothing is reaching the box, so the drop is upstream. On a cloud VM this is nearly always the **provider's** security group, which is invisible from inside the machine — see the note below |
| Packets arriving from a **different address** than the configuration names | The far end's WAN address changed. Classic on a dynamic residential line, and it looks exactly like a failure with no cause: worked for months, then stopped, nobody touched either end |
| Packets from the right address, IKE still failing | A negotiation problem — the IPsec audit and IKEEXT events name it (auth failure, proposal mismatch, no matching peer) |

**On a cloud VM, check the provider firewall first.** IPSec needs **UDP 500** (IKE) and **UDP 4500** (NAT-T) inbound, and these are not open by default. Two traps here:

- **Some providers cannot express ESP at all.** Where the security group offers only TCP, UDP and ICMP, raw protocol 50 can never be allowed. If IKE completes but no traffic crosses the tunnel, force UDP encapsulation so ESP travels inside UDP 4500.
- **A peer on a dynamic address outgrows a pinned rule.** Scoping the source to the peer's `/32` is the right instinct, but every ISP rotation then breaks the tunnel until someone edits both the provider firewall *and* the local configuration. Identify the peer by certificate or a strong PSK instead and the address stops mattering — the provider rule still has to widen to all sources, so the authentication is doing the work the address filter used to.

**This app never auto-blocks a tunnel endpoint** — see [The same shield for IPSec](#the-same-shield-for-ipsec-including-site-to-site). If the script does find a rule naming your peer, it was a manual block or predates the shield.

---

## License

Private project — all rights reserved unless you add a license file later.
