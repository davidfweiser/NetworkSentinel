---
description: Inspect and configure NetworkSentinel's automatic blocking mode
argument-hint: "[desired settings, e.g. 'enable, min level Critical, dry run'] (omit to report only)"
---

Set up NetworkSentinel's **auto-block (prevention) mode**.

Requested change: $ARGUMENTS

If the line above is empty, this is a **report-only** run: describe the current
state and stop without editing anything.

## 1. Read the current state

Settings are the `AutoBlock*` / prevention properties on
`Services/AppSettings.cs`, persisted as JSON at
`$XDG_DATA_HOME/NetworkSentinel/settings.json` (falling back to
`~/.local/share/NetworkSentinel/settings.json`, then `LocalApplicationData`) —
see `Services/AppPaths.cs`. The file is written owner-only because it can hold
the `.pfx` password and webhook URL; do not print secrets from it.

Report the effective values of:

| Setting | Meaning |
| --- | --- |
| `AutoBlockEnabled` | master switch (default off) |
| `AutoBlockMinLevel` | minimum `ThreatLevel` that can trigger a block (default `High`) |
| `AutoBlockInbound` / `AutoBlockOutbound` | which directions get rules |
| `PreventionDryRun` | decide and report, but write no firewall rules |
| `AutoBlockExpiryMinutes` | lifetime of auto-created rules (0 = never expire) |
| `AutoBlockSuppressedUntil` | per-IP suppression after a manual unblock (count only, not the list) |

Read the settings file if it exists; if it does not, say so and report the
defaults from `AppSettings` rather than inventing a state.

## 2. Understand what the settings gate

`Services/PreventionService.cs` is the single decision engine shared by GUI, TUI
and web. A threat must clear every gate, cheapest first:

> severity ≥ `MinLevel` → not informational-only → routable public IP → not
> allowlisted → not this machine's own address → not a protected tunnel endpoint
> → not operator-protected → not already blocked → not suppressed by a manual
> unblock → not attempted within `RetryAfter`.

Relevant collaborators:

- `Services/FirewallService.cs` — writes the actual nft/iptables rules; needs
  elevation. Outside dry-run, `IsAdministrator` must be true or nothing blocks.
- `Services/AllowlistService.cs` — local + built-in + optional remote GitHub
  feed (`AllowlistUseRemoteFeed`).
- `Services/WireGuardEndpointGuard.cs` and `Services/IpsecEndpointGuard.cs` —
  shield the public addresses that VPN tunnels are anchored to, so enabling
  auto-block cannot cut the operator's own site-to-site link. Wired in via
  `PreventionService.IsProtectedAddress`.

Call out any interaction that makes the requested change riskier than it looks —
especially enabling `AutoBlockOutbound`, lowering `AutoBlockMinLevel` below
`High`, or turning off dry-run on a host reachable only over a VPN tunnel.

## 3. Apply the change

Only when settings were requested:

- Prefer promoting a new or noisy detection source through `PreventionDryRun`
  first — watch what it *would* have dropped before it drops anything.
- Edit `settings.json` in place, preserving unrelated keys and the owner-only
  (0600) file mode. Do **not** hand-edit defaults into `AppSettings.cs` to
  change runtime behaviour; that file defines defaults, not the live config.
- A running instance loads settings at startup — say plainly that the app needs
  a restart (or the equivalent in-app toggle) for the change to take effect.
- Re-read the file afterwards and report the resulting values.

## 4. Verify

Run the prevention tests and report the real output, pass or fail:

```
dotnet test Tests/NetworkSentinel.Tests --filter "FullyQualifiedName~Prevention|FullyQualifiedName~EndpointGuard"
```

Finish with a short summary: what changed, what it now blocks, and anything left
undone.
