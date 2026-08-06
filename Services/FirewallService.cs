using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Manages host firewall rules owned by Network Sentinel on Linux via nftables
/// (preferred) or iptables. The GUI always runs as the normal user; privileged
/// commands are elevated per-call with pkexec/sudo so Wayland/X11 never has to
/// run Avalonia as root (which fails with XOpenDisplay).
/// </summary>
public sealed class FirewallService
{
    public const string RulePrefix = "NetworkSentinel";
    public const string ProbeLogRuleName = "NetworkSentinel-ProbeLog";
    public const string ProbeLogPrefix = "NS-PROBE ";
    private const string NftTable = "inet networksentinel";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public AllowlistService? Allowlist { get; set; }

    /// <summary>True when euid is root (rare; GUI should not run as root on Wayland).</summary>
    public bool IsRoot
    {
        get
        {
            try { return geteuid() == 0; }
            catch { return false; }
        }
    }

    /// <summary>True when firewall changes can be attempted (root or elevatable via pkexec/sudo).</summary>
    public bool IsAdministrator => IsRoot || CanElevate;

    public bool CanElevate => CommandExists("pkexec") || CommandExists("sudo");

    public string PrivilegeText
    {
        get
        {
            if (IsRoot)
                return "Running as root — firewall rules can be applied directly.";
            if (CommandExists("pkexec"))
                return "Running as your user. Firewall changes will ask for your password (polkit/pkexec).";
            if (CommandExists("sudo"))
                return "Running as your user. Firewall changes use sudo (may prompt for a password in a terminal).";
            return "No elevation helper found (install pkexec or sudo) — firewall rules cannot be applied.";
        }
    }

    /// <summary>
    /// Expiry applied to auto-created block rules (null = permanent). Manual
    /// blocks are always permanent; auto-block passes this through.
    /// </summary>
    public TimeSpan? AutoBlockExpiry { get; set; }

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false, TimeSpan? expiresAfter = null)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (IsPrivateOrLocal(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        EnsureBackendReady();
        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: true, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: false, reason, expiresAfter);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Blocked {normalized} ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockIp(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        var inName = IpRuleName(normalized, true);
        var outName = IpRuleName(normalized, false);
        var r1 = RemoveRuleByName(inName);
        var r2 = RemoveRuleByName(outName);

        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No Network Sentinel block rules found for {normalized}.");

        return FirewallOperationResult.Ok($"Unblocked {normalized}. Removed managed inbound/outbound rules when present.");
    }

    public FirewallOperationResult BlockPort(int port, string protocol, FirewallDirection direction = FirewallDirection.Inbound, string? reason = null)
    {
        if (port is < 1 or > 65535)
            return FirewallOperationResult.Fail("Port must be between 1 and 65535.");

        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (protocol is not ("TCP" or "UDP"))
            return FirewallOperationResult.Fail("Protocol must be TCP or UDP.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        EnsureBackendReady();
        var results = new List<string>();
        var ok = true;

        if (direction is FirewallDirection.Inbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: true, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsurePortRule(port, protocol, isInbound: false, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        return ok
            ? FirewallOperationResult.Ok($"Port {protocol}/{port} blocked ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockPort(int port, string protocol)
    {
        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        var r1 = RemoveRuleByName(PortRuleName(port, protocol, true));
        var r2 = RemoveRuleByName(PortRuleName(port, protocol, false));
        if (!r1.Success && !r2.Success)
            return FirewallOperationResult.Fail($"No managed port rules for {protocol}/{port}.");

        return FirewallOperationResult.Ok($"Removed managed rules for {protocol}/{port}.");
    }

    public FirewallOperationResult RemoveRule(string ruleName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

            if (!IsAdministrator)
                return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

            var name = ruleName.Trim();

            // Blocks are created as an -In/-Out pair. Removing only the clicked row left
            // the sibling active, so the IP stayed blocked and remove "didn't work".
            var siblings = new List<string> { name };
            if (name.EndsWith("-In", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-In".Length] + "-Out");
            else if (name.EndsWith("-Out", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-Out".Length] + "-In");

            var removed = new List<string>();
            string? firstError = null;
            foreach (var sibling in siblings)
            {
                var r = RemoveRuleByName(sibling);
                if (r.Success)
                    removed.Add(sibling);
                else if (sibling == name)
                    firstError = r.Message;
            }

            if (removed.Count == 0)
                return FirewallOperationResult.Fail(firstError ?? $"No rule named \"{name}\".");

            return FirewallOperationResult.Ok(removed.Count > 1
                ? $"Removed inbound + outbound rules ({removed[0]} and its pair)."
                : $"Removed \"{removed[0]}\".");
        }
        catch (Exception ex)
        {
            // Never let firewall backend failures tear down the web host process.
            return FirewallOperationResult.Fail($"Remove failed: {ex.Message}");
        }
    }

    /// <param name="skip">Rules to leave in place (kept for API parity with the Windows build).</param>
    public FirewallOperationResult RemoveAllManagedRules(Func<FirewallRuleInfo, bool>? skip = null)
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        var rules = GetManagedRules().ToList();
        int removed = 0;
        int kept = 0;
        foreach (var rule in rules)
        {
            if (skip != null && skip(rule))
            {
                kept++;
                continue;
            }
            if (RemoveRuleByName(rule.Name).Success)
                removed++;
        }

        if (kept == 0)
        {
            if (BackendIsNft())
                RunPrivileged("nft", $"flush table {NftTable}");
            SaveLedger(new List<FirewallRuleInfo>());
        }

        var msg = $"Removed {removed} Network Sentinel firewall rule(s).";
        if (kept > 0)
            msg += $" Kept {kept}.";
        return FirewallOperationResult.Ok(msg);
    }

    /// <summary>
    /// Best-effort IP from a managed rule name or remote field (for auto-block suppress after Remove).
    /// </summary>
    public static bool TryExtractIpFromManagedRule(string? ruleName, string? remoteAddresses, out string ip)
    {
        ip = "";
        if (!string.IsNullOrWhiteSpace(remoteAddresses) &&
            TryNormalizeIp(remoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault(), out ip, out _))
            return true;

        if (string.IsNullOrWhiteSpace(ruleName))
            return false;

        // NetworkSentinel-IP-1.2.3.4-In  or  NetworkSentinel-IP-2001_db8__1-Out
        var m = Regex.Match(ruleName.Trim(),
            @"^NetworkSentinel-IP-(.+)-(In|Out)$",
            RegexOptions.IgnoreCase);
        if (!m.Success)
            return false;

        var raw = m.Groups[1].Value.Replace('_', ':');
        return TryNormalizeIp(raw, out ip, out _);
    }

    public FirewallOperationResult UnblockAllowlistedAddresses()
    {
        if (Allowlist == null)
            return FirewallOperationResult.Fail("Allowlist is not available.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to remove firewall rules.");

        var rules = GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock).ToList();
        int removed = 0;
        var notes = new List<string>();

        foreach (var rule in rules)
        {
            var remote = rule.RemoteAddresses;
            if (string.IsNullOrWhiteSpace(remote)) continue;
            if (!Allowlist.IsAllowed(remote, out var why)) continue;

            if (RemoveRuleByName(rule.Name).Success)
            {
                removed++;
                notes.Add($"{remote} ({why})");
            }
        }

        if (removed == 0)
            return FirewallOperationResult.Ok("No allowlisted IPs were blocked by Network Sentinel rules.");

        return FirewallOperationResult.Ok(
            $"Restored {removed} allowlisted address(es): {string.Join("; ", notes.Take(12))}" +
            (notes.Count > 12 ? "…" : ""));
    }

    public IReadOnlyList<FirewallRuleInfo> GetManagedRules()
    {
        var ledger = LoadLedger();
        return ledger
            .OrderBy(r => r.Kind)
            .ThenBy(r => r.RemoteAddresses)
            .ThenBy(r => r.LocalPorts)
            .ThenBy(r => r.Direction)
            .ToList();
    }

    public bool IsIpBlocked(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out _))
            return false;

        return GetManagedRules().Any(r =>
            r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired &&
            string.Equals(r.RemoteAddresses, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public HashSet<string> GetBlockedIps()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock && !r.IsExpired))
        {
            if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses))
                set.Add(rule.RemoteAddresses);
        }
        return set;
    }

    /// <summary>
    /// Installs a rate-limited kernel log rule for new inbound TCP SYNs in the
    /// managed table. Probes to CLOSED ports are answered with a RST before
    /// they ever appear in /proc/net, so connection polling cannot see them —
    /// this rule makes them visible via the kernel log at near-zero cost
    /// (in-kernel match, one log line per probe, capped at 50/second).
    /// </summary>
    public FirewallOperationResult EnableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        // Everything below runs in ONE elevated shell: creating the table/chains,
        // clearing any stale probe rule, and adding the new one. As separate
        // RunPrivileged calls this cost four consecutive password dialogs.
        FirewallOperationResult applied;
        if (BackendIsNft())
        {
            var nft = ResolveExecutable("nft") ?? "nft";
            var script =
                $"set -u; NFT={Sh(nft)}; T={Sh(NftTable)};\n" +
                "\"$NFT\" add table $T 2>/dev/null || true;\n" +
                "\"$NFT\" add chain $T input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true;\n" +
                "\"$NFT\" add chain $T output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true;\n" +
                // Drop any previous probe rule so re-enabling cannot stack duplicates.
                $"for h in $(\"$NFT\" -a list table $T 2>/dev/null | awk '/{ProbeLogRuleName}/{{for(i=1;i<=NF;i++) if($i==\"handle\") print $(i+1)}}'); do\n" +
                "  \"$NFT\" delete rule $T input handle \"$h\" 2>/dev/null || true;\n" +
                "done;\n" +
                $"\"$NFT\" add rule $T input tcp flags '&' '(syn|ack)' == syn ct state new " +
                $"limit rate 50/second log prefix {ShNftString(ProbeLogPrefix)} " +
                $"comment {ShNftString(ProbeLogRuleName)}\n";

            var r = RunPrivilegedBatch(script);
            applied = r.Success
                ? FirewallOperationResult.Ok("Probe logging enabled (nftables).")
                : FirewallOperationResult.Fail($"Failed to add probe log rule: {r.Message}");
        }
        else
        {
            var ipt = ResolveExecutable("iptables") ?? "iptables";
            // -D with the identical spec is the idempotent delete for iptables.
            var spec =
                $"-p tcp --syn -m conntrack --ctstate NEW -m limit --limit 50/sec " +
                $"-j LOG --log-prefix {Sh(ProbeLogPrefix)} -m comment --comment {Sh(ProbeLogRuleName)}";
            var script =
                $"set -u; IPT={Sh(ipt)};\n" +
                $"\"$IPT\" -D INPUT {spec} 2>/dev/null || true;\n" +
                $"\"$IPT\" -A INPUT {spec}\n";

            var r = RunPrivilegedBatch(script);
            applied = r.Success
                ? FirewallOperationResult.Ok("Probe logging enabled (iptables).")
                : FirewallOperationResult.Fail($"Failed to add probe log rule: {r.Message}");
        }

        if (applied.Success)
        {
            UpsertLedger(new FirewallRuleInfo
            {
                Name = ProbeLogRuleName,
                Description = "Logs new inbound TCP SYNs (rate-limited) so scans of closed ports are detectable",
                Enabled = true,
                IsBlock = false,
                Direction = FirewallDirection.Inbound,
                RemoteAddresses = "",
                LocalPorts = "",
                Protocol = "TCP",
                Kind = FirewallRuleKind.Other
            });
        }

        return applied;
    }

    public FirewallOperationResult DisableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        // One prompt here too — the nft path otherwise costs a list plus a delete each.
        FirewallOperationResult r;
        if (BackendIsNft())
        {
            var nft = ResolveExecutable("nft") ?? "nft";
            r = RunPrivilegedBatch(
                $"set -u; NFT={Sh(nft)}; T={Sh(NftTable)};\n" +
                $"for h in $(\"$NFT\" -a list table $T 2>/dev/null | awk '/{ProbeLogRuleName}/{{for(i=1;i<=NF;i++) if($i==\"handle\") print $(i+1)}}'); do\n" +
                "  \"$NFT\" delete rule $T input handle \"$h\" 2>/dev/null || true;\n" +
                "done\n");
        }
        else
        {
            var ipt = ResolveExecutable("iptables") ?? "iptables";
            r = RunPrivilegedBatch(
                $"set -u; IPT={Sh(ipt)};\n" +
                $"\"$IPT\" -D INPUT -p tcp --syn -m conntrack --ctstate NEW -m limit --limit 50/sec " +
                $"-j LOG --log-prefix {Sh(ProbeLogPrefix)} -m comment --comment {Sh(ProbeLogRuleName)} 2>/dev/null || true\n");
        }

        RemoveFromLedger(ProbeLogRuleName);
        return r.Success
            ? FirewallOperationResult.Ok("Probe logging disabled.")
            : r;
    }

    public bool IsProbeLoggingInstalled()
        => GetManagedRules().Any(r => string.Equals(r.Name, ProbeLogRuleName, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Pre-authorize elevation with a no-op privileged command so the first real
    /// block does not surprise the user. Does NOT relaunch the GUI as root.
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (IsRoot)
            return FirewallOperationResult.Ok("Already running as root.");

        if (!CanElevate)
            return FirewallOperationResult.Fail(
                "No elevation helper found. Install policykit-1 (pkexec) or sudo.");

        // Touch a harmless privileged read — triggers polkit/sudo password once.
        var probe = BackendIsNft()
            ? RunPrivileged("nft", "list tables")
            : RunPrivileged("iptables", "-L -n");

        if (probe.Success)
            return FirewallOperationResult.Ok(
                "Authorization OK. Firewall changes can proceed (you may be prompted again after a while).");

        return FirewallOperationResult.Fail(
            "Elevation failed or was cancelled. " + probe.Message +
            "\n\nDo not run the whole app with sudo on Wayland — that breaks the display " +
            "(XOpenDisplay). Run as your user and let pkexec prompt for password.");
    }

    [Obsolete("GUI must not restart as root on Wayland. Use AuthorizeElevation() instead.")]
    public void RestartAsAdministrator()
    {
        // Kept for API compatibility — elevates in-place rather than relaunching GUI.
        var result = AuthorizeElevation();
        if (!result.Success)
            throw new InvalidOperationException(result.Message);
    }

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason, TimeSpan? expiresAfter = null)
    {
        var name = IpRuleName(ip, isInbound);
        RemoveRuleByName(name);

        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";
        FirewallOperationResult applied;

        if (BackendIsNft())
        {
            var chain = isInbound ? "input" : "output";
            var match = isInbound ? $"ip saddr {ip}" : $"ip daddr {ip}";
            if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                match = isInbound ? $"ip6 saddr {ip}" : $"ip6 daddr {ip}";

            var r = RunPrivileged("nft",
                $"add rule {NftTable} {chain} {match} counter drop comment \"{Escape(name)}\"");
            applied = r.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied (nftables).")
                : FirewallOperationResult.Fail($"Failed nft add {name}: {r.Message}");
        }
        else
        {
            // iptables is IPv4-only; an IPv6 address needs ip6tables or the rule is
            // rejected outright (and the block silently never happened).
            var isV6 = IPAddress.TryParse(ip, out var parsed) &&
                       parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            var tool = isV6 ? "ip6tables" : "iptables";
            if (isV6 && !CommandExists("ip6tables"))
                return FirewallOperationResult.Fail($"Cannot block IPv6 address {ip}: ip6tables is not installed (and nft is unavailable).");

            var table = isInbound ? "INPUT" : "OUTPUT";
            var flag = isInbound ? "-s" : "-d";
            var r = RunPrivileged(tool,
                $"-A {table} {flag} {ip} -j DROP -m comment --comment \"{Escape(name)}\"");
            applied = r.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied ({tool}).")
                : FirewallOperationResult.Fail($"Failed {tool} add {name}: {r.Message}");
        }

        if (applied.Success)
        {
            UpsertLedger(new FirewallRuleInfo
            {
                Name = name,
                Description = description,
                Enabled = true,
                IsBlock = true,
                Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
                RemoteAddresses = ip,
                LocalPorts = "",
                Protocol = "Any",
                Kind = FirewallRuleKind.IpBlock,
                ExpiresUtc = expiresAfter.HasValue ? DateTime.UtcNow + expiresAfter.Value : null
            });
        }

        return applied;
    }

    private FirewallOperationResult EnsurePortRule(int port, string protocol, bool isInbound, string? reason)
    {
        var name = PortRuleName(port, protocol, isInbound);
        RemoveRuleByName(name);
        var description = reason ?? $"Port blocked by Network Sentinel at {DateTime.Now:u}";
        var proto = protocol.ToLowerInvariant();
        FirewallOperationResult applied;

        if (BackendIsNft())
        {
            var chain = isInbound ? "input" : "output";
            var portMatch = isInbound ? $"dport {port}" : $"sport {port}";
            var r = RunPrivileged("nft",
                $"add rule {NftTable} {chain} {proto} {portMatch} counter drop comment \"{Escape(name)}\"");
            applied = r.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied (nftables).")
                : FirewallOperationResult.Fail($"Failed nft add {name}: {r.Message}");
        }
        else
        {
            var table = isInbound ? "INPUT" : "OUTPUT";
            var portFlag = isInbound ? "--dport" : "--sport";
            var r = RunPrivileged("iptables",
                $"-A {table} -p {proto} {portFlag} {port} -j DROP -m comment --comment \"{Escape(name)}\"");
            applied = r.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied (iptables).")
                : FirewallOperationResult.Fail($"Failed iptables add {name}: {r.Message}");
        }

        if (applied.Success)
        {
            UpsertLedger(new FirewallRuleInfo
            {
                Name = name,
                Description = description,
                Enabled = true,
                IsBlock = true,
                Direction = isInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
                RemoteAddresses = "",
                LocalPorts = port.ToString(),
                Protocol = protocol.ToUpperInvariant(),
                Kind = FirewallRuleKind.PortBlock
            });
        }

        return applied;
    }

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        bool removed = false;

        if (BackendIsNft())
        {
            var list = RunPrivileged("nft", $"-a list table {NftTable}");
            if (list.Success)
            {
                foreach (var handle in FindNftHandles(list.Message, name))
                {
                    if (RunPrivileged("nft", $"delete rule {NftTable} input handle {handle}").Success)
                        removed = true;
                    else if (RunPrivileged("nft", $"delete rule {NftTable} output handle {handle}").Success)
                        removed = true;
                }
            }
        }
        else
        {
            var tool = IptablesToolFor(name);
            removed |= DeleteIptablesByComment(tool, "INPUT", name);
            removed |= DeleteIptablesByComment(tool, "OUTPUT", name);
        }

        // Ledger is always updated so UI stays consistent even if kernel rule was already gone.
        var hadLedger = LoadLedger().Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        RemoveFromLedger(name);

        return removed || hadLedger
            ? FirewallOperationResult.Ok($"Removed “{name}”.")
            : FirewallOperationResult.Fail($"No rule named “{name}”.");
    }

    /// <summary>
    /// Which iptables-family binary owns a managed rule: IPv6 IP-block rules live in
    /// ip6tables, everything else in iptables. Keeps list/delete from prompting for
    /// elevation against a table the rule can't be in.
    /// </summary>
    private static string IptablesToolFor(string ruleName)
        => TryExtractIpFromManagedRule(ruleName, null, out var ip)
           && IPAddress.TryParse(ip, out var address)
           && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "ip6tables"
            : "iptables";

    private bool DeleteIptablesByComment(string tool, string table, string name)
    {
        var list = RunPrivileged(tool, $"-L {table} -n --line-numbers");
        if (!list.Success) return false;

        var lines = list.Message.Split('\n')
            .Where(l => l.Contains(name, StringComparison.Ordinal))
            .Select(l => l.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault())
            .Where(s => !string.IsNullOrEmpty(s) && int.TryParse(s, out _))
            .Select(s => int.Parse(s!))
            .OrderByDescending(n => n)
            .ToList();

        bool any = false;
        foreach (var num in lines)
        {
            if (RunPrivileged(tool, $"-D {table} {num}").Success)
                any = true;
        }
        return any;
    }

    private static IEnumerable<string> FindNftHandles(string dump, string comment)
    {
        foreach (var line in dump.Split('\n'))
        {
            if (!line.Contains(comment, StringComparison.Ordinal)) continue;
            var m = Regex.Match(line, @"#\s*handle\s+(\d+)");
            if (m.Success)
                yield return m.Groups[1].Value;
        }
    }

    private void EnsureBackendReady()
    {
        if (!BackendIsNft()) return;

        RunPrivileged("nft", $"add table {NftTable}");
        RunPrivileged("nft", $"add chain {NftTable} input {{ type filter hook input priority 0; policy accept; }}");
        RunPrivileged("nft", $"add chain {NftTable} output {{ type filter hook output priority 0; policy accept; }}");
    }

    private static bool? _backendNft;

    private static bool BackendIsNft()
    {
        if (_backendNft.HasValue) return _backendNft.Value;
        _backendNft = CommandExists("nft");
        return _backendNft.Value;
    }

    private static bool CommandExists(string name)
    {
        try
        {
            var psi = new ProcessStartInfo("which", name)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            p.WaitForExit(3000);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Runs a host-firewall tool, elevating with pkexec (preferred) or sudo when
    /// not already root. Never relaunches the Avalonia UI as root.
    /// </summary>
    private static FirewallOperationResult RunPrivileged(string file, string args)
    {
        if (geteuid() == 0)
            return RunDirect(file, args);

        // Resolve absolute path so pkexec/sudo can find the binary in secure PATH.
        var resolved = ResolveExecutable(file) ?? file;

        // Background sweeps take the cached-sudo path only — no dialogs.
        if (_silentElevationOnly)
        {
            return CommandExists("sudo")
                ? RunDirect("sudo", $"-n {Quote(resolved)} {args}")
                : FirewallOperationResult.Fail("No silent elevation available.");
        }

        // 1) pkexec — graphical polkit dialog, works under Wayland
        if (CommandExists("pkexec"))
        {
            var r = RunDirect("pkexec", $"{Quote(resolved)} {args}");
            if (r.Success || !LooksLikeMissingHelper(r.Message))
                return r;
        }

        // 2) sudo -n first (passwordless / already cached)
        if (CommandExists("sudo"))
        {
            var cached = RunDirect("sudo", $"-n {Quote(resolved)} {args}");
            if (cached.Success)
                return cached;

            // 3) Interactive sudo only if we have a TTY (rare for GUI)
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SUDO_ASKPASS")) ||
                !Console.IsInputRedirected)
            {
                var interactive = RunDirect("sudo", $"{Quote(resolved)} {args}");
                if (interactive.Success)
                    return interactive;
                return interactive;
            }

            return FirewallOperationResult.Fail(
                "Need admin rights for firewall changes. Install policykit-1 (pkexec) for a password dialog, " +
                "or configure passwordless sudo for nft/iptables. Do not start the GUI with plain sudo on Wayland.");
        }

        return FirewallOperationResult.Fail("No elevation helper (pkexec/sudo) available.");
    }

    /// <summary>
    /// Runs a whole sequence of privileged commands under a SINGLE elevation prompt.
    /// polkit's org.freedesktop.policykit.exec is <c>auth_admin</c> (not
    /// <c>auth_admin_keep</c>) on most desktops, so it caches nothing and every
    /// pkexec call raises its own password dialog. An operation built from several
    /// RunPrivileged calls therefore asked for the password several times, and
    /// answering only the first looked exactly like authentication failing.
    /// </summary>
    private static FirewallOperationResult RunPrivilegedBatch(string script)
    {
        if (geteuid() == 0)
            return RunDirectArgs("/bin/sh", "-c", script);

        if (CommandExists("pkexec"))
        {
            var r = RunDirectArgs("pkexec", "/bin/sh", "-c", script);
            if (r.Success || !LooksLikeMissingHelper(r.Message))
                return r;
        }

        if (CommandExists("sudo"))
        {
            var cached = RunDirectArgs("sudo", "-n", "/bin/sh", "-c", script);
            if (cached.Success)
                return cached;

            return FirewallOperationResult.Fail(
                "Need admin rights for firewall changes. Install policykit-1 (pkexec) for a password dialog, " +
                "or configure passwordless sudo for nft/iptables.");
        }

        return FirewallOperationResult.Fail("No elevation helper (pkexec/sudo) available.");
    }

    private static bool LooksLikeMissingHelper(string message)
        => message.Contains("not found", StringComparison.OrdinalIgnoreCase)
           || message.Contains("No such file", StringComparison.OrdinalIgnoreCase);

    private static string? ResolveExecutable(string name)
    {
        if (name.Contains('/')) return name;
        try
        {
            var psi = new ProcessStartInfo("which", name)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            var path = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(3000);
            return p.ExitCode == 0 && !string.IsNullOrWhiteSpace(path) ? path : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Same as <see cref="RunDirect"/> but passes argv entries individually, so
    /// shell metacharacters in an argument survive verbatim. Required for the
    /// batched elevation path, where the payload is a shell script.
    /// </summary>
    private static FirewallOperationResult RunDirectArgs(string file, params string[] argv)
    {
        var psi = new ProcessStartInfo(file);
        foreach (var a in argv)
            psi.ArgumentList.Add(a);
        return RunProcess(psi, file);
    }

    private static FirewallOperationResult RunDirect(string file, string args)
    {
        var psi = new ProcessStartInfo(file, args);
        return RunProcess(psi, file);
    }

    private static FirewallOperationResult RunProcess(ProcessStartInfo psi, string file)
    {
        try
        {
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;

            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail($"Could not start {file}.");

            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(30000);
            string combined = (stdout + "\n" + stderr).Trim();

            if (p.ExitCode == 0)
                return FirewallOperationResult.Ok(combined);
            if (combined.Contains("File exists", StringComparison.OrdinalIgnoreCase) ||
                combined.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Ok(combined);

            return FirewallOperationResult.Fail(string.IsNullOrWhiteSpace(combined)
                ? $"{file} exit code {p.ExitCode}"
                : combined);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
    }

    // ── Block expiry ─────────────────────────────────────────────────────

    private Timer? _expiryTimer;

    /// <summary>
    /// Starts the background sweep that removes expired block rules. Deleting
    /// an nft/iptables rule needs root, and pkexec raises a password dialog per
    /// call, so the sweep only acts when it can elevate silently (running as
    /// root, or sudo credentials are cached/passwordless). Otherwise the rule
    /// stays in the kernel but is already treated as lifted everywhere the UI
    /// looks — never a surprise password dialog from a timer.
    /// </summary>
    public void StartExpirySweep()
    {
        if (_expiryTimer == null)
        {
            // One-time startup pass, off the caller's thread: the ledger survives a
            // reboot but kernel rules don't, so reconcile before the first sweep.
            _ = Task.Run(() => ReconcileLedgerWithKernel());
        }
        _expiryTimer ??= new Timer(_ => TrySweepExpired(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Drops ledger entries whose kernel rule no longer exists. nft/iptables rules
    /// do not survive a reboot while firewall-rules.json does, so after a restart
    /// the app reported addresses as blocked — and the auto-block "already blocked"
    /// gate skipped re-blocking a still-active attacker — with no rule in the
    /// kernel. The same divergence appears when an admin flushes the firewall
    /// externally. Listing the live rules needs elevation, so this only acts when
    /// that can happen silently (root, or cached/passwordless sudo) — never a
    /// prompt from startup. When it can't, the ledger is left alone and the next
    /// process start retries.
    /// </summary>
    public FirewallOperationResult ReconcileLedgerWithKernel()
    {
        try
        {
            var ledger = LoadLedger();
            if (ledger.Count == 0)
                return FirewallOperationResult.Ok("Ledger empty — nothing to reconcile.");

            if (!CanElevateSilently())
                return FirewallOperationResult.Fail("Cannot list kernel rules without prompting — reconciliation skipped.");

            string dump;
            _silentElevationOnly = true;
            try
            {
                if (BackendIsNft())
                {
                    var list = RunPrivileged("nft", $"list table {NftTable}");
                    if (list.Success)
                    {
                        dump = list.Message;
                    }
                    else if (LooksLikeMissingTable(list.Message))
                    {
                        // The managed table is gone entirely — the post-reboot case.
                        // Every ledger entry is stale.
                        dump = "";
                    }
                    else
                    {
                        return FirewallOperationResult.Fail($"Could not list nft rules: {list.Message}");
                    }
                }
                else
                {
                    var input = RunPrivileged("iptables", "-L INPUT -n");
                    var output = RunPrivileged("iptables", "-L OUTPUT -n");
                    if (!input.Success || !output.Success)
                        return FirewallOperationResult.Fail("Could not list iptables rules — reconciliation skipped.");
                    dump = input.Message + "\n" + output.Message;

                    if (ledger.Any(r => IptablesToolFor(r.Name) == "ip6tables") && CommandExists("ip6tables"))
                    {
                        var input6 = RunPrivileged("ip6tables", "-L INPUT -n");
                        var output6 = RunPrivileged("ip6tables", "-L OUTPUT -n");
                        if (!input6.Success || !output6.Success)
                            return FirewallOperationResult.Fail("Could not list ip6tables rules — reconciliation skipped.");
                        dump += "\n" + input6.Message + "\n" + output6.Message;
                    }
                }
            }
            finally
            {
                _silentElevationOnly = false;
            }

            // Rule names carry an -In/-Out suffix, so no managed name is a prefix of
            // another and a plain containment test against the dump is exact enough.
            var stale = ledger.Where(r => !dump.Contains(r.Name, StringComparison.Ordinal)).ToList();
            if (stale.Count == 0)
                return FirewallOperationResult.Ok("Ledger matches kernel rules.");

            ledger.RemoveAll(r => stale.Any(s => string.Equals(s.Name, r.Name, StringComparison.OrdinalIgnoreCase)));
            SaveLedger(ledger);
            return FirewallOperationResult.Ok(
                $"Dropped {stale.Count} ledger entr{(stale.Count == 1 ? "y" : "ies")} with no matching kernel rule.");
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail($"Reconcile failed: {ex.Message}");
        }
    }

    private static bool LooksLikeMissingTable(string message)
        => message.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase)
           || message.Contains("does not exist", StringComparison.OrdinalIgnoreCase);

    private void TrySweepExpired()
    {
        try
        {
            var expired = LoadLedger().Where(r => r.IsExpired).ToList();
            if (expired.Count == 0) return;
            if (!CanElevateSilently()) return;

            _silentElevationOnly = true;
            try
            {
                foreach (var rule in expired)
                    RemoveRuleByName(rule.Name);
            }
            finally
            {
                _silentElevationOnly = false;
            }
        }
        catch
        {
            // sweep is best-effort; it simply retries next minute
        }
    }

    private static bool CanElevateSilently()
    {
        if (geteuid() == 0) return true;
        try
        {
            return CommandExists("sudo") && RunDirectArgs("sudo", "-n", "true").Success;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Set for the duration of the expiry sweep on the sweeping thread: makes
    /// <see cref="RunPrivileged"/> use cached sudo only, so a background timer
    /// can never pop a polkit dialog in the user's face.
    /// </summary>
    [ThreadStatic]
    private static bool _silentElevationOnly;

    // ── Rule ledger (JSON under XDG config) ──────────────────────────────

    private static string LedgerPath
        => Path.Combine(AppPaths.DataDirectory, "firewall-rules.json");

    private static List<FirewallRuleInfo> LoadLedger()
    {
        try
        {
            if (!File.Exists(LedgerPath)) return new List<FirewallRuleInfo>();
            var json = File.ReadAllText(LedgerPath);
            return JsonSerializer.Deserialize<List<FirewallRuleInfo>>(json, JsonOptions)
                   ?? new List<FirewallRuleInfo>();
        }
        catch
        {
            return new List<FirewallRuleInfo>();
        }
    }

    private static void SaveLedger(List<FirewallRuleInfo> rules)
    {
        try
        {
            AppPaths.WriteAtomic(LedgerPath, JsonSerializer.Serialize(rules, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    private static void UpsertLedger(FirewallRuleInfo rule)
    {
        var list = LoadLedger();
        list.RemoveAll(r => string.Equals(r.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
        list.Add(rule);
        SaveLedger(list);
    }

    private static void RemoveFromLedger(string name)
    {
        var list = LoadLedger();
        list.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        SaveLedger(list);
    }

    public static string IpRuleName(string ip, bool inbound)
        => $"{RulePrefix}-IP-{Sanitize(ip)}-{(inbound ? "In" : "Out")}";

    public static string PortRuleName(int port, string protocol, bool inbound)
        => $"{RulePrefix}-Port-{protocol.ToUpperInvariant()}-{port}-{(inbound ? "In" : "Out")}";

    private static string Sanitize(string value)
        => Regex.Replace(value, @"[^A-Za-z0-9.\-_]", "_");

    private static string Escape(string value)
        => value.Replace("\"", "'");

    private static string Quote(string path)
        => path.Contains(' ') ? $"\"{path}\"" : path;

    /// <summary>POSIX single-quoting for a value interpolated into a batched shell script.</summary>
    private static string Sh(string value)
        => "'" + value.Replace("'", "'\\''") + "'";

    /// <summary>
    /// Like <see cref="Sh"/>, but keeps literal double quotes around the value so
    /// nft's own parser still sees a quoted string. nft joins its argv back into one
    /// line and re-parses it, so a prefix like "NS-PROBE " (trailing space) has to
    /// arrive with its quotes intact or nft rejects the rule.
    /// </summary>
    private static string ShNftString(string value)
        => Sh("\"" + value + "\"");

    public static bool TryNormalizeIp(string? ip, out string normalized, out string error)
    {
        normalized = "";
        error = "";
        if (string.IsNullOrWhiteSpace(ip))
        {
            error = "IP address is empty.";
            return false;
        }

        ip = ip.Trim();
        if (ip.StartsWith('['))
        {
            var end = ip.IndexOf(']');
            if (end > 1)
                ip = ip[1..end];
        }
        else if (ip.Contains(':') && IPAddress.TryParse(ip, out _) == false)
        {
            var idx = ip.LastIndexOf(':');
            if (idx > 0 && ip.Count(c => c == ':') == 1)
                ip = ip[..idx];
        }

        if (!IPAddress.TryParse(ip, out var address))
        {
            error = $"Invalid IP address: {ip}";
            return false;
        }

        // ::ffff:a.b.c.d is how dual-stack sockets report IPv4 peers — rules and
        // bookkeeping should use the IPv4 form so both spellings mean one address.
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Drop any IPv6 zone id (fe80::1%eth0 parses fine but nft/ip6tables reject
        // it in a rule, and two zone spellings of one address must compare equal).
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes());

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);

    [DllImport("libc")]
    private static extern uint geteuid();
}

public enum FirewallDirection
{
    Inbound,
    Outbound,
    Both
}

public enum FirewallRuleKind
{
    IpBlock,
    PortBlock,
    Other
}

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Enabled { get; init; }
    public bool IsBlock { get; init; }
    public FirewallDirection Direction { get; init; }
    public string RemoteAddresses { get; init; } = "";
    public string LocalPorts { get; init; } = "";
    public string Protocol { get; init; } = "Any";
    public FirewallRuleKind Kind { get; init; }

    /// <summary>UTC time this rule stops applying (null = permanent). Set by auto-block expiry.</summary>
    public DateTime? ExpiresUtc { get; init; }

    public bool IsExpired => ExpiresUtc.HasValue && ExpiresUtc.Value <= DateTime.UtcNow;

    public string ExpiryText => ExpiresUtc.HasValue
        ? (IsExpired ? "Expired" : $"Expires {ExpiresUtc.Value.ToLocalTime():HH:mm}")
        : "Permanent";

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        _ => "Rule"
    };
    /// <summary>Best-effort IP target for display (falls back to parsing the rule name).</summary>
    public string AddressText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(RemoteAddresses) && RemoteAddresses is not ("Any" or "*"))
                return RemoteAddresses;
            var ipMatch = Regex.Match(
                Name,
                @"^NetworkSentinel-IP-(.+)-(In|Out)$",
                RegexOptions.IgnoreCase);
            if (ipMatch.Success)
                return ipMatch.Groups[1].Value.Replace('_', ':');
            return "";
        }
    }

    public string TargetText => Kind == FirewallRuleKind.IpBlock
        ? (string.IsNullOrWhiteSpace(RemoteAddresses) ? "—" : RemoteAddresses)
        : $"{Protocol}/{LocalPorts}";
    public string EnabledText => Enabled ? "On" : "Off";
    public string ActionText => IsBlock ? "Block" : "Allow";
}

public sealed class FirewallOperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = "";

    public static FirewallOperationResult Ok(string message) => new() { Success = true, Message = message };
    public static FirewallOperationResult Fail(string message) => new() { Success = false, Message = message };
}
