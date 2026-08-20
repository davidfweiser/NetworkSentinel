using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>One listening socket, with the verdict the firewall passes on it.</summary>
public sealed class HostListener
{
    public string Protocol { get; init; } = "TCP";
    public string Address { get; init; } = "";
    public string Port { get; init; } = "";
    public string Process { get; init; } = "—";
    public string State { get; init; } = "LISTEN";

    /// <summary>
    /// "Open", "Restricted", "Not allowed", "Local only" or "No firewall" — what
    /// the inbound rules do to traffic arriving here. A listener the firewall
    /// does not admit is not reachable, however loudly it is listening, and a
    /// listener nothing covers is the one worth knowing about.
    /// </summary>
    public string Covered { get; set; } = "Unknown";

    public string ServiceName =>
        int.TryParse(Port, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p)
            ? PortCatalog.GetHint(p, Protocol)
            : Port;
}

/// <summary>
/// The host firewall as one scan: the rules actually in the kernel, the default
/// policies, and what is listening behind them.
/// </summary>
public sealed class HostFirewallSnapshot
{
    /// <summary>The machine — the firewall is named after the host it protects.</summary>
    public string HostLabel { get; init; } = "";

    /// <summary>"UFW", "nftables", "iptables" or "none".</summary>
    public string Backend { get; init; } = "none";

    public string Status { get; init; } = "Unknown";
    public bool Enabled { get; init; }
    public string DefaultInbound { get; init; } = "Unknown";
    public string DefaultOutbound { get; init; } = "Unknown";
    public string Description { get; init; } = "";

    /// <summary>What could not be read, and what would fix it.</summary>
    public string PrivilegeNote { get; init; } = "";

    public IReadOnlyList<FirewallRuleInfo> Inbound { get; init; } = Array.Empty<FirewallRuleInfo>();
    public IReadOnlyList<FirewallRuleInfo> Outbound { get; init; } = Array.Empty<FirewallRuleInfo>();
    public IReadOnlyList<HostListener> Listeners { get; init; } = Array.Empty<HostListener>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> BackendsSeen { get; init; } = Array.Empty<string>();
    public DateTime ScannedUtc { get; init; } = DateTime.UtcNow;

    public string RulesSummary
    {
        get
        {
            var parts = new List<string>();
            if (Inbound.Count > 0) parts.Add($"{Inbound.Count} Inbound");
            if (Outbound.Count > 0) parts.Add($"{Outbound.Count} Outbound");
            return parts.Count > 0 ? string.Join(" · ", parts) : "No rules";
        }
    }

    /// <summary>Inbound rules that admit traffic — the ports genuinely open.</summary>
    public IReadOnlyList<FirewallRuleInfo> OpenPorts => Inbound.Where(r => !r.IsBlock).ToList();

    public static HostFirewallSnapshot Unreadable(string note, IReadOnlyList<string>? errors = null) => new()
    {
        HostLabel = Environment.MachineName,
        Backend = "none",
        Status = "Unknown",
        Description = "No UFW, nftables, or iptables rules could be read.",
        PrivilegeNote = note,
        Errors = errors ?? Array.Empty<string>()
    };
}

/// <summary>One backend's contribution, before the fold into a single firewall.</summary>
internal sealed class BackendRules
{
    public List<FirewallRuleInfo> Inbound { get; } = new();
    public List<FirewallRuleInfo> Outbound { get; } = new();
    public string DefaultInbound { get; set; } = "Accept";
    public string DefaultOutbound { get; set; } = "Accept";
    public bool Enabled { get; set; }
    public string Status { get; set; } = "Disabled";
    public bool Any => Inbound.Count > 0 || Outbound.Count > 0;
}

/// <summary>
/// Reads the host firewall the way
/// <see href="https://github.com/davidfweiser/FireWallConfig">FireWallConfig</see>
/// does, and for the same reason. The Firewall Config view used to list only
/// what this app had written itself, out of its own JSON ledger. On an Ubuntu
/// box that is a near-empty list sitting next to a firewall full of UFW rules —
/// and the rules Network Sentinel added were invisible to UFW in turn. One
/// machine has one firewall; this reads all of it.
///
/// Sources, folded in this order:
/// <list type="table">
/// <item><term>UFW</term><description><c>ufw status verbose</c>, falling back to <c>/etc/ufw/user.rules</c> when it cannot elevate</description></item>
/// <item><term>nftables</term><description><c>nft -j list ruleset</c></description></item>
/// <item><term>iptables</term><description><c>iptables -S</c>, skipped when it is only the nft shim</description></item>
/// <item><term>Listeners</term><description><c>ss -tulpnH</c>, falling back to <c>/proc/net</c></description></item>
/// </list>
///
/// Every parser is static and takes text, so the suite exercises them against
/// captured output with no firewall and no root shell.
/// </summary>
public sealed class HostFirewallScanner
{
    private readonly FirewallService _firewall;

    public HostFirewallScanner(FirewallService firewall) => _firewall = firewall;

    private static readonly string[] UfwRuleFiles =
    {
        "/etc/ufw/user.rules",
        "/etc/ufw/user6.rules",
        "/var/lib/ufw/user.rules",
        "/var/lib/ufw/user6.rules"
    };

    /// <summary>UFW's own helper chains: plumbing, not rules anybody wrote.</summary>
    private static readonly HashSet<string> SkipChains = new(StringComparer.OrdinalIgnoreCase)
    {
        "ufw-before-logging-input", "ufw-after-logging-input", "ufw-logging-deny",
        "ufw-logging-allow", "ufw-track-input", "ufw-track-output",
        "ufw-skip-to-policy-input", "ufw-skip-to-policy-output", "ufw-not-local",
        "ufw6-before-logging-input", "ufw6-after-logging-input", "ufw6-logging-deny",
        "ufw6-logging-allow", "ufw6-track-input", "ufw6-track-output",
        "ufw6-skip-to-policy-input", "ufw6-skip-to-policy-output", "ufw6-not-local"
    };

    private static readonly HashSet<string> InputChains = new(StringComparer.OrdinalIgnoreCase)
    {
        "input", "inbound", "in", "filter_in", "filter_input",
        "ufw-user-input", "ufw-before-input", "ufw6-user-input", "ufw6-before-input"
    };

    private static readonly HashSet<string> OutputChains = new(StringComparer.OrdinalIgnoreCase)
    {
        "output", "outbound", "out", "filter_out", "filter_output",
        "ufw-user-output", "ufw-before-output", "ufw6-user-output", "ufw6-before-output"
    };

    // ── Scan ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads every backend and folds them into one firewall named after the
    /// machine. Never throws: a backend that is missing, empty or refused
    /// becomes an entry in <see cref="HostFirewallSnapshot.Errors"/> and the
    /// scan carries on with what it did get.
    /// </summary>
    public HostFirewallSnapshot Scan()
    {
        var errors = new List<string>();
        var backends = new List<string>();

        var ufw = CollectUfw(errors, backends);
        var nft = CollectNft(errors, backends);
        // On anything modern `iptables` is the nft shim, reporting the very rules
        // nft just gave us in a different syntax — close enough to differ in
        // formatting ("203.0.113.44" vs "/32") that dedupe would not catch it, so
        // every rule would be listed twice. Only ask when nft came back empty,
        // which is the iptables-legacy case this is for.
        var ipt = nft == null ? CollectIptables(errors, backends) : null;

        var inbound = new List<FirewallRuleInfo>();
        var outbound = new List<FirewallRuleInfo>();
        var defaultIn = "Drop";
        var defaultOut = "Accept";
        var enabled = false;
        var backend = "none";
        var status = "Disabled";

        if (ufw != null)
        {
            inbound.AddRange(ufw.Inbound);
            outbound.AddRange(ufw.Outbound);
            defaultIn = ufw.DefaultInbound;
            defaultOut = ufw.DefaultOutbound;
            enabled = ufw.Enabled;
            status = ufw.Status;
            backend = "UFW";
        }
        else if (nft != null) backend = "nftables";
        else if (ipt != null) backend = "iptables";

        // Kernel rules that are not UFW plumbing — Network Sentinel's own blocks,
        // WireGuard, IPsec, Docker. They are in force whether or not UFW knows
        // about them, so they belong in the same list.
        foreach (var extra in new[] { nft, ipt })
        {
            if (extra == null) continue;
            inbound.AddRange(extra.Inbound.Where(r => !IsPlumbing(r)));
            outbound.AddRange(extra.Outbound.Where(r => !IsPlumbing(r)));
            if (extra.Enabled && !enabled)
            {
                enabled = true;
                status = extra.Status;
                if (ufw == null)
                {
                    defaultIn = extra.DefaultInbound;
                    defaultOut = extra.DefaultOutbound;
                }
            }
        }

        inbound = Dedupe(inbound);
        outbound = Dedupe(outbound);
        AttributeOwnRules(inbound);
        AttributeOwnRules(outbound);
        if (enabled) status = "Enabled";

        var listeners = CollectListeners(errors);
        AnnotateCoverage(listeners, inbound, enabled);

        var note = PrivilegeNote();
        if (backend == "none")
        {
            // Keep the listeners. They come from `ss`, which needs no privilege, so a
            // host whose firewall could not be read still knows what is listening on
            // it — and "nothing readable" is the case where that matters most: an
            // unprivileged run, or a box with no firewall configured at all.
            // Unreadable() carries no listeners, so returning it here emptied the
            // listening-services table on exactly those hosts.
            return new HostFirewallSnapshot
            {
                HostLabel = Environment.MachineName,
                Backend = "none",
                Status = "Unknown",
                Description = "No UFW, nftables, or iptables rules could be read.",
                PrivilegeNote = "No firewall backend returned rules. " + note,
                Listeners = listeners,
                Errors = errors
            };
        }

        var description = backend.Equals("UFW", StringComparison.OrdinalIgnoreCase)
            ? "Host firewall (UFW on nftables)."
            : $"Host firewall ({backend}).";

        return new HostFirewallSnapshot
        {
            HostLabel = Environment.MachineName,
            Backend = backend,
            Status = status,
            Enabled = enabled,
            DefaultInbound = defaultIn,
            DefaultOutbound = defaultOut,
            Description = description,
            PrivilegeNote = note,
            Inbound = inbound,
            Outbound = outbound,
            Listeners = listeners,
            Errors = errors,
            BackendsSeen = backends.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private string PrivilegeNote()
    {
        if (!FirewallService.PlatformSupported)
            return FirewallService.UnsupportedPlatformText;
        if (_firewall.IsRoot)
            return "Running as root — UFW, nftables and process names are all visible.";
        if (_firewall.CanElevate)
            return "Running unprivileged. Rules that need root are read through sudo -n where that is allowed; " +
                   "run the app elevated if the list looks short.";
        return "Running unprivileged with no pkexec or sudo. Only world-readable rules are listed.";
    }

    // ── UFW ──────────────────────────────────────────────────────────────

    private BackendRules? CollectUfw(List<string> errors, List<string> backends)
    {
        var haveFiles = UfwRuleFiles.Any(File.Exists);
        if (!FirewallService.ReadCommandExists("ufw") && !haveFiles) return null;
        backends.Add("ufw");

        var status = FirewallService.ReadCommand("ufw", "status", "verbose");
        var parsed = status.Ok && status.StdOut.Trim().Length > 0 ? ParseUfwStatus(status.StdOut) : null;
        if (parsed != null && (parsed.Any || parsed.Enabled))
            return parsed;

        // `ufw status` needs root. The user.rules files carry the same allow list
        // and are often readable, so an unprivileged run still sees the firewall.
        var fromFiles = CollectUfwUserFiles();
        if (fromFiles != null)
        {
            if (parsed != null)
            {
                fromFiles.Status = parsed.Status;
                fromFiles.Enabled = parsed.Enabled;
                fromFiles.DefaultInbound = parsed.DefaultInbound;
                fromFiles.DefaultOutbound = parsed.DefaultOutbound;
            }
            return fromFiles;
        }

        if (parsed != null) return parsed;
        if (!string.IsNullOrWhiteSpace(status.StdErr))
            errors.Add("ufw: " + FirstLine(status.StdErr));
        return null;
    }

    private static BackendRules? CollectUfwUserFiles()
    {
        var result = new BackendRules { Enabled = true, Status = "Enabled", DefaultInbound = "Drop", DefaultOutbound = "Accept" };
        foreach (var path in UfwRuleFiles.Where(File.Exists))
        {
            string text;
            try { text = File.ReadAllText(path); }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var family = Path.GetFileName(path).Contains('6') ? "ip6" : "ip";
            var parsed = ParseUfwUserRules(text, family);
            result.Inbound.AddRange(parsed.Inbound);
            result.Outbound.AddRange(parsed.Outbound);
        }
        return result.Any ? result : null;
    }

    private static readonly Regex UfwStatusRule = new(
        @"^(?<to>\S+(?:\s+\(v6\))?)\s+(?<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?<dir>IN|OUT))?\s+(?<from>.+?)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Parses <c>ufw status verbose</c> — status, default policies, and the rule table.</summary>
    internal static BackendRules ParseUfwStatus(string text)
    {
        var result = new BackendRules { DefaultInbound = "Drop", DefaultOutbound = "Accept" };
        var inTable = false;

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
            {
                var value = line[7..].Trim();
                result.Enabled = value.StartsWith("active", StringComparison.OrdinalIgnoreCase);
                result.Status = result.Enabled ? "Enabled" : "Disabled";
                continue;
            }

            if (line.StartsWith("Default:", StringComparison.OrdinalIgnoreCase))
            {
                // Default: deny (incoming), allow (outgoing), disabled (routed)
                var incoming = Regex.Match(line, @"(\w+)\s+\(incoming\)", RegexOptions.IgnoreCase);
                var outgoing = Regex.Match(line, @"(\w+)\s+\(outgoing\)", RegexOptions.IgnoreCase);
                if (incoming.Success) result.DefaultInbound = UfwAction(incoming.Groups[1].Value);
                if (outgoing.Success) result.DefaultOutbound = UfwAction(outgoing.Groups[1].Value);
                continue;
            }

            if (Regex.IsMatch(line, @"^To\s+Action\s+From", RegexOptions.IgnoreCase) || line.StartsWith("--"))
            {
                inTable = true;
                continue;
            }

            if (!inTable) continue;
            var rule = ParseUfwStatusLine(line);
            if (rule == null) continue;
            if (rule.Direction == FirewallDirection.Outbound) result.Outbound.Add(rule);
            else result.Inbound.Add(rule);
        }

        return result;
    }

    /// <summary>
    /// One row of the <c>ufw status</c> table:
    /// <c>22/tcp  ALLOW IN  Anywhere</c>, <c>80,443/tcp  ALLOW IN  10.0.0.0/8</c>,
    /// <c>22/tcp (v6)  ALLOW IN  Anywhere (v6)</c>, <c>53  ALLOW OUT  Anywhere</c>.
    /// </summary>
    internal static FirewallRuleInfo? ParseUfwStatusLine(string line)
    {
        var comment = "";
        var body = line;
        var hash = body.IndexOf(" # ", StringComparison.Ordinal);
        if (hash >= 0)
        {
            comment = body[(hash + 3)..].Trim();
            body = body[..hash];
        }

        var match = UfwStatusRule.Match(body.Trim());
        if (!match.Success) return null;

        var to = match.Groups["to"].Value;
        var from = match.Groups["from"].Value.Trim();
        var action = UfwAction(match.Groups["action"].Value);
        var outbound = string.Equals(
            match.Groups["dir"].Success ? match.Groups["dir"].Value : "IN", "OUT", StringComparison.OrdinalIgnoreCase);

        var v6 = to.Contains("(v6)", StringComparison.Ordinal) || from.Contains("(v6)", StringComparison.Ordinal);
        to = to.Replace("(v6)", "", StringComparison.Ordinal).Trim();
        from = from.Replace("(v6)", "", StringComparison.Ordinal).Trim();

        var protocol = FirewallRuleSpecs.ProtocolAny;
        var ports = "";
        var slash = to.LastIndexOf('/');
        if (slash > 0)
        {
            var maybeProto = to[(slash + 1)..];
            var maybePorts = to[..slash];
            if (IsProtocolWord(maybeProto))
            {
                protocol = maybeProto.ToUpperInvariant();
                ports = maybePorts.Equals("Anywhere", StringComparison.OrdinalIgnoreCase)
                    ? ""
                    : maybePorts.Replace(",", ", ");
            }
            else ports = to;
        }
        else if (!to.Equals("Anywhere", StringComparison.OrdinalIgnoreCase))
        {
            ports = to;
        }

        var addresses = IsAnyWord(from)
            ? (v6 ? "All IPv6" : "All IPv4")
            : from;

        return BuildRule(
            action: action, protocol: protocol, ports: ports, addresses: addresses,
            outbound: outbound, origin: "UFW", backend: "ufw",
            table: "filter", chain: outbound ? "ufw-user-output" : "ufw-user-input",
            family: v6 ? "ip6" : "ip", comment: comment, handle: "");
    }

    /// <summary>
    /// Parses <c>/etc/ufw/user.rules</c> — iptables-restore syntax, with UFW's own
    /// <c>### tuple ###</c> comment above each rule carrying the action it meant.
    /// </summary>
    internal static BackendRules ParseUfwUserRules(string text, string family = "ip")
    {
        var result = new BackendRules { Enabled = true, Status = "Enabled", DefaultInbound = "Drop", DefaultOutbound = "Accept" };
        var pendingTuple = "";

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("### tuple ###", StringComparison.Ordinal))
            {
                pendingTuple = line["### tuple ###".Length..].Trim();
                continue;
            }
            if (!line.StartsWith("-A ", StringComparison.Ordinal))
            {
                pendingTuple = "";
                continue;
            }

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var chain = parts.Length > 1 ? parts[1] : "";
            var outbound = chain.Contains("user-output", StringComparison.OrdinalIgnoreCase)
                           || DirectionOf(chain, "") == FirewallDirection.Outbound;

            var rule = ParseIptablesLine(line, "ufw", family, "UFW", forceOutbound: outbound);
            if (rule == null) { pendingTuple = ""; continue; }

            // "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in" — the first word is the verdict
            // UFW recorded, which the -A line itself does not carry for a jump target.
            if (pendingTuple.Length > 0)
            {
                var bits = pendingTuple.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (bits.Length > 0)
                {
                    var verdict = UfwAction(bits[0]);
                    rule = Relabel(rule, verdict);
                }
            }
            pendingTuple = "";

            if (rule.Direction == FirewallDirection.Outbound) result.Outbound.Add(rule);
            else result.Inbound.Add(rule);
        }

        return result;
    }

    private static string UfwAction(string word) => word.ToLowerInvariant() switch
    {
        "allow" or "accept" => "Accept",
        "deny" or "drop" => "Drop",
        "reject" => "Reject",
        "limit" => "Accept",
        _ => Capitalize(word)
    };

    // ── nftables ─────────────────────────────────────────────────────────

    private BackendRules? CollectNft(List<string> errors, List<string> backends)
    {
        if (!FirewallService.ReadCommandExists("nft")) return null;
        backends.Add("nft");

        var json = FirewallService.ReadCommand("nft", "-j", "list", "ruleset");
        if (json.Ok && json.StdOut.Trim().Length > 0)
        {
            try { return ParseNftJson(json.StdOut); }
            catch (JsonException ex) { errors.Add("nft json: " + ex.Message); }
        }
        else if (!string.IsNullOrWhiteSpace(json.StdErr))
        {
            errors.Add("nft: " + FirstLine(json.StdErr));
        }

        return null;
    }

    /// <summary>Parses <c>nft -j list ruleset</c> into rules, with handles kept for deletes.</summary>
    internal static BackendRules? ParseNftJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("nftables", out var items) || items.ValueKind != JsonValueKind.Array)
            return null;

        // (family, table, chain) -> hook/policy, so a rule knows its direction even
        // when the chain is called something other than "input".
        var hooks = new Dictionary<string, (string Hook, string Policy)>(StringComparer.OrdinalIgnoreCase);
        var result = new BackendRules();
        var sawChain = false;

        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            if (item.TryGetProperty("chain", out var chain))
            {
                sawChain = true;
                var key = ChainKey(Str(chain, "family"), Str(chain, "table"), Str(chain, "name"));
                hooks[key] = (Str(chain, "hook"), Str(chain, "policy"));
            }
        }

        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            if (!item.TryGetProperty("rule", out var rule)) continue;

            var parsed = NftRule(rule, hooks);
            if (parsed == null) continue;
            if (parsed.Direction == FirewallDirection.Outbound) result.Outbound.Add(parsed);
            else result.Inbound.Add(parsed);
        }

        if (!result.Any && !sawChain) return null;

        result.DefaultInbound = NftPolicy(hooks, inbound: true);
        result.DefaultOutbound = NftPolicy(hooks, inbound: false);
        result.Enabled = result.Any || sawChain;
        result.Status = result.Enabled ? "Enabled" : "Empty";
        return result;
    }

    private static string ChainKey(string family, string table, string name) => $"{family}|{table}|{name}";

    private static string NftPolicy(Dictionary<string, (string Hook, string Policy)> hooks, bool inbound)
    {
        var wantedHook = inbound ? "input" : "output";
        var wantedNames = inbound ? InputChains : OutputChains;
        foreach (var (key, value) in hooks)
        {
            var name = key.Split('|').Last();
            if (value.Hook.Equals(wantedHook, StringComparison.OrdinalIgnoreCase) || wantedNames.Contains(name))
            {
                if (!string.IsNullOrWhiteSpace(value.Policy)) return Capitalize(value.Policy);
            }
        }
        return "Accept";
    }

    private static FirewallRuleInfo? NftRule(JsonElement rule, Dictionary<string, (string Hook, string Policy)> hooks)
    {
        var family = Str(rule, "family");
        var table = Str(rule, "table");
        var chain = Str(rule, "chain");
        if (SkipChains.Contains(chain)) return null;

        var handle = rule.TryGetProperty("handle", out var h)
            ? (h.ValueKind == JsonValueKind.Number ? h.GetRawText() : h.ToString())
            : "";

        var protocol = "";
        var ports = "";
        var sources = new List<string>();
        var action = "";
        var comment = Str(rule, "comment");
        var jumpTarget = "";
        var extras = new List<string>();

        if (rule.TryGetProperty("expr", out var exprs) && exprs.ValueKind == JsonValueKind.Array)
        {
            foreach (var expr in exprs.EnumerateArray())
            {
                if (expr.ValueKind != JsonValueKind.Object) continue;

                if (expr.TryGetProperty("comment", out var c) && comment.Length == 0)
                    comment = c.ValueKind == JsonValueKind.String ? c.GetString() ?? "" : c.ToString();
                else if (expr.TryGetProperty("accept", out _)) action = "Accept";
                else if (expr.TryGetProperty("drop", out _)) action = "Drop";
                else if (expr.TryGetProperty("reject", out _)) action = "Reject";
                else if (expr.TryGetProperty("return", out _)) action = "Return";
                else if (expr.TryGetProperty("log", out _)) extras.Add("log");
                else if (expr.TryGetProperty("counter", out _)) { /* bookkeeping, not a match */ }
                else if (expr.TryGetProperty("jump", out var j) || expr.TryGetProperty("goto", out j))
                {
                    jumpTarget = j.ValueKind == JsonValueKind.Object ? Str(j, "target") : j.ToString();
                    if (action.Length == 0) action = "Jump";
                }
                else if (expr.TryGetProperty("match", out var m))
                {
                    ApplyNftMatch(m, ref protocol, ref ports, sources, extras);
                }
                else if (expr.TryGetProperty("ct", out _))
                {
                    extras.Add("established,related");
                }
            }
        }

        if (action.Length == 0)
        {
            // A conntrack accept helper still counts as a rule; anything else with
            // no verdict is a fragment we should not present as one.
            if (extras.Any(e => e.Contains("established", StringComparison.OrdinalIgnoreCase))) action = "Accept";
            else return null;
        }

        // A jump into UFW's own chains is plumbing — the chains themselves are read.
        if (action == "Jump" && jumpTarget.StartsWith("ufw", StringComparison.OrdinalIgnoreCase))
            return null;

        hooks.TryGetValue(ChainKey(family, table, chain), out var meta);
        var direction = DirectionOf(chain, meta.Hook);
        if (protocol.Length == 0)
            protocol = extras.Any(e => e.Contains("icmp", StringComparison.OrdinalIgnoreCase))
                ? "ICMP"
                : FirewallRuleSpecs.ProtocolAny;

        return BuildRule(
            action: action, protocol: protocol, ports: ports,
            addresses: JoinSources(sources, family),
            outbound: direction == FirewallDirection.Outbound,
            origin: "nftables", backend: "nft", table: table, chain: chain,
            family: family, comment: comment, handle: handle);
    }

    private static void ApplyNftMatch(
        JsonElement match, ref string protocol, ref string ports, List<string> sources, List<string> extras)
    {
        var field = NftField(match.TryGetProperty("left", out var left) ? left : default);
        var right = match.TryGetProperty("right", out var r) ? r : default;

        if (field is "tcp.dport" or "udp.dport" or "sctp.dport" or "th.dport" or "dport")
        {
            ports = MergePorts(ports, FormatPortRange(right));
            if (protocol.Length == 0)
                protocol = field.StartsWith("tcp", StringComparison.Ordinal) ? "TCP"
                    : field.StartsWith("udp", StringComparison.Ordinal) ? "UDP"
                    : field.StartsWith("sctp", StringComparison.Ordinal) ? "SCTP"
                    : "";
        }
        else if (field is "ip.saddr" or "ip6.saddr" or "saddr")
        {
            sources.AddRange(NftAddresses(right));
        }
        else if (field is "ip.protocol" or "ip6.nexthdr" or "meta.l4proto")
        {
            if (protocol.Length == 0) protocol = ProtocolName(right);
        }
        else if (field.Contains("icmp", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "ICMP";
        }
        else if (field.StartsWith("ct.", StringComparison.Ordinal))
        {
            extras.Add("established,related");
        }
    }

    private static string NftField(JsonElement left)
    {
        if (left.ValueKind != JsonValueKind.Object) return "";
        if (left.TryGetProperty("payload", out var payload) && payload.ValueKind == JsonValueKind.Object)
        {
            var proto = Str(payload, "protocol");
            var field = Str(payload, "field");
            return proto.Length > 0 && field.Length > 0 ? $"{proto}.{field}" : (field.Length > 0 ? field : proto);
        }
        if (left.TryGetProperty("meta", out var meta))
            return "meta." + (meta.ValueKind == JsonValueKind.Object ? Str(meta, "key") : meta.ToString());
        if (left.TryGetProperty("ct", out var ct))
            return "ct." + (ct.ValueKind == JsonValueKind.Object ? Str(ct, "key") : ct.ToString());
        return "";
    }

    private static List<string> NftAddresses(JsonElement value)
    {
        var result = new List<string>();
        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                result.Add(value.GetString() ?? "");
                break;
            case JsonValueKind.Number:
                result.Add(value.GetRawText());
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray()) result.AddRange(NftAddresses(item));
                break;
            case JsonValueKind.Object:
                if (value.TryGetProperty("prefix", out var prefix) && prefix.ValueKind == JsonValueKind.Object)
                    result.Add($"{Str(prefix, "addr")}/{Str(prefix, "len")}");
                else if (value.TryGetProperty("set", out var set) && set.ValueKind == JsonValueKind.Array)
                    foreach (var item in set.EnumerateArray()) result.AddRange(NftAddresses(item));
                break;
        }
        return result.Where(s => s.Length > 0).ToList();
    }

    /// <summary>nft renders a port as a number, a <c>{"range":[a,b]}</c> or a set of either.</summary>
    internal static string FormatPortRange(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Number:
                return value.GetRawText();
            case JsonValueKind.String:
            {
                var text = (value.GetString() ?? "").Trim();
                return text is "0-65535" or "1-65535" or "0:65535" or "1:65535" ? "" : text.Replace(':', '-');
            }
            case JsonValueKind.Object:
                if (value.TryGetProperty("range", out var range) && range.ValueKind == JsonValueKind.Array)
                {
                    var bounds = range.EnumerateArray().Select(FormatPortRange).Where(s => s.Length > 0).ToList();
                    return bounds.Count == 2 ? $"{bounds[0]}-{bounds[1]}" : string.Join("-", bounds);
                }
                if (value.TryGetProperty("set", out var set) && set.ValueKind == JsonValueKind.Array)
                    return string.Join(", ", set.EnumerateArray().Select(FormatPortRange).Where(s => s.Length > 0));
                return "";
            case JsonValueKind.Array:
                return string.Join(", ", value.EnumerateArray().Select(FormatPortRange).Where(s => s.Length > 0));
            default:
                return "";
        }
    }

    private static string ProtocolName(JsonElement value)
    {
        var text = value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString();
        return text.ToLowerInvariant() switch
        {
            "6" or "tcp" => "TCP",
            "17" or "udp" => "UDP",
            "1" or "icmp" => "ICMP",
            "58" or "icmpv6" or "ipv6-icmp" => "ICMP",
            "132" or "sctp" => "SCTP",
            "" => "",
            _ => text.ToUpperInvariant()
        };
    }

    // ── iptables ─────────────────────────────────────────────────────────

    private BackendRules? CollectIptables(List<string> errors, List<string> backends)
    {
        if (!FirewallService.ReadCommandExists("iptables")) return null;

        var listing = FirewallService.ReadCommand("iptables", "-S");
        if (!listing.Ok || listing.StdOut.Trim().Length == 0)
        {
            if (!string.IsNullOrWhiteSpace(listing.StdErr))
                errors.Add("iptables: " + FirstLine(listing.StdErr));
            return null;
        }

        var parsed = ParseIptablesSave(listing.StdOut, "ip");
        // iptables-nft with nothing but empty chains and policies is the shim over
        // the ruleset nft already gave us — listing it again would double every rule.
        if (!parsed.Any) return null;

        backends.Add("iptables");
        return parsed;
    }

    /// <summary>Parses <c>iptables -S</c> / <c>ip6tables -S</c> output.</summary>
    internal static BackendRules ParseIptablesSave(string text, string family = "ip")
    {
        var result = new BackendRules();

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith("-P ", StringComparison.Ordinal))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;
                if (InputChains.Contains(parts[1])) result.DefaultInbound = Capitalize(parts[2]);
                else if (OutputChains.Contains(parts[1])) result.DefaultOutbound = Capitalize(parts[2]);
                continue;
            }

            if (!line.StartsWith("-A ", StringComparison.Ordinal)) continue;
            var rule = ParseIptablesLine(line, "iptables", family, "iptables");
            if (rule == null) continue;
            if (rule.Direction == FirewallDirection.Outbound) result.Outbound.Add(rule);
            else result.Inbound.Add(rule);
        }

        result.Enabled = result.Any;
        result.Status = result.Any ? "Enabled" : "Empty";
        return result;
    }

    private static readonly Regex IptDport = new(@"--dports?\s+(\S+)", RegexOptions.Compiled);
    private static readonly Regex IptProto = new(@"(?:^|\s)-p\s+(\S+)", RegexOptions.Compiled);
    private static readonly Regex IptSource = new(@"(?:^|\s)-s\s+(\S+)", RegexOptions.Compiled);
    private static readonly Regex IptJump = new(@"(?:^|\s)-j\s+(\S+)", RegexOptions.Compiled);
    private static readonly Regex IptComment = new(@"--comment\s+""?([^""]+)""?", RegexOptions.Compiled);

    /// <summary>One <c>-A CHAIN …</c> line, shared by the iptables and UFW-file parsers.</summary>
    internal static FirewallRuleInfo? ParseIptablesLine(
        string line, string backend, string family, string origin, bool? forceOutbound = null)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return null;
        var chain = parts[1];
        if (SkipChains.Contains(chain)) return null;

        var jump = IptJump.Match(line);
        var target = jump.Success ? jump.Groups[1].Value : "";
        var action = target.ToUpperInvariant() switch
        {
            "ACCEPT" => "Accept",
            "DROP" => "Drop",
            "REJECT" => "Reject",
            "RETURN" => "Return",
            "LOG" => "Log",
            "" => "",
            _ => "Jump"
        };

        // A jump into another UFW chain is plumbing; the target chain is parsed on
        // its own lines, so following it here would list every rule twice.
        if (action == "Jump" && target.StartsWith("ufw", StringComparison.OrdinalIgnoreCase)) return null;
        if (action.Length == 0 || action == "Log") return null;

        var protoMatch = IptProto.Match(line);
        var protocol = protoMatch.Success ? NormalizeProtocolWord(protoMatch.Groups[1].Value) : FirewallRuleSpecs.ProtocolAny;

        var portMatch = IptDport.Match(line);
        var ports = portMatch.Success ? portMatch.Groups[1].Value.Replace(":", "-").Replace(",", ", ") : "";

        var srcMatch = IptSource.Match(line);
        var source = srcMatch.Success ? srcMatch.Groups[1].Value : "";
        var addresses = IsAnyWord(source) ? JoinSources(new List<string>(), family) : source;

        var commentMatch = IptComment.Match(line);
        var comment = commentMatch.Success ? commentMatch.Groups[1].Value.Trim() : "";

        var outbound = forceOutbound ?? (DirectionOf(chain, "") == FirewallDirection.Outbound);

        return BuildRule(
            action: action, protocol: protocol, ports: ports, addresses: addresses,
            outbound: outbound, origin: origin, backend: backend,
            table: "filter", chain: chain, family: family, comment: comment, handle: "");
    }

    // ── Listeners ────────────────────────────────────────────────────────

    private static List<HostListener> CollectListeners(List<string> errors)
    {
        if (FirewallService.ReadCommandExists("ss"))
        {
            var ss = FirewallService.ReadCommand("ss", "-tulpnH");
            if (ss.Ok && ss.StdOut.Trim().Length > 0) return ParseSs(ss.StdOut);
            if (!string.IsNullOrWhiteSpace(ss.StdErr)) errors.Add("ss: " + FirstLine(ss.StdErr));
        }
        return new List<HostListener>();
    }

    private static readonly Regex SsProcess = new(@"users:\(\(""([^""]+)""", RegexOptions.Compiled);

    /// <summary>Parses <c>ss -tulpnH</c>: Netid State Recv-Q Send-Q Local Peer [Process].</summary>
    internal static List<HostListener> ParseSs(string text)
    {
        var result = new List<HostListener>();
        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) continue;

            var protocol = parts[0].ToUpperInvariant();
            if (protocol.StartsWith("TCP", StringComparison.Ordinal)) protocol = "TCP";
            else if (protocol.StartsWith("UDP", StringComparison.Ordinal)) protocol = "UDP";
            else continue;

            var state = parts[1];
            var local = parts[4];
            var (address, port) = SplitHostPort(local);
            if (port.Length == 0) continue;

            var processMatch = SsProcess.Match(line);
            result.Add(new HostListener
            {
                Protocol = protocol,
                Address = address,
                Port = port,
                Process = processMatch.Success ? processMatch.Groups[1].Value : "—",
                State = state
            });
        }
        return result;
    }

    private static (string Address, string Port) SplitHostPort(string value)
    {
        var text = (value ?? "").Trim();
        var colon = text.LastIndexOf(':');
        if (colon < 0) return (text, "");
        var address = text[..colon].Trim('[', ']');
        var port = text[(colon + 1)..];
        if (address is "*" or "0.0.0.0") address = "0.0.0.0";
        else if (address is "[::]" or "::" or "*:") address = "::";
        return (address, port);
    }

    /// <summary>
    /// Marks each listener with what the inbound rules do to it. A socket bound
    /// to loopback is unreachable regardless; one that no Accept rule matches is
    /// listening into a closed door, which is worth seeing next to the rule list.
    /// </summary>
    internal static void AnnotateCoverage(
        IReadOnlyList<HostListener> listeners, IReadOnlyList<FirewallRuleInfo> inbound, bool firewallEnabled)
    {
        var accepts = inbound
            .Where(r => !r.IsBlock)
            .Select(r => (
                WideOpen: MatchesEveryAddress(r.AddressListText),
                Protocol: r.ProtocolText.ToUpperInvariant(),
                Ports: new HashSet<string>(Regex.Matches(r.LocalPorts, @"\d+").Select(m => m.Value))))
            .ToList();

        foreach (var socket in listeners)
        {
            if (socket.Address is "127.0.0.1" or "::1")
            {
                socket.Covered = "Local only";
                continue;
            }
            if (!firewallEnabled || accepts.Count == 0)
            {
                socket.Covered = firewallEnabled ? "Not allowed" : "No firewall";
                continue;
            }

            var matched = false;
            var restricted = false;
            foreach (var (wideOpen, protocol, ports) in accepts)
            {
                var protocolOk = protocol is "ANY" or "IP" || protocol == socket.Protocol;
                var portOk = ports.Count == 0 || ports.Contains(socket.Port);
                if (!protocolOk || !portOk) continue;

                matched = true;
                if (!wideOpen) restricted = true;
            }

            socket.Covered = matched ? (restricted ? "Restricted" : "Open") : "Not allowed";
        }
    }

    // ── Folding helpers ──────────────────────────────────────────────────

    /// <summary>
    /// UFW helper chains and the usual established/loopback noise. They are real
    /// rules, but listing them puts twenty rows of plumbing above the two rules
    /// somebody actually chose.
    /// </summary>
    internal static bool IsPlumbing(FirewallRuleInfo rule)
    {
        var chain = rule.Chain.ToLowerInvariant();
        if (chain.StartsWith("ufw", StringComparison.Ordinal)) return true;
        if (rule.Table.StartsWith("ufw", StringComparison.OrdinalIgnoreCase)) return true;

        // A base-chain rule with no port, no protocol and no comment is the
        // established/loopback helper every ruleset opens with — not a decision
        // anybody made. A comment means somebody named it, so it stays.
        var bare = string.IsNullOrWhiteSpace(rule.LocalPorts)
                   && rule.ProtocolText.Equals(FirewallRuleSpecs.ProtocolAny, StringComparison.OrdinalIgnoreCase);
        if (bare && string.IsNullOrWhiteSpace(rule.Comment) && (chain is "input" or "output")) return true;
        return false;
    }

    /// <summary>
    /// True when an address field admits every address. Token-wise, not by
    /// substring: "10.0.0.0/8" contains the characters "0.0.0.0" while admitting
    /// only a LAN, and reading that as wide open marks a restricted port Open.
    /// </summary>
    internal static bool MatchesEveryAddress(string addresses)
    {
        var tokens = (addresses ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0) return true;
        return tokens.All(t =>
            t.Equals("All IPv4", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("All IPv6", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("Anywhere", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("any", StringComparison.OrdinalIgnoreCase) ||
            t is "0.0.0.0/0" or "::/0");
    }

    internal static List<FirewallRuleInfo> Dedupe(IEnumerable<FirewallRuleInfo> rules)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<FirewallRuleInfo>();
        foreach (var rule in rules)
        {
            var key = string.Join("|",
                rule.ActionText, rule.ProtocolText, rule.LocalPorts, rule.RemoteAddresses,
                rule.Direction, rule.Label);
            if (seen.Add(key)) result.Add(rule);
        }
        return result;
    }

    /// <summary>
    /// Re-attributes rules this app wrote. They come back from the kernel looking
    /// like any other nft rule; the comment Network Sentinel stamps on them is
    /// what tells the Created by column who is responsible for the row.
    /// </summary>
    private void AttributeOwnRules(List<FirewallRuleInfo> rules)
    {
        var ledger = _firewall.GetConfigRules();
        if (ledger.Count == 0) return;
        var byName = ledger.ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < rules.Count; i++)
        {
            var scanned = rules[i];
            // The comment, not the label: Label is the cleaned-and-truncated form,
            // so a long rule name would not match the ledger key it came from.
            var stamp = scanned.Comment;
            if (stamp.Length == 0 || !byName.TryGetValue(stamp, out var owned)) continue;

            rules[i] = Clone(scanned, origin: owned.OriginText, kind: owned.Kind, label: owned.LabelText);
        }
    }

    // ── Rule construction ────────────────────────────────────────────────

    private static FirewallRuleInfo BuildRule(
        string action, string protocol, string ports, string addresses, bool outbound,
        string origin, string backend, string table, string chain, string family,
        string comment, string handle)
    {
        var isBlock = action is "Drop" or "Reject";
        var label = comment.Length > 0
            ? FirewallRuleSpecs.CleanLabel(comment)
            : FirewallRuleSpecs.AutoLabel(
                isBlock ? FirewallRuleSpecs.ActionBlock : FirewallRuleSpecs.ActionAllow,
                outbound ? FirewallRuleSpecs.DirectionOutbound : FirewallRuleSpecs.DirectionInbound,
                protocol,
                Regex.Matches(ports, @"\d+(?:[-:]\d+)?").Select(m => m.Value.Replace('-', ':')).ToList());

        return new FirewallRuleInfo
        {
            Name = label,
            Label = label,
            Description = $"{action} {protocol} {(ports.Length > 0 ? ports : "all ports")} " +
                          $"{(outbound ? "to" : "from")} {addresses}",
            Enabled = true,
            IsBlock = isBlock,
            Direction = outbound ? FirewallDirection.Outbound : FirewallDirection.Inbound,
            RemoteAddresses = addresses,
            LocalPorts = ports,
            Protocol = protocol,
            Kind = FirewallRuleKind.Other,
            Backend = backend,
            Origin = origin,
            Handle = handle,
            Table = table,
            Chain = chain,
            Family = family,
            IsForeign = true,
            Verdict = action,
            Comment = comment
        };
    }

    private static FirewallRuleInfo Relabel(FirewallRuleInfo rule, string verdict)
    {
        var isBlock = verdict is "Drop" or "Reject";
        return Clone(rule, isBlock: isBlock, verdict: verdict);
    }

    private static FirewallRuleInfo Clone(
        FirewallRuleInfo rule, string? origin = null, FirewallRuleKind? kind = null,
        string? label = null, bool? isBlock = null, string? verdict = null) => new()
    {
        Name = rule.Name,
        Label = label ?? rule.Label,
        Description = rule.Description,
        Enabled = rule.Enabled,
        IsBlock = isBlock ?? rule.IsBlock,
        Direction = rule.Direction,
        RemoteAddresses = rule.RemoteAddresses,
        LocalPorts = rule.LocalPorts,
        Protocol = rule.Protocol,
        Kind = kind ?? rule.Kind,
        Backend = rule.Backend,
        ExpiresUtc = rule.ExpiresUtc,
        Origin = origin ?? rule.Origin,
        Handle = rule.Handle,
        Table = rule.Table,
        Chain = rule.Chain,
        Family = rule.Family,
        IsForeign = rule.IsForeign,
        Verdict = verdict ?? rule.Verdict
    };

    // ── Small shared helpers ─────────────────────────────────────────────

    internal static FirewallDirection DirectionOf(string chain, string hook)
    {
        var name = (chain ?? "").ToLowerInvariant();
        var h = (hook ?? "").ToLowerInvariant();
        if (h == "output" || OutputChains.Contains(name) || name.EndsWith("-output", StringComparison.Ordinal)
            || name.Contains("outbound", StringComparison.Ordinal))
            return FirewallDirection.Outbound;
        return FirewallDirection.Inbound;
    }

    private static string JoinSources(List<string> sources, string family)
    {
        var cleaned = sources
            .Where(s => s.Length > 0 && s is not ("0.0.0.0/0" or "::/0" or "anywhere" or "any"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (cleaned.Count > 0) return string.Join(", ", cleaned);
        return family.ToLowerInvariant() switch
        {
            "ip" or "ipv4" => "All IPv4",
            "ip6" or "ipv6" => "All IPv6",
            _ => FirewallRuleSpecs.AnyAddressText
        };
    }

    private static string MergePorts(string existing, string addition)
    {
        if (addition.Length == 0) return existing;
        if (existing.Length == 0) return addition;
        return existing.Contains(addition, StringComparison.Ordinal) ? existing : $"{existing}, {addition}";
    }

    private static bool IsAnyWord(string value) =>
        value.Length == 0 ||
        value is "0.0.0.0/0" or "::/0" ||
        value.Equals("anywhere", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("any", StringComparison.OrdinalIgnoreCase);

    private static bool IsProtocolWord(string value) =>
        value.ToLowerInvariant() is "tcp" or "udp" or "icmp" or "ah" or "esp" or "gre" or "sctp";

    private static string NormalizeProtocolWord(string value) => value.ToLowerInvariant() switch
    {
        "tcp" => "TCP",
        "udp" => "UDP",
        "icmp" or "icmpv6" or "ipv6-icmp" => "ICMP",
        "all" or "any" => FirewallRuleSpecs.ProtocolAny,
        _ => value.ToUpperInvariant()
    };

    private static string Str(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? (value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : value.ToString())
            : "";

    private static string Capitalize(string value) =>
        value.Length == 0 ? value : char.ToUpperInvariant(value[0]) + value[1..].ToLowerInvariant();

    private static string FirstLine(string text)
    {
        var line = (text ?? "").Trim().Split('\n').FirstOrDefault() ?? "";
        return line.Length > 200 ? line[..200] : line;
    }
}
