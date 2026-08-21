using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>One listening socket, with the verdict the firewall passes on it.</summary>
public sealed class HostListener
{
    public string Protocol { get; init; } = "TCP";
    public string Address { get; init; } = "";
    public string Port { get; init; } = "";
    public string Process { get; init; } = "—";
    public int ProcessId { get; init; }
    public string State { get; init; } = "LISTEN";

    /// <summary>
    /// "Open", "Restricted", "Blocked", "Not allowed", "Local only" or "No firewall"
    /// — what the inbound rules do to traffic arriving here. A listener the firewall
    /// does not admit is not reachable, however loudly it is listening, and a
    /// listener nothing covers is the one worth knowing about.
    /// </summary>
    public string Covered { get; set; } = "Unknown";

    public string ServiceName =>
        int.TryParse(Port, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p)
            ? PortCatalog.GetHint(p, Protocol)
            : Port;
}

/// <summary>One Windows Firewall profile: whether it is on, and what it does by default.</summary>
public sealed class HostFirewallProfile
{
    public string Name { get; init; } = "";
    public bool On { get; init; }
    public string DefaultInbound { get; init; } = "Unknown";
    public string DefaultOutbound { get; init; } = "Unknown";

    /// <summary>
    /// "Block all inbound connections, including those in the list of allowed apps"
    /// — the setting that makes allow rules inert. A listener under it is unreachable
    /// no matter what the rule list says, which is worth showing rather than implying.
    /// </summary>
    public bool BlocksInboundAlways { get; init; }

    /// <summary>True for the profile the active network connection is using.</summary>
    public bool IsActive { get; set; }

    public string SummaryText =>
        $"{Name}{(IsActive ? " (active)" : "")}: {(On ? "on" : "off")} · " +
        $"{DefaultInbound} inbound / {DefaultOutbound} outbound";
}

/// <summary>
/// The host firewall as one scan: the rules Windows Defender Firewall actually
/// holds, the profile defaults behind them, and what is listening in front of them.
/// </summary>
public sealed class HostFirewallSnapshot
{
    /// <summary>The machine — the firewall is named after the host it protects.</summary>
    public string HostLabel { get; init; } = "";

    /// <summary>"Windows Defender Firewall", or "none" when nothing could be read.</summary>
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

    /// <summary>One line per profile: on/off and its default actions.</summary>
    public IReadOnlyList<string> ProfilesSeen { get; init; } = Array.Empty<string>();

    /// <summary>Rules netsh listed as disabled — configuration, but not enforcement.</summary>
    public int DisabledRules { get; init; }

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
        Description = "No Windows Defender Firewall rules could be read.",
        PrivilegeNote = note,
        Errors = errors ?? Array.Empty<string>()
    };
}

/// <summary>
/// Reads the host firewall the way
/// <see href="https://github.com/davidfweiser/FireWallConfig">FireWallConfig</see>
/// does, and for the same reason. The Firewall Config view used to list only what
/// this app had written itself — on a Windows box that is a handful of rows sitting
/// next to the fifteen hundred rules Windows, the installers and the games on the
/// machine have written into the same firewall. One machine has one firewall; this
/// reads all of it.
///
/// Sources:
/// <list type="table">
/// <item><term>Rules</term><description><c>netsh advfirewall firewall show rule name=all verbose</c> — verbose because Grouping, Program and Service are what "who wrote this" is read from</description></item>
/// <item><term>Profiles</term><description><c>netsh advfirewall show allprofiles</c> and <c>show currentprofile</c>, for the default actions and which profile is in force</description></item>
/// <item><term>Listeners</term><description>the same IP Helper tables the monitor polls, so no second inventory of the machine can disagree with the first</description></item>
/// </list>
///
/// None of the reads need elevation, which is the one place Windows is kinder than
/// Linux here: the rule list is complete whether or not the app is running as
/// Administrator, and only writing needs UAC. Every parser is static and takes
/// text, so the suite exercises them against captured output with no firewall of
/// its own.
/// </summary>
public sealed class HostFirewallScanner
{
    private readonly FirewallService _firewall;
    private readonly ProcessResolver _processes = new();

    public HostFirewallScanner(FirewallService firewall) => _firewall = firewall;

    // ── Scan ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Reads the firewall and folds it into one list named after the machine. Never
    /// throws: anything that cannot be read becomes an entry in
    /// <see cref="HostFirewallSnapshot.Errors"/> and the scan carries on with what
    /// it did get.
    /// </summary>
    public HostFirewallSnapshot Scan()
    {
        var errors = new List<string>();

        var profiles = ReadProfiles(errors);
        var active = profiles.FirstOrDefault(p => p.IsActive) ?? profiles.FirstOrDefault(p => p.On);
        var enabled = active?.On ?? profiles.Any(p => p.On);

        var scanned = ReadRules(errors, out var disabled);
        var listeners = CollectListeners(errors);

        // The app's own rules come from the managed list rather than being re-derived
        // from the dump: that list already knows a rule's kind and expiry, which is
        // what tells auto-block's rules apart from the operator's config rules.
        var mine = ReadOwnRules(errors);

        var inbound = Order(mine.Where(r => r.IsInbound).Concat(scanned.Where(r => r.IsInbound)));
        var outbound = Order(mine.Where(r => !r.IsInbound).Concat(scanned.Where(r => !r.IsInbound)));

        // Only the rules the active profile actually applies decide reachability. A
        // rule scoped to Domain is configuration on a machine sitting on a private
        // network, not enforcement.
        var inForce = inbound.Where(r => AppliesToProfile(r, active?.Name)).ToList();
        AnnotateCoverage(listeners, inForce, enabled, active?.BlocksInboundAlways ?? false);

        var note = PrivilegeNote(profiles, active);

        if (inbound.Count == 0 && outbound.Count == 0 && profiles.Count == 0)
        {
            // Keep the listeners. They come from IP Helper, which needs no privilege,
            // so a host whose firewall could not be read still knows what is listening
            // on it — and that is the case where it matters most. Unreadable() carries
            // no listeners, so returning it here would empty the table on exactly
            // those hosts.
            return new HostFirewallSnapshot
            {
                HostLabel = Environment.MachineName,
                Backend = "none",
                Status = "Unknown",
                Description = "No Windows Defender Firewall rules could be read.",
                PrivilegeNote = "netsh returned no rules and no profiles. " + note,
                Listeners = listeners,
                Errors = errors
            };
        }

        return new HostFirewallSnapshot
        {
            HostLabel = Environment.MachineName,
            Backend = "Windows Defender Firewall",
            Status = enabled ? "Enabled" : "Off",
            Enabled = enabled,
            DefaultInbound = active?.DefaultInbound ?? "Unknown",
            DefaultOutbound = active?.DefaultOutbound ?? "Unknown",
            Description = active == null
                ? "Host firewall (Windows Defender Firewall)."
                : $"Host firewall (Windows Defender Firewall, {active.Name} profile active).",
            PrivilegeNote = note,
            Inbound = inbound,
            Outbound = outbound,
            Listeners = listeners,
            Errors = errors,
            ProfilesSeen = profiles.Select(p => p.SummaryText).ToList(),
            DisabledRules = disabled
        };
    }

    /// <summary>
    /// Network Sentinel's rules first — they are the ones the operator is here to
    /// see — then blocks ahead of allows, which is the order Windows evaluates them
    /// in, then by who wrote them so a group's rules stay together.
    /// </summary>
    private static List<FirewallRuleInfo> Order(IEnumerable<FirewallRuleInfo> rules)
        => rules
            .OrderBy(r => r.IsForeign ? 1 : 0)
            .ThenBy(r => r.IsBlock ? 0 : 1)
            .ThenBy(r => r.OriginText, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.LabelText, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private string PrivilegeNote(IReadOnlyList<HostFirewallProfile> profiles, HostFirewallProfile? active)
    {
        var profileText = profiles.Count == 0
            ? "Profile states could not be read. "
            : string.Join("  ", profiles.Select(p => p.SummaryText)) + ".  ";

        if (active is { BlocksInboundAlways: true })
            profileText += "The active profile blocks all inbound connections, including ones an allow " +
                           "rule would admit, so no inbound rule below is in force.  ";

        if (_firewall.IsAdministrator)
            return profileText + "Running as Administrator — rules can be written as well as read.";

        // The reads and the writes are two different questions, and “Run as Admin” only
        // answers the second one on a surface that has a window to run. In a browser
        // pointed at a service there is nothing to right-click.
        return profileText + "Reading the firewall needs no elevation, so this is the whole rule set; " +
            (FirewallService.Surface == FirewallUiSurface.Web
                ? "writing or deleting a rule is not possible here until the console runs elevated."
                : "writing or deleting a rule needs “Run as Admin”.");
    }

    // ── Profiles ─────────────────────────────────────────────────────────

    private List<HostFirewallProfile> ReadProfiles(List<string> errors)
    {
        var all = FirewallService.RunNetsh("advfirewall show allprofiles");
        if (!all.Success && string.IsNullOrWhiteSpace(all.Message))
        {
            errors.Add("netsh could not read the firewall profiles.");
            return new List<HostFirewallProfile>();
        }

        var profiles = ParseProfiles(all.Message);

        // Which one is in force. Its settings are the defaults the rules are read
        // against, so "Block inbound" on a profile that is not active would describe
        // a firewall this host is not running.
        var current = FirewallService.RunNetsh("advfirewall show currentprofile");
        var activeName = current.Success ? ParseProfiles(current.Message).FirstOrDefault()?.Name : null;
        if (!string.IsNullOrWhiteSpace(activeName))
        {
            foreach (var profile in profiles)
                profile.IsActive = profile.Name.Equals(activeName, StringComparison.OrdinalIgnoreCase);
        }

        return profiles;
    }

    private static readonly Regex ProfileHeader =
        new(@"^(\w[\w ]*?)\s+Profile Settings:", RegexOptions.Compiled);

    /// <summary>
    /// Parses <c>netsh advfirewall show allprofiles</c> (or <c>show currentprofile</c>,
    /// which prints one block in the same shape).
    /// </summary>
    internal static List<HostFirewallProfile> ParseProfiles(string text)
    {
        var result = new List<HostFirewallProfile>();

        string? name = null;
        var on = false;
        var inbound = "Unknown";
        var outbound = "Unknown";
        var always = false;

        void Flush()
        {
            if (name == null) return;
            result.Add(new HostFirewallProfile
            {
                Name = name,
                On = on,
                DefaultInbound = inbound,
                DefaultOutbound = outbound,
                BlocksInboundAlways = always
            });
        }

        foreach (var raw in (text ?? "").Split('\n'))
        {
            var line = raw.TrimEnd('\r').TrimEnd();
            var header = ProfileHeader.Match(line);
            if (header.Success)
            {
                Flush();
                name = header.Groups[1].Value.Trim();
                on = false;
                inbound = outbound = "Unknown";
                always = false;
                continue;
            }

            if (name == null) continue;

            var state = Regex.Match(line, @"^State\s+(\S+)", RegexOptions.IgnoreCase);
            if (state.Success)
            {
                on = state.Groups[1].Value.Equals("ON", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            var policy = Regex.Match(line, @"^Firewall Policy\s+(\S+)", RegexOptions.IgnoreCase);
            if (policy.Success)
            {
                var value = policy.Groups[1].Value;
                always = value.Contains("BlockInboundAlways", StringComparison.OrdinalIgnoreCase);
                inbound = value.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase) ? "Block"
                    : value.Contains("AllowInbound", StringComparison.OrdinalIgnoreCase) ? "Allow"
                    : "Unknown";
                outbound = value.Contains("BlockOutbound", StringComparison.OrdinalIgnoreCase) ? "Block"
                    : value.Contains("AllowOutbound", StringComparison.OrdinalIgnoreCase) ? "Allow"
                    : "Unknown";
            }
        }

        Flush();
        return result;
    }

    /// <summary>
    /// True when the active profile applies the rule. netsh writes the profile list
    /// as "Domain,Private,Public"; a rule that names none of them applies to all.
    /// </summary>
    internal static bool AppliesToProfile(FirewallRuleInfo rule, string? activeProfile)
    {
        if (string.IsNullOrWhiteSpace(activeProfile)) return true;
        var profiles = rule.Profiles;
        if (string.IsNullOrWhiteSpace(profiles)) return true;
        if (profiles.Contains("Any", StringComparison.OrdinalIgnoreCase)) return true;

        return profiles
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(p => p.Equals(activeProfile, StringComparison.OrdinalIgnoreCase));
    }

    // ── Rules ────────────────────────────────────────────────────────────

    private List<FirewallRuleInfo> ReadRules(List<string> errors, out int disabled)
    {
        disabled = 0;

        // Verbose: Grouping, Program and Service are what the Created by column is
        // built from, and the non-verbose form omits all three.
        var dump = FirewallService.RunNetsh("advfirewall firewall show rule name=all verbose");
        if (string.IsNullOrWhiteSpace(dump.Message))
        {
            errors.Add("netsh returned no firewall rules.");
            return new List<FirewallRuleInfo>();
        }
        if (!dump.Success)
            errors.Add("netsh: " + FirstLine(dump.Message));

        var parsed = ParseHostRules(dump.Message, out disabled);
        return Dedupe(parsed);
    }

    private List<FirewallRuleInfo> ReadOwnRules(List<string> errors)
    {
        try
        {
            return _firewall.GetConfigRules().ToList();
        }
        catch (Exception ex)
        {
            errors.Add("Network Sentinel's own rules could not be listed: " + FirstLine(ex.Message));
            return new List<FirewallRuleInfo>();
        }
    }

    /// <summary>
    /// Every rule on the host that this app did not write. Ours are skipped here and
    /// come from the managed list instead, which knows their kind and expiry.
    /// </summary>
    internal static List<FirewallRuleInfo> ParseHostRules(string dump, out int disabled)
    {
        var list = new List<FirewallRuleInfo>();
        var off = 0;

        foreach (var block in FirewallService.ScanNetshBlocks(dump))
        {
            if (string.IsNullOrWhiteSpace(block.Name)) continue;
            if (FirewallService.IsManagedRuleName(block.Name)) continue;

            // A disabled rule is configuration, not enforcement — it decides nothing
            // about traffic, and listing 228 of them alongside the rules in force
            // would make the page describe a firewall this host is not running.
            if (!block.IsEnabled) { off++; continue; }

            list.Add(FromBlock(block));
        }

        disabled = off;
        return list;
    }

    /// <summary>One foreign rule, as the Firewall Config view shows it.</summary>
    internal static FirewallRuleInfo FromBlock(FirewallService.NetshRuleBlock block)
    {
        var outbound = block.IsOutbound;
        var localPorts = FirewallService.NormalizePorts(block.LocalPort);
        var remotePorts = FirewallService.NormalizePorts(block.RemotePort);

        // The port the rule is about: what is being listened on for an inbound rule,
        // what is being reached for an outbound one — the same choice the app's own
        // config rules display, so one column means one thing down the whole list.
        var display = outbound
            ? (remotePorts.Length > 0 ? remotePorts : localPorts)
            : (localPorts.Length > 0 ? localPorts : remotePorts);

        return new FirewallRuleInfo
        {
            Name = block.Name,
            Label = DisplayName(block.Name),
            Description = block.Description,
            Enabled = true,
            IsBlock = block.IsBlock,
            Direction = outbound ? FirewallDirection.Outbound : FirewallDirection.Inbound,
            RemoteAddresses = FirewallService.NormalizeRemoteList(block.RemoteIp),
            LocalPorts = display,
            LocalPortsRaw = localPorts,
            RemotePortsRaw = remotePorts,
            Protocol = string.IsNullOrWhiteSpace(block.Protocol) ? "Any" : block.Protocol.Trim(),
            Kind = FirewallRuleKind.Other,
            Origin = DescribeOrigin(block),
            Grouping = block.Grouping,
            Program = block.Program,
            Service = block.Service,
            Profiles = block.Profiles,
            IsForeign = true
        };
    }

    /// <summary>
    /// Who wrote the rule, in the order Windows makes it knowable: the group an
    /// installer stamped on it, then the program it is scoped to, then the service.
    /// A rule with none of the three was typed into wf.msc or a netsh line by hand.
    /// </summary>
    internal static string DescribeOrigin(FirewallService.NetshRuleBlock block)
    {
        if (!string.IsNullOrWhiteSpace(block.Grouping)) return DisplayName(block.Grouping);

        var program = ProgramName(block.Program);
        if (program.Length > 0) return program;

        if (!string.IsNullOrWhiteSpace(block.Service)) return $"service {block.Service.Trim()}";
        return "Local rule";
    }

    /// <summary>A package full name: <c>Microsoft.People_10.2202.100.0_x64__8wekyb3d8bbwe</c>.</summary>
    private static readonly Regex PackageFullName =
        new(@"^([A-Za-z0-9.]+)_\d[\d.]*_[A-Za-z0-9_]+$", RegexOptions.Compiled);

    /// <summary>
    /// What to call a rule Windows or an installer wrote. Store-app rules carry a
    /// package identity where a name should be —
    /// <c>@{Microsoft.People_10.2202.100.0_x64__8wekyb3d8bbwe?ms-resource://…/DisplayName}</c>
    /// — because netsh prints the indirect string when it cannot resolve it to the
    /// app's display name. The package name is lifted out of it; every other rule
    /// keeps the name it has, in full: it is the name the same rule shows in wf.msc,
    /// and the one a delete has to match.
    /// </summary>
    internal static string DisplayName(string? raw)
    {
        var value = (raw ?? "").Trim();
        if (value.Length == 0) return "";

        if (value.StartsWith("@{", StringComparison.Ordinal))
        {
            var inner = value[2..];
            var cut = inner.IndexOfAny(new[] { '?', '}' });
            if (cut > 0) inner = inner[..cut];
            var package = PackageFullName.Match(inner);
            return package.Success ? package.Groups[1].Value : inner;
        }

        var direct = PackageFullName.Match(value);
        return direct.Success ? direct.Groups[1].Value : value;
    }

    /// <summary>
    /// The image name a rule is scoped to, matched against the process names the
    /// listener table carries — which is why the extension is dropped:
    /// <see cref="ProcessResolver"/> reports "svchost", not "svchost.exe".
    /// </summary>
    internal static string ProgramName(string? program)
    {
        var value = (program ?? "").Trim();
        if (value.Length == 0) return "";
        if (value.Equals("Any", StringComparison.OrdinalIgnoreCase) || value == "*") return "";
        if (value.Equals("System", StringComparison.OrdinalIgnoreCase)) return "System";

        try { return Path.GetFileNameWithoutExtension(value); }
        catch (ArgumentException) { return value; }
    }

    /// <summary>
    /// Folds rules that are the same rule written more than once into one row and
    /// counts them. Windows does not stop a setup script adding its rule on every
    /// run, so a host really can hold hundreds of identical copies; printing them is
    /// noise, and silently dropping them would understate what is in the firewall.
    ///
    /// The profile a rule applies to is deliberately <em>not</em> part of the fold.
    /// Windows stores its built-in groups once per profile — File and Printer Sharing
    /// and Cast to Device arrive two and three times over, identical but for Domain
    /// against Private,Public — and every consumer of this list keys a row by the shape
    /// it displays, which does not include the profile. So they arrived as separate
    /// rows that no front-end could tell apart, and a delete aimed at one of them was
    /// refused as ambiguous. They fold into one row now, carrying the union of the
    /// profiles they came from, which is also exactly what a delete does to them:
    /// <see cref="FirewallService.DeleteHostRule"/> filters netsh on the fields the row
    /// shows and no profile, so it takes every copy anyway.
    /// </summary>
    internal static List<FirewallRuleInfo> Dedupe(IEnumerable<FirewallRuleInfo> rules)
    {
        var order = new List<string>();
        var byKey = new Dictionary<string, FirewallRuleInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in rules)
        {
            var key = string.Join("|",
                rule.Name, rule.DirectionText, rule.ActionText, rule.ProtocolText,
                rule.LocalPortsRaw, rule.RemotePortsRaw, rule.RemoteAddresses,
                rule.Program, rule.Service);

            if (byKey.TryGetValue(key, out var seen))
            {
                seen.Copies++;
                seen.Profiles = MergeProfiles(seen.Profiles, rule.Profiles);
                continue;
            }

            byKey[key] = rule;
            order.Add(key);
        }

        return order.Select(k => byKey[k]).ToList();
    }

    /// <summary>
    /// The union of two netsh profile lists, in the order Windows names them. A rule
    /// folded across all three reads "Domain,Private,Public", which is how netsh spells
    /// "every profile" — so a row that says nothing less than that is scoped to nothing
    /// less than the whole machine.
    /// </summary>
    internal static string MergeProfiles(string? left, string? right)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var list in new[] { left, right })
            foreach (var part in (list ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries))
                seen.Add(part.Trim());

        if (seen.Count == 0) return "";

        // Domain, Private, Public first and in that order; anything netsh calls something
        // else (an "Any" from a hand-written rule) keeps its place after them.
        var ordered = new List<string>();
        foreach (var known in new[] { "Domain", "Private", "Public" })
        {
            var match = seen.FirstOrDefault(p => p.Equals(known, StringComparison.OrdinalIgnoreCase));
            if (match != null) { ordered.Add(known); seen.Remove(match); }
        }
        ordered.AddRange(seen.OrderBy(p => p, StringComparer.OrdinalIgnoreCase));
        return string.Join(",", ordered);
    }

    // ── Listeners ────────────────────────────────────────────────────────

    /// <summary>
    /// What is listening, from the IP Helper tables the monitor already polls. No
    /// elevation is involved, so this half of the page is complete even when the app
    /// is running unelevated and cannot write a rule at all.
    /// </summary>
    private List<HostListener> CollectListeners(List<string> errors)
    {
        var list = new List<HostListener>();
        try
        {
            foreach (var c in IpHelper.GetTcpConnections().Where(x => x.State == TcpConnectionState.Listen))
            {
                list.Add(new HostListener
                {
                    Protocol = "TCP",
                    Address = c.LocalAddress,
                    Port = c.LocalPort.ToString(CultureInfo.InvariantCulture),
                    ProcessId = c.ProcessId,
                    Process = _processes.Resolve(c.ProcessId),
                    State = "LISTEN"
                });
            }

            foreach (var u in IpHelper.GetUdpTable().Listeners)
            {
                list.Add(new HostListener
                {
                    Protocol = "UDP",
                    Address = u.Address,
                    Port = u.Port.ToString(CultureInfo.InvariantCulture),
                    ProcessId = u.ProcessId,
                    Process = _processes.Resolve(u.ProcessId),
                    State = "BOUND"
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add("Listening sockets could not be read: " + FirstLine(ex.Message));
        }

        return list
            .OrderBy(l => l.Protocol, StringComparer.Ordinal)
            .ThenBy(l => int.TryParse(l.Port, out var p) ? p : int.MaxValue)
            .ThenBy(l => l.Address, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Marks each listener with what the inbound rules do to it. A socket bound to
    /// loopback is unreachable regardless; one that no allow rule matches is
    /// listening into a closed door, which is worth seeing next to the rule list.
    ///
    /// Windows evaluates blocks ahead of allows, so a matching block rule settles it
    /// whatever else admits the port.
    /// </summary>
    internal static void AnnotateCoverage(
        IReadOnlyList<HostListener> listeners,
        IReadOnlyList<FirewallRuleInfo> inbound,
        bool firewallEnabled,
        bool blocksInboundAlways = false)
    {
        // Only a block that covers every address decides a socket's reachability. The
        // app's own auto-blocks name one attacker each; reading those as "this port is
        // blocked" marked all 187 sockets on a live host Blocked, when what they close
        // is one address on all of them.
        var blocks = inbound.Where(r => r.IsBlock && MatchesEveryAddress(r.AddressListText)).ToList();
        var allows = inbound.Where(r => !r.IsBlock).ToList();

        foreach (var socket in listeners)
        {
            if (socket.Address is "127.0.0.1" or "::1")
            {
                socket.Covered = "Local only";
                continue;
            }
            if (!firewallEnabled)
            {
                socket.Covered = "No firewall";
                continue;
            }
            if (blocksInboundAlways || blocks.Any(r => Covers(r, socket)))
            {
                socket.Covered = "Blocked";
                continue;
            }

            var matched = false;
            var restricted = false;
            foreach (var rule in allows)
            {
                if (!Covers(rule, socket)) continue;
                matched = true;
                if (!MatchesEveryAddress(rule.AddressListText)) restricted = true;
                else { restricted = false; break; }
            }

            socket.Covered = matched ? (restricted ? "Restricted" : "Open") : "Not allowed";
        }
    }

    /// <summary>True when the rule decides what happens to traffic arriving at this socket.</summary>
    private static bool Covers(FirewallRuleInfo rule, HostListener socket)
    {
        var protocol = rule.ProtocolText;
        var protocolOk = protocol.Equals("Any", StringComparison.OrdinalIgnoreCase) ||
                         protocol.Equals("IP", StringComparison.OrdinalIgnoreCase) ||
                         protocol.Equals(socket.Protocol, StringComparison.OrdinalIgnoreCase);
        if (!protocolOk) return false;

        if (!PortMatches(rule.LocalPortsRaw.Length > 0 ? rule.LocalPortsRaw : rule.LocalPorts, socket.Port))
            return false;

        // A rule that names no program, no service and no port is a store-app rule:
        // Windows scopes those to a package SID, which netsh does not print, so the
        // one thing the row cannot tell us is which app it admits. Reading them as
        // "every socket" marked all 159 listeners on a live host Open — including
        // SMB and RDP, which the rules that really cover them scope to a program.
        // Ours are exempt: a catch-all this app wrote does cover everything.
        if (rule.IsForeign &&
            string.IsNullOrWhiteSpace(rule.Program) &&
            string.IsNullOrWhiteSpace(rule.Service) &&
            string.IsNullOrWhiteSpace(rule.LocalPortsRaw) &&
            string.IsNullOrWhiteSpace(rule.LocalPorts))
            return false;

        // A rule scoped to one program only decides that program's sockets. Comparing
        // image names is the most the two tables have in common: the rule names a path,
        // the socket names the process that holds it.
        var image = ProgramName(rule.Program);
        if (image.Length > 0 && !image.Equals(socket.Process, StringComparison.OrdinalIgnoreCase))
            return false;

        // A rule scoped to a Windows service admits that service's socket only. Which
        // service inside a shared host process owns a socket is not visible from here,
        // so a service rule counts for a service host and nothing else — erring
        // towards "something admits this" rather than calling an open port closed.
        if (!string.IsNullOrWhiteSpace(rule.Service) &&
            !socket.Process.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
            !socket.Process.Equals("System", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    /// <summary>
    /// True when a netsh port field covers the socket's port. An empty field is no
    /// constraint at all; a keyword field ("RPC", "IPHTTPS") names a port Windows
    /// picks at runtime, which cannot be resolved from here and so matches nothing.
    /// </summary>
    internal static bool PortMatches(string portField, string listenerPort)
    {
        var field = (portField ?? "").Trim();
        if (field.Length == 0) return true;
        if (!int.TryParse(listenerPort, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
            return false;

        foreach (var raw in field.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = raw.IndexOf('-');
            if (dash > 0 &&
                int.TryParse(raw[..dash], NumberStyles.Integer, CultureInfo.InvariantCulture, out var low) &&
                int.TryParse(raw[(dash + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var high))
            {
                if (port >= low && port <= high) return true;
                continue;
            }

            if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var single) && single == port)
                return true;
        }

        return false;
    }

    /// <summary>
    /// True when an address field admits every address. Token-wise, not by substring:
    /// "10.0.0.0/8" contains the characters "0.0.0.0" while admitting only a LAN, and
    /// reading that as wide open marks a restricted port Open.
    /// </summary>
    internal static bool MatchesEveryAddress(string addresses)
    {
        var tokens = (addresses ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length == 0) return true;
        return tokens.All(t =>
            t.Equals("All IPv4", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("All IPv6", StringComparison.OrdinalIgnoreCase) ||
            t.Equals("Any", StringComparison.OrdinalIgnoreCase) ||
            t is "0.0.0.0/0" or "::/0" or "*");
    }

    private static string FirstLine(string text)
    {
        var line = (text ?? "").Split('\n').FirstOrDefault(l => l.Trim().Length > 0) ?? "";
        return line.Trim();
    }
}
