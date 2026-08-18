using System.Globalization;
using System.Text.RegularExpressions;

namespace NetworkSentinel.Services;

/// <summary>
/// Writes rules through UFW, the way
/// <see href="https://github.com/davidfweiser/FireWallConfig">FireWallConfig</see>
/// does on Ubuntu.
///
/// Where UFW is installed it is the source of truth: it owns the nftables chains,
/// it re-applies its rule set at boot, and `ufw status` is what an operator reads
/// to find out what the machine allows. A rule this app wrote straight into
/// nftables was invisible there and did not survive `ufw reload`, so it looked
/// like the block had quietly stopped working. Going through UFW puts our rules
/// in the same list, in the same order, with the same lifetime as every other
/// rule on the host.
///
/// The command builders are static and pure so the suite can assert the exact
/// argv without a firewall.
/// </summary>
public static class UfwWriter
{
    /// <summary>Verb UFW uses for each action.</summary>
    private static string Verb(string action) =>
        action.Equals(FirewallRuleSpecs.ActionAllow, StringComparison.OrdinalIgnoreCase) ? "allow" : "deny";

    /// <summary>
    /// The commands that create one rule. A spec with several addresses or
    /// several port tokens becomes several UFW rules, because UFW takes one
    /// source and one port per invocation.
    /// </summary>
    public static IReadOnlyList<string[]> BuildAddCommands(FirewallRuleSpec spec)
    {
        var normalized = FirewallRuleSpecs.Normalize(spec);
        FirewallRuleSpecs.TryParsePorts(normalized.PortRange, out var ports, out _);
        FirewallRuleSpecs.TryParseAddresses(normalized.Addresses, out var addresses, out _);

        var verb = Verb(normalized.Action);
        var side = normalized.Direction.Equals(FirewallRuleSpecs.DirectionOutbound, StringComparison.OrdinalIgnoreCase)
            ? "out" : "in";
        var protocol = normalized.Protocol.ToLowerInvariant();
        var sources = addresses.Count > 0 ? addresses : new List<string> { "any" };
        var commands = new List<string[]>();

        // ICMP carries no ports; UFW rejects `proto icmp … port N` outright.
        if (protocol == "icmp")
        {
            foreach (var source in sources)
                commands.Add(Finish(new List<string> { "--force", verb, side, "proto", "icmp", "from", source }, normalized.Label));
            return commands;
        }

        var portTokens = ports.Count > 0 ? ports : new List<string> { "" };
        foreach (var source in sources)
        {
            foreach (var port in portTokens)
            {
                var argv = new List<string> { "--force", verb, side };

                // Protocol "Any" is left off entirely: UFW then covers tcp and udp,
                // which is what "any protocol on this port" means.
                if (protocol is "tcp" or "udp")
                    argv.AddRange(new[] { "proto", protocol });

                argv.AddRange(new[] { "from", source });
                if (port.Length > 0)
                    argv.AddRange(new[] { "to", "any", "port", port });

                commands.Add(Finish(argv, normalized.Label));
            }
        }

        return commands;
    }

    private static string[] Finish(List<string> argv, string label)
    {
        if (label.Length > 0)
        {
            argv.Add("comment");
            argv.Add(label);
        }
        return argv.ToArray();
    }

    /// <summary>
    /// Fallback delete: the add command with the verb swapped for
    /// <c>delete</c> and the comment dropped. Used when the numbered listing
    /// could not be read; UFW matches the rule by its shape.
    /// </summary>
    public static IReadOnlyList<string[]> BuildDeleteCommands(FirewallRuleSpec spec)
    {
        var commands = new List<string[]>();
        foreach (var add in BuildAddCommands(spec))
        {
            // add = ["--force", verb, side, …, "comment", label]
            var body = add.Skip(2).ToList();
            var comment = body.IndexOf("comment");
            if (comment >= 0) body = body.Take(comment).ToList();
            commands.Add(new[] { "--force", "delete" }.Concat(body).ToArray());
        }
        return commands;
    }

    private static readonly Regex NumberedRow = new(@"^\[\s*(\d+)\s*\]\s+(.*)$", RegexOptions.Compiled);

    /// <summary>Parses <c>ufw status numbered</c> into (number, rule) pairs.</summary>
    public static IReadOnlyList<(int Number, FirewallRuleInfo Rule)> ParseNumbered(string text)
    {
        var rows = new List<(int, FirewallRuleInfo)>();
        foreach (var raw in (text ?? "").Split('\n'))
        {
            var match = NumberedRow.Match(raw.Trim());
            if (!match.Success) continue;
            var rule = HostFirewallScanner.ParseUfwStatusLine(match.Groups[2].Value);
            if (rule == null) continue;
            rows.Add((int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture), rule));
        }
        return rows;
    }

    /// <summary>
    /// Every numbered row the target rule corresponds to. An "anywhere" rule has
    /// an IPv4 and an IPv6 twin and both must go, or the half left behind still
    /// admits traffic — the failure mode that makes a delete look like it worked
    /// when it did not.
    /// </summary>
    public static IReadOnlyList<int> MatchNumbers(
        FirewallRuleInfo target, IReadOnlyList<(int Number, FirewallRuleInfo Rule)> rows)
    {
        var hits = new List<int>();
        foreach (var (number, listed) in rows)
            if (SameRule(target, listed)) hits.Add(number);
        return hits;
    }

    private static bool SameRule(FirewallRuleInfo target, FirewallRuleInfo listed)
    {
        if (target.Direction != listed.Direction) return false;
        if (!target.ActionText.Equals(listed.ActionText, StringComparison.OrdinalIgnoreCase)) return false;
        if (!target.ProtocolText.Equals(listed.ProtocolText, StringComparison.OrdinalIgnoreCase)) return false;

        FirewallRuleSpecs.TryParsePorts(target.LocalPorts, out var targetPorts, out _);
        FirewallRuleSpecs.TryParsePorts(listed.LocalPorts, out var listedPorts, out _);
        if (!targetPorts.SequenceEqual(listedPorts, StringComparer.OrdinalIgnoreCase)) return false;

        FirewallRuleSpecs.TryParseAddresses(target.RemoteAddresses, out var targetAddresses, out _);
        FirewallRuleSpecs.TryParseAddresses(listed.RemoteAddresses, out var listedAddresses, out _);

        if (targetAddresses.Count == 0 && listedAddresses.Count == 0)
        {
            // Both mean "everywhere". If the target named one family only, match
            // just that family's row; otherwise take both twins.
            var raw = (target.RemoteAddresses ?? "").ToLowerInvariant();
            var listedIsV6 = (listed.RemoteAddresses ?? "").Contains("IPv6", StringComparison.OrdinalIgnoreCase);
            if (raw.Contains("all ipv4") && !raw.Contains("all ipv6")) return !listedIsV6;
            if (raw.Contains("all ipv6") && !raw.Contains("all ipv4")) return listedIsV6;
            return true;
        }

        return targetAddresses.SequenceEqual(listedAddresses, StringComparer.OrdinalIgnoreCase);
    }
}
