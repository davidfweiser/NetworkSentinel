using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Which front-end is driving <see cref="FirewallService"/>. The only thing it decides
/// is what can be said about a missing privilege: a desktop session or a terminal can
/// relaunch through UAC and have someone there to approve it, and the web console can
/// do neither — the operator is in a browser, and a consent dialog raised on the server
/// would appear on a desktop nobody is sitting at.
/// </summary>
public enum FirewallUiSurface
{
    /// <summary>The WPF GUI — UAC can prompt on this desktop.</summary>
    Desktop,

    /// <summary>The TUI on a console — UAC can prompt on the session it was launched from.</summary>
    Terminal,

    /// <summary>The headless web console — nothing can prompt.</summary>
    Web
}

/// <summary>
/// Manages Windows Defender Firewall rules owned by Network Sentinel.
/// Requires administrator privileges to add/remove rules.
/// </summary>
public sealed class FirewallService
{
    public const string RulePrefix = "NetworkSentinel";

    /// <summary>Optional allowlist — when set, known-good IPs cannot be blocked.</summary>
    public AllowlistService? Allowlist { get; set; }

    // Cached managed-rule list. Enumerating rules means spawning netsh and parsing the
    // full system rule dump — seconds on a busy server. The web UI polls state every
    // couple of seconds; without a cache those netsh processes pile up until the host
    // stops responding. Single-flight: only one dump runs at a time, callers get the
    // last known list meanwhile.
    private static readonly TimeSpan RuleCacheTtl = TimeSpan.FromSeconds(10);
    private readonly object _ruleCacheGate = new();
    private readonly object _ruleLoadLock = new();
    private IReadOnlyList<FirewallRuleInfo> _ruleCache = Array.Empty<FirewallRuleInfo>();
    private DateTime _ruleCacheAt = DateTime.MinValue;
    private bool _ruleRefreshInFlight;
    private int _ruleCacheGeneration;

    public bool IsAdministrator
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>Windows has no separate root; true when elevated (matches Linux API for TUI/Web).</summary>
    public bool IsRoot => IsAdministrator;

    /// <summary>
    /// Which front-end is running. Set once at startup by <c>Program</c>; the default
    /// suits the GUI, which is the one process that does not set it.
    /// </summary>
    public static FirewallUiSurface Surface { get; set; } = FirewallUiSurface.Desktop;

    /// <summary>
    /// True when a rule written now would actually reach the firewall.
    ///
    /// On Windows this is exactly <see cref="IsAdministrator"/>: netsh either has the
    /// elevated token or it does not, and there is no in-process way to acquire one.
    /// It exists as its own name because the front-ends ask this question rather than
    /// "am I an administrator", and because the Linux build's answer is genuinely a
    /// different one — there, elevation helpers can be installed but unable to prompt.
    /// Keeping the name identical is what lets the shared web and TUI code port across.
    /// </summary>
    public bool CanApplyRules => IsAdministrator;

    public string PrivilegeText => IsAdministrator
        ? "Running as Administrator — firewall rules can be applied."
        : Surface == FirewallUiSurface.Web
            ? "Not elevated, so the console cannot write rules: a UAC prompt would have to be approved " +
              "on the server, not in this browser. " + HeadlessElevationHelp(asBlock: false)
            : "Not elevated — use “Run as Admin” / authorize (UAC) to add or remove firewall rules.";

    /// <summary>
    /// What to do about a console that cannot write, as commands to run rather than a
    /// section to go and find. <paramref name="asBlock"/> keeps the newlines for a
    /// preformatted block; the flowed form is for a one-line status.
    /// </summary>
    public static string HeadlessElevationHelp(bool asBlock = true)
        => asBlock
            ? $"{HeadlessElevationLead}\n\n{ElevationInstallCommands()}\n\n{HeadlessElevationTail}"
            : $"{HeadlessElevationLead} {ElevationInstallCommands().Replace("\n", "  ")} {HeadlessElevationTail}";

    /// <summary>
    /// The commands on their own, so a front-end that can lay out a code block does not
    /// have to pick them back out of the prose. Re-registering the scheduled task is the
    /// supported fix: it runs as SYSTEM at boot, which is elevated without anyone
    /// approving anything. Starting the console by hand from an elevated prompt is the
    /// same privilege without the persistence, so it is offered second.
    /// </summary>
    public static string ElevationInstallCommands()
    {
        var exe = ProcessImagePath() ?? "NetworkSentinel.exe";
        return "powershell -ExecutionPolicy Bypass -File scripts\\install-web-service.ps1\n" +
               "schtasks /Run /TN \"NetworkSentinel-Web\"\n" +
               $"# or, from an elevated prompt:  \"{exe}\" -w";
    }

    /// <summary>Full path of the running image, so the pasted line points at this install.</summary>
    private static string? ProcessImagePath()
    {
        try
        {
            return Environment.ProcessPath;
        }
        catch
        {
            return null;
        }
    }

    public const string HeadlessElevationLead =
        "Run the console with an elevated token. The installed scheduled task already does — " +
        "it runs as SYSTEM at boot — so registering and starting it is the fix:";

    public const string HeadlessElevationTail =
        "Then use Rescan to re-check — see “Headless web console” in the README.";

    /// <summary>
    /// TUI/Web “Authorize” action. On Windows this relaunches the process elevated (UAC).
    ///
    /// Except from the web console, where relaunching is the wrong move twice over: the
    /// consent dialog would be raised on the server's desktop with nobody at it, and a
    /// success would tear down the very process serving the page that asked. There it
    /// reports what has to be done on the host instead.
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (IsAdministrator)
            return FirewallOperationResult.Ok("Already running as Administrator. Firewall rules can be applied.");

        if (Surface == FirewallUiSurface.Web)
            return FirewallOperationResult.Fail(
                "The web console cannot elevate itself: approving UAC would mean sitting at the server, " +
                "and restarting this process would drop the connection serving this page.\n\n" +
                HeadlessElevationHelp());

        try
        {
            RestartAsAdministrator();
            return FirewallOperationResult.Ok(
                "Relaunching elevated — approve the UAC prompt, then continue in the new window.");
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail($"Could not relaunch as Administrator: {ex.Message}");
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

        // Auto-block screens CGNAT out one gate earlier, so anything reaching here in
        // that range is a deliberate manual block.
        if (IsNeverBlockable(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

        // overrideAllowlist is only set from an explicit, confirmed user action —
        // auto-block never bypasses the allowlist.
        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

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

        InvalidateRuleCache();
        return ok
            ? FirewallOperationResult.Ok($"Blocked {normalized} ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockIp(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        var inName = IpRuleName(normalized, true);
        var outName = IpRuleName(normalized, false);
        var r1 = RemoveRuleByName(inName, out var o1);
        var r2 = RemoveRuleByName(outName, out var o2);
        InvalidateRuleCache();

        if (o1 == RemovalOutcome.Failed || o2 == RemovalOutcome.Failed)
            return o1 == RemovalOutcome.Failed ? r1 : r2;
        if (o1 == RemovalOutcome.Absent && o2 == RemovalOutcome.Absent)
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
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        // Safety: never silently block essential local services without user intent — still allow but warn for DNS etc.
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

        InvalidateRuleCache();
        return ok
            ? FirewallOperationResult.Ok($"Port {protocol}/{port} blocked ({direction}). " + string.Join(" ", results))
            : FirewallOperationResult.Fail(string.Join(" ", results));
    }

    public FirewallOperationResult UnblockPort(int port, string protocol)
    {
        protocol = (protocol ?? "TCP").Trim().ToUpperInvariant();
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        var r1 = RemoveRuleByName(PortRuleName(port, protocol, true), out var o1);
        var r2 = RemoveRuleByName(PortRuleName(port, protocol, false), out var o2);
        InvalidateRuleCache();
        if (o1 == RemovalOutcome.Failed || o2 == RemovalOutcome.Failed)
            return o1 == RemovalOutcome.Failed ? r1 : r2;
        if (o1 == RemovalOutcome.Absent && o2 == RemovalOutcome.Absent)
            return FirewallOperationResult.Fail($"No managed port rules for {protocol}/{port}.");

        return FirewallOperationResult.Ok($"Removed managed rules for {protocol}/{port}.");
    }

    public FirewallOperationResult RemoveRule(string ruleName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(ruleName) || !IsManagedRuleName(ruleName))
                return FirewallOperationResult.Fail("Only Network Sentinel managed rules (IP/Port/Web) can be removed here.");

            if (!IsAdministrator)
                return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

            var name = ruleName.Trim();

            // Blocks are created as an -In/-Out pair. Removing only the clicked row left
            // the sibling active, so the IP stayed blocked and remove "didn't work".
            //
            // Config rules are never paired, and their names end in an operator's
            // label — a rule labelled "vpn-In" would otherwise drag an unrelated
            // "vpn-Out" rule out of the firewall with it.
            var isPaired = !IsConfigRuleName(name);
            var siblings = new List<string> { name };
            if (isPaired && name.EndsWith("-In", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-In".Length] + "-Out");
            else if (isPaired && name.EndsWith("-Out", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-Out".Length] + "-In");

            var removed = new List<string>();
            string? firstError = null;
            string? stillInForce = null;
            foreach (var sibling in siblings)
            {
                var r = RemoveRuleByName(sibling, out var outcome);
                if (outcome == RemovalOutcome.Removed)
                    removed.Add(sibling);
                else if (outcome == RemovalOutcome.Failed)
                    stillInForce ??= r.Message;
                else if (sibling == name)
                    firstError = r.Message;
            }

            InvalidateRuleCache();

            // Half a pair still in place is still a block: say so rather than report
            // the half that went.
            if (stillInForce != null)
                return FirewallOperationResult.Fail(stillInForce);

            if (removed.Count == 0)
                return FirewallOperationResult.Fail(firstError ?? $"No rule named \"{name}\".");

            return FirewallOperationResult.Ok(removed.Count > 1
                ? $"Removed inbound + outbound rules ({removed[0]} and its pair)."
                : $"Removed \"{removed[0]}\".");
        }
        catch (Exception ex)
        {
            // Never let firewall COM/netsh failures tear down the web host process.
            return FirewallOperationResult.Fail($"Remove failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Deletes a rule that came from a host scan rather than from this app's own
    /// rules — one Windows shipped, or one an installer wrote. The Firewall Config
    /// view lists the whole host firewall, so Delete has to work on rows Network
    /// Sentinel did not write; refusing them would make the list a read-only report
    /// with buttons that lie.
    /// </summary>
    public FirewallOperationResult DeleteHostRule(FirewallRuleInfo? rule)
    {
        if (rule == null)
            return FirewallOperationResult.Fail("No rule to remove.");

        // One of ours: through the managed path, which clears the expiry ledger and
        // takes the rule's -In/-Out sibling with it.
        if (!rule.IsForeign)
            return RemoveRule(rule.Name);

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");
        if (string.IsNullOrWhiteSpace(rule.Name))
            return FirewallOperationResult.Fail(
                "That rule has no name to delete it by — remove it in Windows Defender Firewall (wf.msc).");

        // netsh deletes by match, not by identity, and Windows rule names are not
        // unique: 685 rules on this host can share one name. Every field the row
        // displays goes in as a filter so the delete takes the rules the row stands
        // for and nothing beside them. "Any" values are left out — netsh reads them
        // as filters too, and no rule matches a filter of "any".
        var args = new StringBuilder($"advfirewall firewall delete rule name=\"{Escape(rule.Name)}\"");
        args.Append(rule.IsInbound ? " dir=in" : " dir=out");

        if (!rule.ProtocolText.Equals(FirewallRuleSpecs.ProtocolAny, StringComparison.OrdinalIgnoreCase))
            args.Append($" protocol={Escape(rule.ProtocolText)}");
        if (!string.IsNullOrWhiteSpace(rule.LocalPortsRaw))
            args.Append($" localport=\"{Escape(NetshList(rule.LocalPortsRaw))}\"");
        if (!string.IsNullOrWhiteSpace(rule.RemotePortsRaw))
            args.Append($" remoteport=\"{Escape(NetshList(rule.RemotePortsRaw))}\"");
        if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            args.Append($" remoteip=\"{Escape(NetshList(rule.RemoteAddresses))}\"");
        if (!string.IsNullOrWhiteSpace(rule.Program))
            args.Append($" program=\"{Escape(rule.Program)}\"");

        FirewallOperationResult result;
        try { result = RunNetsh(args.ToString()); }
        catch (Exception ex) { return FirewallOperationResult.Fail($"Remove failed: {ex.Message}"); }

        InvalidateRuleCache();

        if (!result.Success)
            return FirewallOperationResult.Fail(
                $"Windows Defender Firewall refused the delete: {result.Message}");

        // netsh answers "Deleted N rule(s)." — worth repeating, because one row can
        // stand for a set of identical rules and N is how many really went.
        var count = Regex.Match(result.Message, @"Deleted\s+(\d+)\s+rule", RegexOptions.IgnoreCase);
        var howMany = count.Success && count.Groups[1].Value != "1"
            ? $" ({count.Groups[1].Value} identical rules)"
            : "";
        return FirewallOperationResult.Ok($"Removed “{rule.LabelText}” from Windows Defender Firewall{howMany}.");
    }

    /// <summary>A display list ("80, 443") as netsh wants it, with no spaces.</summary>
    private static string NetshList(string value)
        => string.Join(",", SplitList(value));

    /// <param name="skip">Rules to leave in place (e.g. the web console's own allow rule).</param>
    public FirewallOperationResult RemoveAllManagedRules(Func<FirewallRuleInfo, bool>? skip = null)
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        var rules = GetManagedRules();
        int removed = 0;
        int kept = 0;
        int failed = 0;
        foreach (var rule in rules)
        {
            if (skip != null && skip(rule))
            {
                kept++;
                continue;
            }
            RemoveRuleByName(rule.Name, out var outcome);
            if (outcome == RemovalOutcome.Removed) removed++;
            else if (outcome == RemovalOutcome.Failed) failed++;
        }

        InvalidateRuleCache();
        var msg = $"Removed {removed} Network Sentinel firewall rule(s).";
        if (kept > 0)
            msg += $" Kept {kept} (web console access).";
        if (failed > 0)
            return FirewallOperationResult.Fail(msg + $" {failed} could not be removed and may still be in force — see the rule list.");
        return FirewallOperationResult.Ok(msg);
    }

    /// <summary>
    /// Removes any Network Sentinel IP-block rules that target allowlisted addresses
    /// (recovery if GitHub/Grok/etc. were blocked before the allowlist existed).
    /// </summary>
    public FirewallOperationResult UnblockAllowlistedAddresses()
    {
        if (Allowlist == null)
            return FirewallOperationResult.Fail("Allowlist is not available.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to remove firewall rules.");

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

        InvalidateRuleCache();
        if (removed == 0)
            return FirewallOperationResult.Ok("No allowlisted IPs were blocked by Network Sentinel rules.");

        return FirewallOperationResult.Ok(
            $"Restored {removed} allowlisted address(es): {string.Join("; ", notes.Take(12))}" +
            (notes.Count > 12 ? "…" : ""));
    }

    // ── Firewall Config rules (operator-authored) ────────────────────────

    /// <summary>
    /// Why an operator's Allow rule can never reopen an address auto-block just
    /// shut — and why, unlike the other builds, this one has to do nothing to get
    /// that.
    ///
    /// The macOS build regenerates one PF anchor from the ledger on every change
    /// and fixes precedence by emitting app-minted blocks first; the Linux build
    /// adds rules to live nft/iptables chains that are first-match-wins, so it has
    /// to insert app blocks at the head of the chain and append config rules.
    ///
    /// Windows Firewall is not evaluated in creation order at all. It groups rules
    /// by type and evaluates the groups: connection-security rules, then
    /// authenticated bypass, then <b>block</b>, then <b>allow</b>, then the
    /// profile default. A block therefore beats an allow whatever order they were
    /// written in, so an operator's Allow rule cannot reopen an address auto-block
    /// just shut, and the app never needs to order its writes.
    ///
    /// The one thing that <em>would</em> defeat an app-minted block is an
    /// authenticated-bypass rule (netsh's <c>security=authenticate</c> with
    /// <c>action=bypass</c>), which outranks block rules. The Firewall Config view
    /// writes plain allow/block rules and offers no way to author one.
    /// </summary>
    internal const string PrecedenceNote =
        "Windows Firewall evaluates block rules ahead of allow rules, so write order does not matter";

    /// <summary>Name prefix for the rules the Firewall Config view writes.</summary>
    internal const string ConfigRulePrefix = RulePrefix + "-Rule-";

    /// <summary>
    /// Every managed rule with the operator's config rules last. The flat rule
    /// list sorts for display; this is the order the Firewall Config view shows,
    /// where app-minted blocks are listed first because they are the ones that
    /// take effect first (see <see cref="PrecedenceNote"/>).
    /// </summary>
    public IReadOnlyList<FirewallRuleInfo> GetConfigRules()
        => GetManagedRules()
            .OrderBy(r => r.Kind == FirewallRuleKind.Custom ? 1 : 0)
            .ToList();

    /// <summary>
    /// Creates or replaces one operator-authored rule. Passing
    /// <paramref name="replaceName"/> edits in place: the old firewall rule is
    /// dropped and the new one written in its place.
    /// </summary>
    public FirewallOperationResult SaveCustomRule(FirewallRuleSpec spec, string? replaceName = null)
    {
        // Validate before normalising — see FirewallRuleSpecs.TryPrepare for why the
        // other order turns an unparseable port range into "every port".
        if (!FirewallRuleSpecs.TryPrepare(spec, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        if (!string.IsNullOrWhiteSpace(replaceName))
        {
            var existing = GetManagedRules().FirstOrDefault(r =>
                string.Equals(r.Name, replaceName, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
                return FirewallOperationResult.Fail($"No rule named \"{replaceName}\" to edit — it may have been removed.");
            if (existing.Kind != FirewallRuleKind.Custom)
                return FirewallOperationResult.Fail("Only Firewall Config rules can be edited here.");

            RemoveRuleByName(replaceName!);
            // The replaced name has to be free again before the new one is minted,
            // or an edit that keeps the label would come back as "…-2".
            InvalidateRuleCache();
        }

        var name = UniqueCustomRuleName(normalized.Label, GetManagedRules());
        var rule = FirewallRuleSpecs.ToRule(normalized, name);
        var applied = ApplyCustomRule(rule);
        InvalidateRuleCache();

        if (!applied.Success)
        {
            // A rule the firewall would not take must not stay behind claiming to be
            // in force. Any fragment that did load is torn back out, so a
            // half-applied rule cannot survive as a silent partial block.
            RemoveRuleByName(name);
            InvalidateRuleCache();
            return FirewallOperationResult.Fail($"The rule was rejected, so it was not kept: {applied.Message}");
        }

        return FirewallOperationResult.Ok(string.IsNullOrWhiteSpace(replaceName)
            ? $"Added rule \"{normalized.Label}\"."
            : $"Saved rule \"{normalized.Label}\".");
    }

    /// <summary>
    /// Writes one config rule's firewall rules. A spec usually needs exactly one —
    /// netsh takes a whole address list, both families together, in a single rule —
    /// but a port range under protocol Any splits into TCP and UDP, and ICMP splits
    /// into icmpv4 and icmpv6. Every fragment carries the same rule name, so a
    /// later delete by name takes all of them.
    /// </summary>
    private FirewallOperationResult ApplyCustomRule(FirewallRuleInfo rule)
    {
        var matches = FirewallRuleSpecs.BuildNetshMatches(rule);
        if (matches.Count == 0)
            return FirewallOperationResult.Fail("The rule matched nothing to write.");

        var dir = rule.IsInbound ? "in" : "out";
        var action = rule.IsBlock ? "block" : "allow";

        foreach (var fragment in matches)
        {
            var netsh = RunNetsh(
                $"advfirewall firewall add rule name=\"{rule.Name}\" dir={dir} action={action} " +
                $"{fragment.Match} enable={(rule.Enabled ? "yes" : "no")} profile=any " +
                $"description=\"{Escape(rule.Description)}\"");
            if (!netsh.Success)
                return FirewallOperationResult.Fail($"Failed to add rule {rule.Name}: {netsh.Message}");
        }

        return FirewallOperationResult.Ok($"Rule \"{rule.Name}\" applied.");
    }

    /// <summary>Rule names are the key, so a repeated label gets a suffix.</summary>
    private static string UniqueCustomRuleName(string label, IReadOnlyList<FirewallRuleInfo> existing)
    {
        var baseName = ConfigRulePrefix + Sanitize(label);
        var name = baseName;
        var suffix = 2;
        while (existing.Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
            name = $"{baseName}-{suffix++}";
        return name;
    }

    /// <summary>True for the rules the Firewall Config view writes.</summary>
    internal static bool IsConfigRuleName(string? name)
        => !string.IsNullOrWhiteSpace(name) &&
           name.StartsWith(ConfigRulePrefix, StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<FirewallRuleInfo> GetManagedRules()
    {
        // netsh ONLY. Never call HNetCfg COM from the web host:
        // - COM is not MTA-safe (HttpListener handlers run on thread-pool MTA)
        // - AccessViolation from COM kills the entire process (looks like a "crash on Remove")
        // - Falling back to COM when the list is empty was the remove-after-delete crash path
        bool startBackgroundRefresh = false;
        lock (_ruleCacheGate)
        {
            var haveData = _ruleCacheAt != DateTime.MinValue;
            var fresh = haveData && DateTime.UtcNow - _ruleCacheAt < RuleCacheTtl;
            if (fresh || (haveData && _ruleRefreshInFlight))
                return _ruleCache;

            if (haveData)
            {
                // Stale but usable: serve it now, refresh off the request path.
                _ruleRefreshInFlight = true;
                startBackgroundRefresh = true;
            }
        }

        if (startBackgroundRefresh)
        {
            var snapshot = _ruleCache;
            _ = Task.Run(() =>
            {
                try { LoadRulesBlocking(); }
                finally { lock (_ruleCacheGate) _ruleRefreshInFlight = false; }
            });
            return snapshot;
        }

        // No data yet (first call, or cache invalidated after a mutation): load now so
        // the caller sees the post-change rule list.
        return LoadRulesBlocking();
    }

    /// <summary>Force the next GetManagedRules to re-enumerate (call after add/remove).</summary>
    public void InvalidateRuleCache()
    {
        lock (_ruleCacheGate)
        {
            _ruleCacheAt = DateTime.MinValue;
            _ruleCacheGeneration++;
        }
    }

    private IReadOnlyList<FirewallRuleInfo> LoadRulesBlocking()
    {
        // One netsh dump at a time — a stampede of these is what made the web UI hang.
        lock (_ruleLoadLock)
        {
            int generation;
            lock (_ruleCacheGate)
            {
                if (_ruleCacheAt != DateTime.MinValue && DateTime.UtcNow - _ruleCacheAt < RuleCacheTtl)
                    return _ruleCache;
                generation = _ruleCacheGeneration;
            }

            try
            {
                var list = GetManagedRulesNetsh();
                lock (_ruleCacheGate)
                {
                    // A rule was added/removed while this dump ran — don't publish stale
                    // data (a just-removed rule would reappear in the UI for one TTL).
                    if (generation == _ruleCacheGeneration)
                    {
                        _ruleCache = list;
                        _ruleCacheAt = DateTime.UtcNow;
                    }
                }
                return list;
            }
            catch
            {
                return _ruleCache;
            }
        }
    }

    public bool IsIpBlocked(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out _))
            return false;

        var rules = GetManagedRules();
        return rules.Any(r =>
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
    /// Turns on Windows Firewall dropped-packet logging for every profile, so
    /// probes to ports this machine does not accept leave a log line. Those
    /// packets never reach the TCP stack, so connection polling cannot see them
    /// (see <see cref="ProbeLogMonitor"/>). Logging is a firewall setting, not a
    /// rule — nothing is blocked or allowed by turning it on, and the log is
    /// capped at MaxFileSize with rotation by the firewall service itself.
    /// </summary>
    public FirewallOperationResult EnableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to change firewall logging.");

        // Give the log an explicit path + size cap when the profile has none, so
        // the monitor knows where to look and the file cannot grow unbounded.
        var current = ReadLoggingSettings();
        if (string.IsNullOrWhiteSpace(current.FileName))
        {
            RunNetsh($"advfirewall set allprofiles logging filename \"{DefaultProbeLogPath}\"");
            RunNetsh("advfirewall set allprofiles logging maxfilesize 4096");
        }

        var applied = RunNetsh("advfirewall set allprofiles logging droppedconnections enable");
        if (!applied.Success)
            return FirewallOperationResult.Fail($"Failed to enable dropped-packet logging: {applied.Message}");

        return FirewallOperationResult.Ok($"Dropped-packet logging enabled ({ResolveProbeLogPath()}).");
    }

    public FirewallOperationResult DisableProbeLogging()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to change firewall logging.");

        var applied = RunNetsh("advfirewall set allprofiles logging droppedconnections disable");
        return applied.Success
            ? FirewallOperationResult.Ok("Dropped-packet logging disabled.")
            : FirewallOperationResult.Fail($"Failed to disable dropped-packet logging: {applied.Message}");
    }

    /// <summary>True when at least one profile is logging dropped packets.</summary>
    public bool IsProbeLoggingInstalled() => ReadLoggingSettings().DroppedEnabled;

    /// <summary>
    /// Path the firewall writes dropped packets to. Falls back to the Windows
    /// default when the setting cannot be read (netsh output is localized, so
    /// parsing is best-effort — the default is correct on a stock install).
    /// </summary>
    public static string ResolveProbeLogPath()
    {
        var name = ReadLoggingSettings().FileName;
        return string.IsNullOrWhiteSpace(name) ? DefaultProbeLogPath : name;
    }

    private static string DefaultProbeLogPath => Path.Combine(
        Environment.SystemDirectory, "LogFiles", "Firewall", "pfirewall.log");

    /// <summary>
    /// Parses `netsh advfirewall show allprofiles logging`. Its output is
    /// "Key<spaces>Value" per line, repeated per profile; a value found in any
    /// profile is good enough for both callers.
    /// </summary>
    private static (bool DroppedEnabled, string FileName) ReadLoggingSettings()
    {
        var dropped = false;
        var fileName = "";

        var result = RunNetsh("advfirewall show allprofiles logging");
        if (string.IsNullOrWhiteSpace(result.Message))
            return (dropped, fileName);

        foreach (var raw in result.Message.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("LogDroppedConnections", StringComparison.OrdinalIgnoreCase))
            {
                var value = line["LogDroppedConnections".Length..].Trim();
                if (value.StartsWith("Enable", StringComparison.OrdinalIgnoreCase))
                    dropped = true;
            }
            else if (line.StartsWith("FileName", StringComparison.OrdinalIgnoreCase))
            {
                var value = line["FileName".Length..].Trim();
                if (!string.IsNullOrWhiteSpace(value) && fileName.Length == 0)
                    fileName = Environment.ExpandEnvironmentVariables(value);
            }
        }

        return (dropped, fileName);
    }

    public void RestartAsAdministrator(string? arguments = null)
    {
        var exe = Environment.ProcessPath
                  ?? Process.GetCurrentProcess().MainModule?.FileName
                  ?? throw new InvalidOperationException("Could not resolve executable path.");

        // Preserve --tui / -w so server modes come back elevated.
        if (arguments == null)
        {
            var args = Environment.GetCommandLineArgs().Skip(1)
                .Select(a => a.Contains(' ') ? $"\"{a}\"" : a);
            arguments = string.Join(" ", args);
        }

        var start = new ProcessStartInfo(exe)
        {
            UseShellExecute = true,
            Verb = "runas",
            Arguments = arguments
        };

        Process.Start(start);
    }

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason, TimeSpan? expiresAfter = null)
    {
        var name = IpRuleName(ip, isInbound);
        RemoveRuleByName(name); // replace cleanly

        var dir = isInbound ? "in" : "out";
        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";
        // netsh ONLY — HNetCfg COM from web/thread-pool (MTA) can AccessViolation and kill the process.
        var netsh = RunNetsh(
            $"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block remoteip={ip} enable=yes profile=any description=\"{Escape(description)}\"");
        if (!netsh.Success)
            return FirewallOperationResult.Fail($"Failed to add rule {name}: {netsh.Message}");

        // netsh has no expiry of its own, so it is tracked alongside the rule
        // and enforced by the sweep below.
        ExpiryLedger.Set(name, expiresAfter.HasValue ? DateTime.UtcNow + expiresAfter.Value : null);
        return FirewallOperationResult.Ok($"Rule \"{name}\" applied.");
    }

    private FirewallOperationResult EnsurePortRule(int port, string protocol, bool isInbound, string? reason)
    {
        var name = PortRuleName(port, protocol, isInbound);
        RemoveRuleByName(name);

        var dir = isInbound ? "in" : "out";
        var description = reason ?? $"Port blocked by Network Sentinel at {DateTime.Now:u}";
        var netsh = RunNetsh(
            $"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block protocol={protocol} localport={port} enable=yes profile=any description=\"{Escape(description)}\"");
        return netsh.Success
            ? FirewallOperationResult.Ok($"Rule \"{name}\" applied.")
            : FirewallOperationResult.Fail($"Failed to add rule {name}: {netsh.Message}");
    }

    /// <summary>What a removal found: the rule taken out, never there, or still in place.</summary>
    internal enum RemovalOutcome { Removed, Absent, Failed }

    /// <summary>
    /// Removes one managed rule. For callers that only want the name free (replacing a
    /// rule before writing it again); anything that reports the removal to the operator,
    /// or forgets the rule on the strength of it, uses the overload that says what
    /// really happened.
    /// </summary>
    private FirewallOperationResult RemoveRuleByName(string name)
        => RemoveRuleByName(name, out _, confirmAbsence: false);

    /// <summary>
    /// Removes one managed rule and says what really happened. A delete netsh would not
    /// carry out used to be indistinguishable from a rule that was never there: both
    /// came back as a plain failure, so unblock answered "no block rules found" for an
    /// address that was still blocked, and the expiry sweep forgot a rule it had failed
    /// to remove — leaving a block in force that nothing would ever look for again.
    /// </summary>
    /// <param name="confirmAbsence">
    /// netsh's "no rules match" text is localized, so a failure it does not word that
    /// way is checked against the live rule list before it is called either thing.
    /// False skips that listing, and reports such a failure as <see cref="RemovalOutcome.Failed"/>.
    /// </param>
    private FirewallOperationResult RemoveRuleByName(string name, out RemovalOutcome outcome, bool confirmAbsence = true)
    {
        // netsh ONLY — never HNetCfg COM. COM remove/enumerate from MTA thread-pool
        // workers (web UI) can AccessViolation and kill NetworkSentinel.exe.
        var safeName = name.Replace("\"", "").Trim();
        if (string.IsNullOrEmpty(safeName))
        {
            outcome = RemovalOutcome.Absent;
            return FirewallOperationResult.Fail("Rule name is empty.");
        }

        var netsh = RunNetsh($"advfirewall firewall delete rule name=\"{safeName}\"");
        if (netsh.Success)
        {
            outcome = RemovalOutcome.Removed;
            return FirewallOperationResult.Ok($"Removed \"{safeName}\".");
        }

        var absent = LooksLikeNoMatchingRule(netsh.Message);
        if (!absent && confirmAbsence)
        {
            var listing = RunNetsh("advfirewall firewall show rule name=all");
            absent = listing.Success && !string.IsNullOrWhiteSpace(listing.Message)
                     && !ListingNamesRule(listing.Message, safeName);
        }

        if (absent)
        {
            outcome = RemovalOutcome.Absent;
            return FirewallOperationResult.Fail($"No rule named \"{safeName}\" (it may already be gone).");
        }

        outcome = RemovalOutcome.Failed;
        return FirewallOperationResult.Fail(
            $"Could not remove \"{safeName}\" — it may still be in force. {netsh.Message}".TrimEnd());
    }

    /// <summary>netsh's answer (as <see cref="RunNetsh"/> relays it) for a delete that matched nothing.</summary>
    internal static bool LooksLikeNoMatchingRule(string message)
        => message.Contains("No rules match", StringComparison.OrdinalIgnoreCase)
           || message.Contains("No matching rule", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether a <c>netsh advfirewall firewall show rule name=all</c> dump lists a rule
    /// with exactly this name. The field label in front of it is localized, so the test
    /// is on the value: a line that ends with the whole name, after the label's padding.
    /// Whole-name matters — "…-Rule-SSH" must not be found in "…-Rule-SSH-2".
    /// </summary>
    internal static bool ListingNamesRule(string listing, string name)
    {
        foreach (var raw in listing.Split('\n'))
        {
            var line = raw.TrimEnd();
            if (!line.EndsWith(name, StringComparison.OrdinalIgnoreCase)) continue;

            var before = line.Length - name.Length - 1;
            if (before >= 0 && char.IsWhiteSpace(line[before]))
                return true;
        }
        return false;
    }

    /// <summary>
    /// True only for rules this app creates (IP block / port block / web UI allow).
    /// Avoids matching Windows "networksentinel.exe" program rules that share the prefix.
    /// </summary>
    public static bool IsManagedRuleName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        return name.StartsWith(RulePrefix + "-IP-", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith(RulePrefix + "-Port-", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith(RulePrefix + "-Web-", StringComparison.OrdinalIgnoreCase)
               || name.StartsWith(ConfigRulePrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static FirewallRuleKind ClassifyRuleKind(string name, string remote, string localPorts)
    {
        // Tested first: the rest of this method matches on "-IP-" and "-Port-"
        // anywhere in the name, and an operator is free to label a config rule
        // "block-IP-scanner".
        if (IsConfigRuleName(name))
            return FirewallRuleKind.Custom;

        if (name.StartsWith(RulePrefix + "-IP-", StringComparison.OrdinalIgnoreCase)
            || name.Contains("-IP-", StringComparison.OrdinalIgnoreCase))
            return FirewallRuleKind.IpBlock;
        if (name.StartsWith(RulePrefix + "-Port-", StringComparison.OrdinalIgnoreCase)
            || name.Contains("-Port-", StringComparison.OrdinalIgnoreCase))
            return FirewallRuleKind.PortBlock;
        // Web installer allow rules: NetworkSentinel-Web-18765
        if (name.StartsWith(RulePrefix + "-Web-", StringComparison.OrdinalIgnoreCase))
            return FirewallRuleKind.Other;
        if (!string.IsNullOrWhiteSpace(remote) && remote is not ("Any" or "*"))
            return FirewallRuleKind.IpBlock;
        if (!string.IsNullOrWhiteSpace(localPorts))
            return FirewallRuleKind.PortBlock;
        return FirewallRuleKind.Other;
    }

    private static List<FirewallRuleInfo> GetManagedRulesNetsh()
    {
        // Non-verbose still includes every field we parse (name, enabled, direction,
        // remote IP, local/remote port, protocol, action, description) at a fraction
        // of the output size.
        var result = RunNetsh("advfirewall firewall show rule name=all");
        if (!result.Success && string.IsNullOrWhiteSpace(result.Message))
            return new List<FirewallRuleInfo>();

        return MergeConfigFragments(ParseNetshRules(result.Message));
    }

    /// <summary>
    /// One rule as netsh printed it, before anything is made of the values. Two
    /// readers walk the same dump — the managed-rule list below, and the whole-host
    /// scan in <see cref="HostFirewallScanner"/> — so the line handling and netsh's
    /// wrapped-list continuations live in one place rather than being written twice.
    /// </summary>
    internal sealed class NetshRuleBlock
    {
        public string Name { get; set; } = "";
        public string Enabled { get; set; } = "";
        public string Direction { get; set; } = "";
        public string Description { get; set; } = "";
        public string RemoteIp { get; set; } = "";
        public string LocalPort { get; set; } = "";
        public string RemotePort { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string Action { get; set; } = "";

        public string Grouping { get; set; } = "";
        public string Profiles { get; set; } = "";

        // Verbose-only: `show rule name=all` without verbose prints no Program or
        // Service line at all. Empty reads the same way as "not constrained", which
        // is what a rule without one means, so the managed reader below is
        // unaffected by which form of the dump it was handed.
        public string Program { get; set; } = "";
        public string Service { get; set; } = "";

        public bool IsOutbound => Direction.Contains("Out", StringComparison.OrdinalIgnoreCase);
        public bool IsEnabled => Enabled.Contains("Yes", StringComparison.OrdinalIgnoreCase);
        public bool IsBlock => Action.Contains("Block", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Splits a <c>netsh advfirewall firewall show rule</c> dump into one block per
    /// rule. Split out from the netsh call so the parsing is testable.
    /// </summary>
    internal static IEnumerable<NetshRuleBlock> ScanNetshBlocks(string dump)
    {
        NetshRuleBlock? current = null;

        // netsh wraps a long address or port list onto following indented lines, so
        // the field it belongs to has to stay selected across them.
        string? continuing = null;

        foreach (var raw in (dump ?? "").Split('\n'))
        {
            var line = raw.TrimEnd('\r');

            // Indented and not a key of its own: the tail of the list above it.
            if (current != null && continuing != null && line.Length > 0 && char.IsWhiteSpace(line[0]))
            {
                var tail = line.Trim();
                if (tail.Length > 0)
                {
                    switch (continuing)
                    {
                        case "remoteip": current.RemoteIp = Append(current.RemoteIp, tail); break;
                        case "localport": current.LocalPort = Append(current.LocalPort, tail); break;
                        case "remoteport": current.RemotePort = Append(current.RemotePort, tail); break;
                    }
                    continue;
                }
            }

            continuing = null;

            if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
            {
                if (current != null) yield return current;
                current = new NetshRuleBlock { Name = NetshField(line, "Rule Name:") };
            }
            else if (current == null)
            {
                // netsh prints a banner before the first rule; nothing to attach it to.
            }
            else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                current.Enabled = NetshField(line, "Enabled:");
            else if (line.StartsWith("Direction:", StringComparison.OrdinalIgnoreCase))
                current.Direction = NetshField(line, "Direction:");
            else if (line.StartsWith("Description:", StringComparison.OrdinalIgnoreCase))
                current.Description = NetshField(line, "Description:");
            else if (line.StartsWith("Grouping:", StringComparison.OrdinalIgnoreCase))
                current.Grouping = NetshField(line, "Grouping:");
            else if (line.StartsWith("Profiles:", StringComparison.OrdinalIgnoreCase))
                current.Profiles = NetshField(line, "Profiles:");
            else if (line.StartsWith("Program:", StringComparison.OrdinalIgnoreCase))
                current.Program = NetshField(line, "Program:");
            else if (line.StartsWith("Service:", StringComparison.OrdinalIgnoreCase))
                current.Service = NetshField(line, "Service:");
            else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
            {
                current.RemoteIp = NetshField(line, "RemoteIP:");
                continuing = "remoteip";
            }
            else if (line.StartsWith("LocalPort:", StringComparison.OrdinalIgnoreCase))
            {
                current.LocalPort = NetshField(line, "LocalPort:");
                continuing = "localport";
            }
            else if (line.StartsWith("RemotePort:", StringComparison.OrdinalIgnoreCase))
            {
                current.RemotePort = NetshField(line, "RemotePort:");
                continuing = "remoteport";
            }
            else if (line.StartsWith("Protocol:", StringComparison.OrdinalIgnoreCase))
                current.Protocol = NetshField(line, "Protocol:");
            else if (line.StartsWith("Action:", StringComparison.OrdinalIgnoreCase))
                current.Action = NetshField(line, "Action:");
        }

        if (current != null) yield return current;
    }

    private static string NetshField(string line, string key) => line[key.Length..].Trim();

    /// <summary>
    /// Parses a <c>netsh advfirewall firewall show rule</c> dump into one entry per
    /// rule Network Sentinel owns. Everything else on the host is skipped here and
    /// read by <see cref="HostFirewallScanner"/> instead.
    /// </summary>
    internal static List<FirewallRuleInfo> ParseNetshRules(string dump)
    {
        var list = new List<FirewallRuleInfo>();
        foreach (var block in ScanNetshBlocks(dump))
        {
            if (string.IsNullOrWhiteSpace(block.Name) || !IsManagedRuleName(block.Name)) continue;
            list.Add(FromManagedBlock(block));
        }
        return list;
    }

    /// <summary>One rule of ours, read the way the app's own views expect it.</summary>
    private static FirewallRuleInfo FromManagedBlock(NetshRuleBlock block)
    {
        var isConfig = IsConfigRuleName(block.Name);

        // A config rule owns its whole address list, CIDR and all. Everything
        // else targets one address, and the display has always shown just that.
        var remoteNorm = isConfig ? NormalizeRemoteList(block.RemoteIp) : NormalizeRemote(block.RemoteIp);

        // Config rules write the port the operator meant: the local port on the
        // way in, the port being reached on the way out. App-minted port blocks
        // use the local port in both directions.
        var portField = isConfig && block.IsOutbound ? block.RemotePort : block.LocalPort;
        var portsNorm = NormalizePorts(portField);

        var protoNorm = string.IsNullOrWhiteSpace(block.Protocol) ? "Any" : block.Protocol.Trim();
        if (isConfig && protoNorm.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase))
            protoNorm = "ICMP"; // netsh spells the two families apart; the spec does not

        return new FirewallRuleInfo
        {
            Name = block.Name,
            Label = isConfig ? block.Name[ConfigRulePrefix.Length..] : "",
            Enabled = block.IsEnabled,
            IsBlock = block.IsBlock,
            Direction = block.IsOutbound ? FirewallDirection.Outbound : FirewallDirection.Inbound,
            RemoteAddresses = remoteNorm,
            LocalPorts = portsNorm,
            Protocol = protoNorm,
            Kind = ClassifyRuleKind(block.Name, remoteNorm, portsNorm),
            Description = block.Description,
            Profiles = block.Profiles,
            Program = block.Program,
            Service = block.Service,
            ExpiresUtc = ExpiryLedger.Get(block.Name)
        };
    }

    private static string Append(string list, string tail)
        => list.Length == 0 ? tail : list.TrimEnd(',') + "," + tail;

    /// <summary>
    /// One config rule can need more than one firewall rule — a port range under
    /// protocol Any becomes TCP and UDP, ICMP becomes icmpv4 and icmpv6 — and every
    /// fragment carries the same name. Reading them back as separate rows would show
    /// the operator two rules they did not write, and would hand the Edit button a
    /// spec that is not the one they typed, so the fragments are folded back into
    /// the rule they came from.
    /// </summary>
    internal static List<FirewallRuleInfo> MergeConfigFragments(List<FirewallRuleInfo> rules)
    {
        var merged = new List<FirewallRuleInfo>();
        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in rules)
        {
            if (rule.Kind != FirewallRuleKind.Custom)
            {
                merged.Add(rule);
                continue;
            }

            if (index.TryGetValue(rule.Name, out var at))
                merged[at] = Combine(merged[at], rule);
            else
            {
                index[rule.Name] = merged.Count;
                merged.Add(rule);
            }
        }

        return merged;
    }

    private static FirewallRuleInfo Combine(FirewallRuleInfo first, FirewallRuleInfo second)
    {
        // Only fragments of one spec ever share a name, so TCP alongside UDP can
        // only have come from protocol Any — which is the one form netsh will not
        // take with a port.
        var protocol = first.Protocol;
        if (!string.Equals(first.Protocol, second.Protocol, StringComparison.OrdinalIgnoreCase))
        {
            var pair = new[] { first.Protocol, second.Protocol };
            protocol = pair.All(p => p.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
                                     p.Equals("UDP", StringComparison.OrdinalIgnoreCase))
                ? FirewallRuleSpecs.ProtocolAny
                : first.Protocol;
        }

        var addresses = new List<string>();
        foreach (var token in SplitList(first.RemoteAddresses).Concat(SplitList(second.RemoteAddresses)))
        {
            if (!addresses.Contains(token, StringComparer.OrdinalIgnoreCase))
                addresses.Add(token);
        }

        return new FirewallRuleInfo
        {
            Name = first.Name,
            Label = first.Label,
            Description = first.Description,
            Enabled = first.Enabled && second.Enabled,
            IsBlock = first.IsBlock,
            Direction = first.Direction,
            RemoteAddresses = string.Join(", ", addresses),
            LocalPorts = first.LocalPorts.Length > 0 ? first.LocalPorts : second.LocalPorts,
            Protocol = protocol,
            Kind = first.Kind,
            ExpiresUtc = first.ExpiresUtc
        };
    }

    private static IEnumerable<string> SplitList(string value)
        => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static string NormalizePorts(string port)
    {
        var value = (port ?? "").Trim();
        if (value.Length == 0 || value is "*" || value.Equals("Any", StringComparison.OrdinalIgnoreCase))
            return "";
        return string.Join(", ", SplitList(value));
    }

    /// <summary>
    /// The whole remote-address list as the spec spells it. netsh writes a mask
    /// where the operator typed a prefix length (<c>10.0.0.0/255.0.0.0</c>), and
    /// writes a full-length mask on a single host, so both are converted back or
    /// the Edit button would hand the form something it cannot parse.
    /// </summary>
    internal static string NormalizeRemoteList(string remote)
    {
        if (string.IsNullOrWhiteSpace(remote)) return "";
        if (remote.Trim() is "Any" or "*") return "";

        var tokens = new List<string>();
        foreach (var token in SplitList(remote))
        {
            var slash = token.IndexOf('/');
            if (slash < 0)
            {
                tokens.Add(token);
                continue;
            }

            var address = token[..slash].Trim();
            var suffix = token[(slash + 1)..].Trim();

            // "10.0.0.0/255.0.0.0" → "10.0.0.0/8"; a numeric suffix is already right.
            if (!int.TryParse(suffix, out var prefix))
            {
                if (!TryMaskToPrefix(suffix, out prefix))
                {
                    tokens.Add(token);
                    continue;
                }
            }

            var full = IPAddress.TryParse(address, out var parsed) &&
                       parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? 128
                : 32;

            tokens.Add(prefix >= full ? address : $"{address}/{prefix}");
        }

        return string.Join(", ", tokens);
    }

    /// <summary>Dotted IPv4 mask to prefix length; false when it is not a contiguous mask.</summary>
    private static bool TryMaskToPrefix(string mask, out int prefix)
    {
        prefix = 0;
        if (!IPAddress.TryParse(mask, out var parsed) ||
            parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        var bits = 0u;
        foreach (var b in parsed.GetAddressBytes())
            bits = (bits << 8) | b;

        var ones = 0;
        while (ones < 32 && (bits & 0x8000_0000u) != 0)
        {
            ones++;
            bits <<= 1;
        }

        if (bits != 0) return false; // holes in the mask — not a prefix
        prefix = ones;
        return true;
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

    internal static FirewallOperationResult RunNetsh(string args)
    {
        try
        {
            // Use full path + separate process. Never load firewall COM into this process
            // for delete/list when called from the web UI. There is no fallback to a bare
            // "netsh": that would be searched for in the current directory before
            // System32, and this runs elevated — see SystemTools.
            var netshExe = SystemTools.Netsh;
            if (netshExe == null)
                return FirewallOperationResult.Fail("netsh.exe was not found in the Windows system directory.");

            var psi = new ProcessStartInfo
            {
                FileName = netshExe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                // Avoid inheriting weird console encodings that break parsing.
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail("Could not start netsh.");

            // Async read prevents deadlock if buffers fill on large "show rule name=all".
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(60000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return FirewallOperationResult.Fail("netsh timed out.");
            }

            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();
            string combined = (stdout + "\n" + stderr).Trim();

            if (p.ExitCode == 0)
                return FirewallOperationResult.Ok(combined);

            // delete rule when missing often exits non-zero
            if (combined.Contains("No rules match", StringComparison.OrdinalIgnoreCase))
                return FirewallOperationResult.Fail("No matching rule.");

            return FirewallOperationResult.Fail(string.IsNullOrWhiteSpace(combined)
                ? $"netsh exit code {p.ExitCode}"
                : combined);
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail(ex.Message);
        }
    }

    public static string IpRuleName(string ip, bool inbound)
        => $"{RulePrefix}-IP-{Sanitize(ip)}-{(inbound ? "In" : "Out")}";

    public static string PortRuleName(int port, string protocol, bool inbound)
        => $"{RulePrefix}-Port-{protocol.ToUpperInvariant()}-{port}-{(inbound ? "In" : "Out")}";

    private static string Sanitize(string value)
        => Regex.Replace(value, @"[^A-Za-z0-9.\-_]", "_");

    private static string Escape(string value)
        => value.Replace("\"", "'");

    private static string NormalizeRemote(string remote)
    {
        if (string.IsNullOrWhiteSpace(remote)) return "";
        // COM sometimes returns "1.2.3.4/255.255.255.255"
        var first = remote.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? remote;
        var slash = first.IndexOf('/');
        return slash > 0 ? first[..slash] : first.Trim();
    }

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
        // strip port / brackets if user pasted "ip:port" or "[v6]:port"
        if (ip.StartsWith('['))
        {
            var end = ip.IndexOf(']');
            if (end > 1)
                ip = ip[1..end];
        }
        else if (ip.Contains(':') && IPAddress.TryParse(ip, out _) == false)
        {
            // could be ipv4:port
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

        // Drop any IPv6 zone id (fe80::1%eth0 parses fine but netsh rejects it in a
        // rule, and two zone spellings of one address must compare equal).
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes());

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);

    /// <summary>
    /// Addresses no rule may ever target, because dropping them breaks the machine's
    /// own connectivity: LAN, loopback, link-local, multicast/broadcast.
    ///
    /// Narrower than <see cref="IsPrivateOrLocal"/>, which also covers CGNAT and is
    /// the right gate for <em>automatic</em> blocking. Blocking a tunnel peer is a
    /// bad default, not an impossible request — a hostile tailnet peer brute-forcing
    /// SSH is a real case, and refusing it in the manual path too left the operator
    /// with no way to stop the attack from inside the app.
    /// </summary>
    public static bool IsNeverBlockable(string ip)
        => GeoIpService.IsNonPublic(ip) && !GeoIpService.IsCarrierGradeNat(ip);

    // ── Block expiry ─────────────────────────────────────────────────────

    private Timer? _expiryTimer;

    /// <summary>
    /// Starts the background sweep that removes expired block rules. Deleting a
    /// firewall rule needs elevation, so the sweep only acts when this process
    /// already has it (the headless service runs as SYSTEM; an unelevated GUI
    /// does not). Otherwise the rule stays in the firewall but is already
    /// treated as lifted everywhere the UI looks — a timer must never trigger
    /// a UAC prompt in the user's face.
    /// </summary>
    public void StartExpirySweep()
    {
        if (_expiryTimer == null)
        {
            // One-time startup pass, off the caller's thread: rules deleted outside the
            // app leave their expiry entries behind, so prune before the first sweep.
            _ = Task.Run(() => ReconcileLedgerWithKernel());
        }
        _expiryTimer ??= new Timer(_ => TrySweepExpired(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Drops expiry-ledger entries whose firewall rule no longer exists.
    ///
    /// This build keeps no ledger of blocked addresses — <see cref="GetManagedRules"/>
    /// reads them straight from the Windows Firewall, which persists rules across
    /// reboots, so the blocked set cannot drift the way a POSIX rule ledger does. What
    /// does drift is the expiry side-file: a rule removed outside the app (wf.msc,
    /// Group Policy, "Restore defaults", another administrator) leaves its expiry entry
    /// behind forever, and <see cref="TrySweepExpired"/> then retries a delete every
    /// minute for a rule that is already gone.
    ///
    /// Listing rules needs no elevation, so this is safe to run at startup — unlike the
    /// sweep itself, it can never put a UAC prompt in the user's face. Nothing is
    /// written unless something is actually stale.
    /// </summary>
    public FirewallOperationResult ReconcileLedgerWithKernel()
    {
        try
        {
            var tracked = ExpiryLedger.TrackedNames();
            if (tracked.Count == 0)
                return FirewallOperationResult.Ok("Expiry ledger empty — nothing to reconcile.");

            // Listed directly rather than through GetManagedRules(): that returns an
            // empty list both when there are no managed rules and when netsh failed,
            // and pruning on a failed listing would discard every live expiry.
            var listing = RunNetsh("advfirewall firewall show rule name=all");
            if (!listing.Success || string.IsNullOrWhiteSpace(listing.Message))
                return FirewallOperationResult.Fail("Could not list firewall rules — reconciliation skipped.");

            // Rule names carry an -In/-Out suffix, so no managed name is a prefix of
            // another and a plain containment test against the dump is exact enough.
            var stale = tracked
                .Where(name => !listing.Message.Contains(name, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (stale.Count == 0)
                return FirewallOperationResult.Ok("Expiry ledger matches the firewall rules.");

            ExpiryLedger.RemoveMany(stale);
            return FirewallOperationResult.Ok(
                $"Dropped {stale.Count} expiry entr{(stale.Count == 1 ? "y" : "ies")} with no matching firewall rule.");
        }
        catch (Exception ex)
        {
            return FirewallOperationResult.Fail($"Reconcile failed: {ex.Message}");
        }
    }

    private int _sweeping;

    private void TrySweepExpired()
    {
        // A Timer fires on the thread pool whether or not the last tick has finished, and
        // a sweep can outlast the minute (each removal is a netsh call under a 60 s
        // process timeout). Two at once raced on the same rules.
        if (Interlocked.Exchange(ref _sweeping, 1) == 1) return;
        try
        {
            var expired = ExpiryLedger.ExpiredNames();
            if (expired.Count == 0) return;
            if (!IsAdministrator) return;

            foreach (var name in expired)
            {
                // The expiry entry is the only record that this rule is due to go, so it
                // is dropped only once the rule is confirmed gone. Dropping it after a
                // delete that failed left the block in force for good, with nothing
                // left to retry it.
                RemoveRuleByName(name, out var outcome);
                if (outcome != RemovalOutcome.Failed)
                    ExpiryLedger.Remove(name);
            }
            InvalidateRuleCache();
        }
        catch
        {
            // sweep is best-effort; it simply retries next minute
        }
        finally
        {
            Interlocked.Exchange(ref _sweeping, 0);
        }
    }

    /// <summary>
    /// Expiry times for auto-created rules, keyed by firewall rule name.
    ///
    /// The Windows build enumerates rules from netsh rather than from a ledger
    /// of its own, and netsh has nowhere to hang an expiry, so it is kept in a
    /// small side file next to the other shared state. It lives under
    /// %ProgramData% so the GUI, TUI and web service all agree on when a rule
    /// stops counting.
    /// </summary>
    private static class ExpiryLedger
    {
        private static readonly object Gate = new();

        private static string LedgerPath
            => Path.Combine(AppPaths.DataDirectory, "auto-block-expiry.json");

        public static DateTime? Get(string ruleName)
        {
            lock (Gate)
            {
                var map = Load();
                return map.TryGetValue(ruleName, out var expiry) ? expiry : null;
            }
        }

        /// <summary>Records an expiry, or clears one when <paramref name="expiresUtc"/> is null.</summary>
        public static void Set(string ruleName, DateTime? expiresUtc)
        {
            lock (Gate)
            {
                var map = Load();
                if (expiresUtc.HasValue) map[ruleName] = expiresUtc.Value;
                else if (!map.Remove(ruleName)) return; // nothing to persist
                Save(map);
            }
        }

        public static void Remove(string ruleName) => Set(ruleName, null);

        /// <summary>Every rule name currently carrying an expiry.</summary>
        public static List<string> TrackedNames()
        {
            lock (Gate) return Load().Keys.ToList();
        }

        /// <summary>
        /// Drops several entries in one read-modify-write. Re-reads inside the lock and
        /// removes only the named entries, so a rule blocked while the caller was
        /// listing the firewall is not erased by writing back a pre-listing snapshot.
        /// </summary>
        public static void RemoveMany(IEnumerable<string> ruleNames)
        {
            lock (Gate)
            {
                var map = Load();
                var changed = false;
                foreach (var name in ruleNames)
                    changed |= map.Remove(name);
                if (changed) Save(map);
            }
        }

        public static List<string> ExpiredNames()
        {
            lock (Gate)
            {
                var now = DateTime.UtcNow;
                return Load().Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();
            }
        }

        private static Dictionary<string, DateTime> Load()
        {
            try
            {
                var path = LedgerPath;
                if (!File.Exists(path))
                    return new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

                var map = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(path));
                return map == null
                    ? new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, DateTime>(map, StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                // A corrupt ledger must not make blocking fail — rules simply
                // read as permanent until the file is rewritten.
                return new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static void Save(Dictionary<string, DateTime> map)
        {
            try
            {
                AppPaths.WriteAtomic(LedgerPath, JsonSerializer.Serialize(map));
            }
            catch
            {
                // best-effort persistence
            }
        }
    }
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
    Other,

    /// <summary>
    /// A rule the operator wrote in the Firewall Config view: any action, any
    /// direction, a protocol, a port range and an address list. The other kinds
    /// are minted by the app (auto-block, manual block, web console access).
    /// </summary>
    Custom
}

public sealed class FirewallRuleInfo
{
    public string Name { get; init; } = "";

    /// <summary>
    /// Operator-facing name for a Firewall Config rule (<c>block-inbound-ssh</c>).
    /// Empty on rules the app minted itself, which fall back to a description
    /// derived from what they match.
    /// </summary>
    public string Label { get; init; } = "";

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

    // ── Host-scan fields ─────────────────────────────────────────────────
    //
    // Set by HostFirewallScanner on rules read back out of Windows Defender
    // Firewall, which is most of what the Firewall Config view lists: Windows'
    // own rules, the ones installers wrote, and this app's. Nothing here is
    // persisted — the app's ledger holds only rule names and expiry times.

    /// <summary>
    /// Who put the rule in the firewall — "Core Networking", "Microsoft Teams",
    /// "chrome.exe", "Local rule". Drives the Created by column, so a rule this
    /// app is not responsible for is never shown as one of its own. Empty on
    /// managed rules, where <see cref="OriginText"/> derives it from the kind.
    /// </summary>
    public string Origin { get; init; } = "";

    /// <summary>netsh's Grouping field: the display group a rule belongs to.</summary>
    public string Grouping { get; init; } = "";

    /// <summary>Program the rule is scoped to, empty when it applies to any program.</summary>
    public string Program { get; init; } = "";

    /// <summary>Windows service the rule is scoped to, empty when it applies to any.</summary>
    public string Service { get; init; } = "";

    /// <summary>
    /// Profiles the rule applies to, as netsh spells them: "Domain,Private,Public".
    /// Settable because the scan folds a rule stored once per profile into one row and
    /// carries the union here — see <see cref="HostFirewallScanner.Dedupe"/>.
    /// </summary>
    public string Profiles { get; set; } = "";

    /// <summary>
    /// Local-port constraint as netsh reported it. <see cref="LocalPorts"/> is the
    /// display value — the local port on an inbound rule, the remote port on an
    /// outbound one — so both raw halves are kept for the delete filter, which has
    /// to name the rule's whole shape to avoid taking its neighbours with it.
    /// </summary>
    public string LocalPortsRaw { get; init; } = "";

    /// <summary>Remote-port constraint as netsh reported it. See <see cref="LocalPortsRaw"/>.</summary>
    public string RemotePortsRaw { get; init; } = "";

    /// <summary>
    /// How many identical rules this row stands for. Windows lets the same rule be
    /// added over and over — a setup script run twice leaves two — so the scan folds
    /// exact duplicates into one row and counts them rather than printing 685 of them.
    /// </summary>
    public int Copies { get; set; } = 1;

    /// <summary>
    /// True for a rule read out of the firewall that this app did not write. The
    /// editor still opens it, but saving replaces it and deleting removes it from
    /// Windows Defender Firewall rather than from the app's ledger.
    /// </summary>
    public bool IsForeign { get; init; }

    /// <summary>"×685" for a folded duplicate set, empty for a rule that is one rule.</summary>
    public string CopiesText => Copies > 1 ? $"×{Copies}" : "";

    /// <summary>
    /// Which profiles this rule is live on, but only when that is not all of them.
    /// "Domain,Private,Public" is netsh's way of saying "always", and a column repeating
    /// it down every row would bury the handful of rules that really are scoped.
    /// </summary>
    public string ProfileScopeText
    {
        get
        {
            var parts = Profiles.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                .Select(p => p.Trim())
                                .Where(p => p.Length > 0)
                                .ToList();
            if (parts.Count == 0 || parts.Count >= 3) return "";
            if (parts.Count == 1 && parts[0].Equals("Any", StringComparison.OrdinalIgnoreCase)) return "";
            return string.Join(", ", parts);
        }
    }

    /// <summary>
    /// Longest scope string a column shows before it is trimmed. Wide enough for a
    /// version directory and an executable name, which is what tells two rules of the
    /// same shape apart, and no wider: a value longer than the column gets trimmed a
    /// second time by the cell — from the right, undoing this one. Trimmed twice,
    /// "cef.win64" and "cef.win7x64" both end up as "cef.win…" and the rows collide
    /// again.
    /// </summary>
    private const int ScopeTextMaxLength = 34;

    /// <summary>
    /// What the rule is scoped to: the executable, or the Windows service, or "Any".
    ///
    /// This is the field that decides whether two rows are the same rule, and it was
    /// the one nothing displayed. A host carries whole families of rules identical in
    /// every column the table did show — same name, action, protocol, ports, addresses
    /// and origin — that are separate rules only because they name different binaries:
    /// 21 <c>Microsoft Edge (mDNS-In)</c> rules, one per retained EdgeWebView version,
    /// and a <c>Steam Web Helper</c> pair split across cef.win64 and cef.win7x64. They
    /// read as duplicates of one another, and there was nothing on screen to say
    /// otherwise.
    ///
    /// Trimmed from the <em>left</em>, not the right. Paths that collide share a long
    /// prefix and differ at the tail, so trimming the usual way keeps precisely the
    /// half that is the same on every row and drops the half that tells them apart.
    /// <see cref="ScopeDetailText"/> carries the whole value for the tooltip, because
    /// no column width disambiguates every case — two build outputs under different
    /// configurations still agree on their last two segments.
    /// </summary>
    public string ScopeText
    {
        get
        {
            var program = CleanScopeValue(Program);
            if (program.Length > 0) return TrimFromLeft(program, ScopeTextMaxLength);

            var service = CleanScopeValue(Service);
            if (service.Length > 0) return TrimFromLeft(service, ScopeTextMaxLength);

            return "Any";
        }
    }

    /// <summary>The whole scope, for the tooltip that sits behind <see cref="ScopeText"/>.</summary>
    public string ScopeDetailText
    {
        get
        {
            var program = CleanScopeValue(Program);
            var service = CleanScopeValue(Service);

            if (program.Length > 0 && service.Length > 0)
                return $"Program: {program}\nService: {service}";
            if (program.Length > 0)
                return program;
            if (service.Length > 0)
                return $"Service: {service}";

            return "Applies to any program or service.";
        }
    }

    /// <summary>
    /// netsh prints an unconstrained scope as "Any" or "*", both of which mean the rule
    /// names no binary at all — not that a program called "Any" is being matched.
    /// </summary>
    private static string CleanScopeValue(string? value)
    {
        var text = (value ?? "").Trim();
        if (text.Length == 0) return "";
        if (text.Equals("Any", StringComparison.OrdinalIgnoreCase) || text == "*") return "";
        return text;
    }

    /// <summary>Keeps the tail — the part that differs — and marks the cut with an ellipsis.</summary>
    private static string TrimFromLeft(string value, int max)
        => value.Length <= max ? value : "…" + value[^(max - 1)..];

    public bool IsExpired => ExpiresUtc.HasValue && ExpiresUtc.Value <= DateTime.UtcNow;

    public string ExpiryText => ExpiresUtc.HasValue
        ? (IsExpired ? "Expired" : $"Expires {ExpiresUtc.Value.ToLocalTime():HH:mm}")
        : "Permanent";

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        FirewallRuleKind.Custom => "Config rule",
        _ when Name.Contains("-Web-", StringComparison.OrdinalIgnoreCase) => "Web UI",
        _ => IsBlock ? "Block rule" : "Allow rule"
    };

    /// <summary>Only Firewall Config rules can be edited; the rest are app-minted.</summary>
    public bool IsCustom => Kind == FirewallRuleKind.Custom;

    public bool IsInbound => Direction != FirewallDirection.Outbound;

    /// <summary>Label column: the operator's name, or a description of what the rule matches.</summary>
    public string LabelText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(Label)) return Label;
            return Kind switch
            {
                FirewallRuleKind.IpBlock => $"auto-block-{(IsInbound ? "inbound" : "outbound")}-{AddressText}",
                FirewallRuleKind.PortBlock => $"block-{(IsInbound ? "inbound" : "outbound")}-port-{LocalPorts}",
                _ => Name
            };
        }
    }

    /// <summary>Where the rule came from, so app-minted rules are not mistaken for config.</summary>
    public string OriginText
    {
        get
        {
            // A scanned rule already knows who wrote it; the kinds below only
            // describe rules this app minted.
            if (!string.IsNullOrWhiteSpace(Origin)) return Origin;

            if (Name.Contains("-Web-", StringComparison.OrdinalIgnoreCase))
                return "Web console";

            return Kind switch
            {
                FirewallRuleKind.IpBlock => "Auto/manual block",
                FirewallRuleKind.PortBlock => "Port block",
                FirewallRuleKind.Custom => "Firewall config",
                _ => "Managed"
            };
        }
    }

    public string ProtocolText => string.IsNullOrWhiteSpace(Protocol) ? "Any" : Protocol;

    public string PortRangeText => string.IsNullOrWhiteSpace(LocalPorts) ? "All ports" : LocalPorts;

    /// <summary>Sources on an inbound rule, destinations on an outbound one.</summary>
    public string AddressListText => string.IsNullOrWhiteSpace(RemoteAddresses)
        ? FirewallRuleSpecs.AnyAddressText
        : RemoteAddresses;
    /// <summary>Best-effort IP or port target for display (COM sometimes omits RemoteAddresses).</summary>
    public string AddressText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(RemoteAddresses) && RemoteAddresses is not ("Any" or "*"))
                return RemoteAddresses;
            // NetworkSentinel-IP-1.2.3.4-In  or  NetworkSentinel-IP-2001_db8__1-Out
            var ipMatch = System.Text.RegularExpressions.Regex.Match(
                Name,
                @"^NetworkSentinel-IP-(.+)-(In|Out)$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (ipMatch.Success)
                return ipMatch.Groups[1].Value.Replace('_', ':'); // reverse Sanitize for IPv6-ish
            return "";
        }
    }

    public string TargetText
    {
        get
        {
            var addr = AddressText;
            if (!string.IsNullOrWhiteSpace(addr))
                return addr;
            if (!string.IsNullOrWhiteSpace(LocalPorts))
                return $"{Protocol}/{LocalPorts}";
            // e.g. NetworkSentinel-Web-18765 → show port from the name
            var parts = Name.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length > 0 && int.TryParse(parts[^1], out var portFromName) && portFromName is > 0 and <= 65535)
                return $"{Protocol}/{portFromName}";
            if (!string.IsNullOrWhiteSpace(Description))
                return Description;
            return "—";
        }
    }
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
