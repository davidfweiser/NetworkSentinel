using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Which front-end is driving <see cref="FirewallService"/>. The only thing it
/// decides is where a password could be typed: a desktop session can raise a polkit
/// dialog, a terminal can prompt on its own TTY, and the web console can do neither —
/// the operator is in a browser, and any prompt would have to appear on a server they
/// are not sitting at.
/// </summary>
public enum FirewallUiSurface
{
    /// <summary>The Avalonia GUI — pkexec or an askpass dialog can prompt.</summary>
    Desktop,

    /// <summary>The TUI over SSH or a console — sudo can prompt on the TTY.</summary>
    Terminal,

    /// <summary>The headless web console — nothing can prompt.</summary>
    Web
}

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

    /// <summary>Ledger <see cref="FirewallRuleInfo.Backend"/> values — which tool owns a kernel rule.</summary>
    private const string NftBackend = "nft";
    private const string IptablesBackend = "iptables";

    /// <summary>Marks a ledger rule that UFW wrote, so removal goes back out through UFW.</summary>
    private const string UfwBackend = "ufw";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public AllowlistService? Allowlist { get; set; }

    /// <summary>
    /// True on the one platform whose firewall this service can drive. Everything
    /// below — nftables, iptables, UFW, <c>geteuid</c>, pkexec — is Linux, and the
    /// read path is /proc, so there is no privilege level on another OS that would
    /// let a rule be written. Checked before the elevation probes so that a
    /// Windows or macOS run is told what is actually wrong instead of being sent
    /// to look for a sudo that would not help if it were there.
    /// </summary>
    public static bool PlatformSupported => OperatingSystem.IsLinux();

    /// <summary>What to say instead of asking for a password the OS has no use for.</summary>
    public const string UnsupportedPlatformText =
        "Network Sentinel drives the Linux host firewall (UFW, nftables or iptables) and has no " +
        "backend for this operating system, so no privilege level here can apply a rule — running " +
        "it as Administrator or root would not change that. Run it on a Linux host. Under WSL2 it " +
        "works, but the rules it writes belong to the Linux VM, not to Windows Defender Firewall.";

    /// <summary>True when euid is root (rare; GUI should not run as root on Wayland).</summary>
    public bool IsRoot => IsRootProcess();

    /// <summary>Static form, for the read path which has no instance to hand.</summary>
    internal static bool IsRootProcess()
    {
        // The P/Invoke below binds to libc; calling it off Linux throws every time.
        if (!PlatformSupported) return false;
        try { return geteuid() == 0; }
        catch { return false; }
    }

    /// <summary>True when firewall changes can be attempted (root or elevatable via pkexec/sudo).</summary>
    public bool IsAdministrator => PlatformSupported && (IsRoot || CanElevate);

    public bool CanElevate => PlatformSupported && (CommandExists("pkexec") || CommandExists("sudo"));

    /// <summary>
    /// Which front-end is running. Set once at startup by <c>Program</c>; the default
    /// suits the GUI, which is the one process that does not set it.
    /// </summary>
    public static FirewallUiSurface Surface { get; set; } = FirewallUiSurface.Desktop;

    /// <summary>
    /// The binaries a rule write ever has to run as root, and therefore the ones a
    /// scoped sudoers grant has to name. Also what the silent-elevation probe asks for
    /// a version of — see <see cref="ProbeSilentSudo"/>.
    /// </summary>
    internal static readonly string[] PrivilegedTools = { "ufw", "nft", "iptables", "ip6tables" };

    /// <summary>True when there is a display for pkexec or an askpass helper to draw on.</summary>
    private static bool HasGraphicalSession()
        => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")) ||
           !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY"));

    /// <summary>
    /// Whether a password prompt could actually reach the operator who is asking.
    /// <see cref="CanPromptForElevation"/> answers a weaker question — which helpers
    /// are installed — and overstates it twice over: pkexec needs a live polkit agent
    /// to talk to, and a browser is not where a prompt raised on the server appears.
    /// </summary>
    private static bool CanPromptOnThisSurface()
    {
        if (!PlatformSupported) return false;
        if (Surface == FirewallUiSurface.Web) return false;
        if (CommandExists("pkexec") && (HasGraphicalSession() || HasTerminal())) return true;
        return CommandExists("sudo") && (FindAskpassHelper() != null || HasTerminal());
    }

    /// <summary>
    /// True when a rule written now would actually reach the kernel: this process is
    /// root, or sudo runs the firewall binaries without asking, or there is somewhere
    /// on this surface to type a password.
    ///
    /// <see cref="IsAdministrator"/> only reports that some elevation helper exists, so
    /// on a headless web console it is true on a host where every single write fails.
    /// That is how an operator came to open the rule editor, fill it in, and learn only
    /// at Save that the console had never been able to write anything.
    /// </summary>
    public bool CanApplyRules
        => PlatformSupported && (IsRoot || CanElevateSilently() || CanPromptOnThisSurface());

    /// <summary>
    /// The sudoers grant that makes writes work where nothing can prompt, built for
    /// this host: the user the process is actually running as, and the firewall
    /// binaries that are actually installed, at the paths they are installed at. The
    /// README's line is a template with placeholders; this one can be pasted as it
    /// stands, which matters most on the surface that cannot show a prompt anyway.
    /// </summary>
    public static string SudoersGrantText()
    {
        var tools = PrivilegedTools
            .Select(ResolveExecutable)
            .Where(path => path != null)
            .ToArray();

        // Naming a binary that is not installed makes visudo reject the whole file, so
        // an empty resolve falls back to the conventional paths rather than to nothing.
        var list = tools.Length > 0
            ? string.Join(", ", tools)
            : "/usr/sbin/nft, /usr/sbin/iptables";

        return $"{Environment.UserName} ALL=(root) NOPASSWD: {list}";
    }

    /// <summary>
    /// What to do about a host that cannot prompt, as commands to run rather than a
    /// section to go and find. <paramref name="asBlock"/> keeps the newlines for a
    /// console or a preformatted block; the flowed form is for a one-line status.
    /// </summary>
    public static string HeadlessElevationHelp(bool asBlock = true)
    {
        var text =
            $"{HeadlessElevationLead}\n\n{CapabilityInstallCommands()}\n\n" +
            $"{HeadlessElevationAlternative}\n\n{SudoersInstallCommands()}\n\n{HeadlessElevationTail}";

        return asBlock ? text : text.Replace("\n\n", "  ").Replace("\n", "  ");
    }

    /// <summary>
    /// Give the unit the one capability nftables asks for. This is the first remedy
    /// offered because it is the smaller grant: <c>CAP_NET_ADMIN</c> is the right to
    /// configure networking, where a NOPASSWD entry for <c>nft</c> is the right to run
    /// <c>nft -f</c> on any file as root, which is the whole machine.
    /// </summary>
    public static string CapabilityInstallCommands()
        => "sudo systemctl edit --full networksentinel-web\n" +
           "#   under [Service], add:  AmbientCapabilities=CAP_NET_ADMIN\n" +
           "sudo systemctl restart networksentinel-web";

    /// <summary>
    /// The four commands on their own, so a front-end that can lay out a code block
    /// does not have to pick them back out of the prose.
    /// </summary>
    public static string SudoersInstallCommands()
        => $"echo '{SudoersGrantText()}' | sudo tee /etc/sudoers.d/networksentinel\n" +
           "sudo chmod 0440 /etc/sudoers.d/networksentinel\n" +
           "sudo visudo -c\n" +
           "sudo systemctl restart networksentinel-web";

    public const string HeadlessElevationLead =
        "Grant the service the one capability nftables needs \u2014 no password, and nothing runs as root:";

    public const string HeadlessElevationAlternative =
        "Or, on a host that writes rules through UFW (which checks the uid, not the capability), " +
        "give this user passwordless sudo for the firewall binaries instead:";

    public const string HeadlessElevationTail =
        "Then use Rescan to re-check \u2014 see \u201cFirewall elevation on a headless server\u201d in the README.";

    /// <summary>
    /// True when a password can actually be collected for a rule the operator asked
    /// for. Sudo on its own is not enough from a GUI or a systemd service: with no
    /// pkexec, no cached credentials, no askpass helper and no terminal to prompt on,
    /// there is nowhere to type the password, which is the case the old
    /// "install pkexec or sudo" wording described as a missing sudo.
    /// </summary>
    public bool CanPromptForElevation =>
        PlatformSupported &&
        (IsRoot || CommandExists("pkexec") ||
         (CommandExists("sudo") && (FindAskpassHelper() != null || HasTerminal())));

    public string PrivilegeText
    {
        get
        {
            if (!PlatformSupported)
                return UnsupportedPlatformText;
            if (IsRoot)
                return "Running as root — firewall rules can be applied directly.";
            if (HasDirectKernelAccess())
                return "Running as your user with CAP_NET_ADMIN — rules are written straight to the kernel, " +
                       "with no elevation and no prompt.";
            if (CanElevateSilently())
                return "Running as your user with passwordless sudo for the firewall binaries — rules apply " +
                       "without a prompt.";

            // Past here nothing can be written without asking for a password, so the
            // question is only whether this surface has anywhere to ask.
            if (Surface == FirewallUiSurface.Web)
                return "Running as your user with no passwordless sudo, so the console cannot write rules: " +
                       "a password prompt would have to appear on the server, not in this browser. " +
                       HeadlessElevationHelp(asBlock: false);
            if (CommandExists("pkexec"))
                return "Running as your user. Firewall changes will ask for your password (polkit/pkexec).";
            if (CommandExists("sudo") && FindAskpassHelper() != null)
                return "Running as your user. Firewall changes ask for your password through sudo's askpass dialog.";
            if (CommandExists("sudo"))
                return "Running as your user with sudo but no password dialog. Firewall changes work only " +
                       "from passwordless sudo or a terminal — install policykit-1 (pkexec), or grant this " +
                       "user NOPASSWD sudo for ufw/nft/iptables.";
            return "No elevation helper found (install pkexec or sudo) — firewall rules cannot be applied.";
        }
    }

    /// <summary>
    /// One sentence for a form that is about to write a rule: what applying will
    /// actually ask for on this host. The editor used to state "asks for elevation
    /// (pkexec or sudo)" unconditionally, which reads as a demand for sudo on the two
    /// hosts where nothing is asked at all — already root, and passwordless sudo — and
    /// promises a prompt on the one host that cannot raise one.
    /// </summary>
    public string ElevationNote
    {
        get
        {
            if (!PlatformSupported)
                return UnsupportedPlatformText;
            if (IsRoot)
                return "Applying writes the rule directly — this process is already root.";
            if (HasDirectKernelAccess())
                return "Applying writes the rule directly — this process holds CAP_NET_ADMIN.";
            if (CanElevateSilently())
                return "Applying writes the rule through passwordless sudo — nothing is asked for.";
            if (Surface == FirewallUiSurface.Web)
                return "Applying will fail: this console has no passwordless sudo, and a password prompt " +
                       "cannot be shown in a browser. " + HeadlessElevationHelp(asBlock: false);
            if (CommandExists("pkexec"))
                return "Applying asks for your password (pkexec).";
            if (CommandExists("sudo") && FindAskpassHelper() != null)
                return "Applying asks for your password (sudo askpass dialog).";
            if (CommandExists("sudo"))
                return "Applying goes through sudo, which can only succeed here from passwordless sudo — " +
                       "this session has no way to show a password prompt.";
            return "Applying will fail: neither pkexec nor sudo is installed.";
        }
    }

    /// <summary>
    /// Why a write cannot even be attempted, naming the gap that is actually there:
    /// an OS with no backend, no helper at all, or a helper with no way to ask for a
    /// password. Every refusal in this class goes through here, so the operator is
    /// never told to install something they already have.
    /// </summary>
    private FirewallOperationResult NoElevation(string action)
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (!CanElevate)
            return FirewallOperationResult.Fail(
                $"No elevation helper is installed, so Network Sentinel cannot {action}. " +
                "Install policykit-1 (pkexec) for a password dialog, or sudo.");

        if (Surface == FirewallUiSurface.Web)
            return FirewallOperationResult.Fail(
                $"This user has no passwordless sudo, so the web console cannot {action}: the password " +
                "prompt would have to appear on the server, not in your browser.\n\n" +
                HeadlessElevationHelp());

        return FirewallOperationResult.Fail(
            $"Elevation is available but has no way to ask for a password, so Network Sentinel cannot {action}. " +
            "Install policykit-1 (pkexec), or grant this user passwordless sudo for ufw/nft/iptables " +
            "(see “Firewall elevation on a headless server” in the README).");
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

        if (!overrideAllowlist && Allowlist != null && Allowlist.IsAllowed(normalized, out var allowReason))
            return FirewallOperationResult.Fail($"Refusing to block allowlisted address {normalized} ({allowReason}).");

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

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
            return NoElevation("modify the host firewall");

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
            return NoElevation("modify the host firewall");

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
            return NoElevation("modify the host firewall");

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
                return NoElevation("modify the host firewall");

            var name = ruleName.Trim();

            // Blocks are created as an -In/-Out pair. Removing only the clicked row left
            // the sibling active, so the IP stayed blocked and remove "didn't work".
            //
            // Config rules are never paired, and their names end in an operator's
            // label — "block-inbound-In" would otherwise drag an unrelated
            // "block-inbound-Out" rule out of the ledger with it.
            var isPaired = !name.StartsWith($"{RulePrefix}-Rule-", StringComparison.OrdinalIgnoreCase);
            var siblings = new List<string> { name };
            if (isPaired && name.EndsWith("-In", StringComparison.OrdinalIgnoreCase))
                siblings.Add(name[..^"-In".Length] + "-Out");
            else if (isPaired && name.EndsWith("-Out", StringComparison.OrdinalIgnoreCase))
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
                return FirewallOperationResult.Fail(firstError ?? AlreadyGoneText(name));

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
            return NoElevation("modify the host firewall");

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
            return NoElevation("remove firewall rules");

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

    // ── Firewall Config rules (operator-authored) ────────────────────────

    /// <summary>
    /// Why an operator's Allow rule can never reopen an address auto-block just
    /// shut, on either backend.
    ///
    /// The macOS build regenerates one PF anchor from the ledger on every change,
    /// so it fixes precedence by emitting app-minted blocks before config rules.
    /// Here rules are added to live nft/iptables chains one at a time and are
    /// evaluated in chain order, so ledger order decides nothing: a config Allow
    /// written today would sit ahead of a block auto-block appends tomorrow, and
    /// the accept would win.
    ///
    /// So the ordering is enforced where the rules are written instead —
    /// app-minted blocks are <b>inserted at the head</b> of their chain
    /// (<c>nft insert</c>, <c>iptables -I … 1</c>) while config rules are
    /// <b>appended</b>. Every app block therefore precedes every config rule, no
    /// matter which was created first, and the first terminal verdict wins.
    ///
    /// One consequence, accepted deliberately: the probe-log rule is appended too,
    /// so a SYN from an address that is already blocked is now dropped before it
    /// reaches the log. Probe logging exists to catch scans of closed ports from
    /// hosts that are not blocked yet, and dropping the duplicate noise is an
    /// improvement rather than a loss.
    /// </summary>
    internal const string PrecedenceNote = "app blocks insert at the chain head; config rules append";

    /// <summary>
    /// nft verb that puts a rule where <see cref="PrecedenceNote"/> says it goes:
    /// <c>insert</c> prepends, <c>add</c> appends.
    /// </summary>
    internal static string NftAddVerb(FirewallRuleKind kind)
        => kind == FirewallRuleKind.Custom ? "add" : "insert";

    /// <summary>
    /// iptables chain clause with the same meaning: <c>-I CHAIN 1</c> prepends,
    /// <c>-A CHAIN</c> appends.
    /// </summary>
    internal static string IptablesChainClause(FirewallRuleKind kind, string chain)
        => kind == FirewallRuleKind.Custom ? $"-A {chain}" : $"-I {chain} 1";

    /// <summary>
    /// Every managed rule in evaluation order — app-minted blocks first, then the
    /// operator's config rules. <see cref="GetManagedRules"/> sorts for the flat
    /// rule list; the Firewall Config view needs the real order instead, because
    /// the chains are first-match-wins.
    /// </summary>
    public IReadOnlyList<FirewallRuleInfo> GetConfigRules()
    {
        var ledger = LoadLedger();
        return ledger
            .OrderBy(r => r.Kind == FirewallRuleKind.Custom ? 1 : 0)
            .ToList();
    }

    /// <summary>
    /// Creates or replaces one operator-authored rule. Passing
    /// <paramref name="replaceName"/> edits in place: the old kernel rule and
    /// ledger entry are dropped and the new one is appended, so the edited rule
    /// moves to the end of the config section.
    /// </summary>
    public FirewallOperationResult SaveCustomRule(FirewallRuleSpec spec, string? replaceName = null)
    {
        // Validate before normalising — see FirewallRuleSpecs.TryPrepare for why the
        // other order turns an unparseable port range into "every port".
        if (!FirewallRuleSpecs.TryPrepare(spec, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        if (!string.IsNullOrWhiteSpace(replaceName))
        {
            var existing = LoadLedger().FirstOrDefault(r =>
                string.Equals(r.Name, replaceName, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
                return FirewallOperationResult.Fail($"No rule named “{replaceName}” to edit — it may have been removed.");
            if (existing.Kind != FirewallRuleKind.Custom)
                return FirewallOperationResult.Fail("Only Firewall Config rules can be edited here.");

            RemoveRuleByName(replaceName!);
        }

        var viaUfw = BackendIsUfw();
        // Only our own nft table needs bootstrapping; under UFW we write into its
        // chains and must not add a competing table beside them.
        if (!viaUfw) EnsureBackendReady();

        var name = UniqueCustomRuleName(normalized.Label, LoadLedger());
        var rule = FirewallRuleSpecs.ToRule(normalized, name,
            backend: viaUfw ? UfwBackend : BackendIsNft() ? NftBackend : IptablesBackend);
        var applied = ApplyCustomRule(rule);

        if (!applied.Success)
        {
            // A rule the kernel would not take must not stay in the ledger claiming
            // to be in force. Any fragment that did load is torn back out, so a
            // half-applied rule cannot survive as a silent partial block.
            RemoveRuleByName(name);
            return FirewallOperationResult.Fail($"The rule was rejected, so it was not kept: {applied.Message}");
        }

        UpsertLedger(rule);

        // Where the rule landed only needs saying when it is not where the operator
        // will go looking for it — see OutsideUfwNote.
        var where = viaUfw ? "" : OutsideUfwNote();
        return FirewallOperationResult.Ok((string.IsNullOrWhiteSpace(replaceName)
            ? $"Added rule “{normalized.Label}”."
            : $"Saved rule “{normalized.Label}”.") + where);
    }

    /// <summary>
    /// Writes one config rule's kernel fragments. A spec can need more than one:
    /// a mixed v4/v6 address list splits by family, and a port range under
    /// protocol Any splits into TCP and UDP.
    /// </summary>
    private FirewallOperationResult ApplyCustomRule(FirewallRuleInfo rule)
    {
        // UFW first where it is running: it owns the chains, and a rule written
        // under it would be invisible in `ufw status` and lost on `ufw reload`.
        if (BackendIsUfw())
            return ApplyViaUfw(rule);

        var verdictNft = rule.IsBlock ? "drop" : "accept";
        var verdictIpt = rule.IsBlock ? "DROP" : "ACCEPT";
        var chain = rule.IsInbound ? "input" : "output";
        var table = rule.IsInbound ? "INPUT" : "OUTPUT";

        if (BackendIsNft())
        {
            var matches = FirewallRuleSpecs.BuildNftMatches(rule);
            if (matches.Count == 0)
                return FirewallOperationResult.Fail("The rule matched nothing to write.");

            foreach (var fragment in matches)
            {
                // Appended, not inserted — app-minted blocks own the head of the chain.
                var r = RunPrivileged("nft",
                    $"{NftAddVerb(rule.Kind)} rule {NftTable} {chain} {fragment.Match} counter {verdictNft} comment \"{Escape(rule.Name)}\"");
                if (!r.Success)
                    return FirewallOperationResult.Fail($"Failed nft add {rule.Name}: {r.Message}");
            }

            return FirewallOperationResult.Ok($"Rule “{rule.Name}” applied (nftables).");
        }

        var iptMatches = FirewallRuleSpecs.BuildIptablesMatches(rule);
        if (iptMatches.Count == 0)
            return FirewallOperationResult.Fail("The rule matched nothing to write.");

        foreach (var fragment in iptMatches)
        {
            var tool = fragment.IsV6 ? "ip6tables" : "iptables";
            if (fragment.IsV6 && !CommandExists("ip6tables"))
                return FirewallOperationResult.Fail(
                    "Cannot write the IPv6 part of this rule: ip6tables is not installed (and nft is unavailable).");

            var body = fragment.Match.Length > 0 ? fragment.Match + " " : "";
            var r = RunPrivileged(tool,
                $"{IptablesChainClause(rule.Kind, table)} {body}-j {verdictIpt} -m comment --comment \"{Escape(rule.Name)}\"");
            if (!r.Success)
                return FirewallOperationResult.Fail($"Failed {tool} add {rule.Name}: {r.Message}");
        }

        return FirewallOperationResult.Ok($"Rule “{rule.Name}” applied (iptables).");
    }

    // ── UFW write path ───────────────────────────────────────────────────

    /// <summary>
    /// Writes one config rule through UFW. Every command goes into a single
    /// batched shell script: one spec can need several `ufw` invocations (one per
    /// address × port), and polkit does not cache, so running them separately
    /// raises one password dialog each.
    /// </summary>
    private FirewallOperationResult ApplyViaUfw(FirewallRuleInfo rule)
    {
        var spec = FirewallRuleSpecs.FromRule(rule);
        // The kernel comment is the ledger key, not the operator's label — that is
        // how a rescan tells our rules apart from everyone else's.
        spec.Label = rule.Name;

        var commands = UfwWriter.BuildAddCommands(spec);
        if (commands.Count == 0)
            return FirewallOperationResult.Fail("The rule matched nothing to write.");

        var result = RunUfwBatch(commands);
        InvalidateUfwProbe();
        return result.Success
            ? FirewallOperationResult.Ok($"Rule “{rule.Name}” applied (UFW).")
            : FirewallOperationResult.Fail($"Failed ufw add {rule.Name}: {result.Message}");
    }

    /// <summary>
    /// Deletes a UFW rule by its number in `ufw status numbered`. Numbers shift as
    /// rows are removed, so they are deleted highest-first; an "anywhere" rule has
    /// an IPv4 and an IPv6 twin and both numbers come back, because leaving one
    /// behind still admits the traffic the delete was supposed to stop.
    /// </summary>
    private FirewallOperationResult RemoveViaUfw(FirewallRuleInfo rule)
    {
        var listing = RunPrivileged("ufw", "status numbered");
        var numbers = listing.Success
            ? UfwWriter.MatchNumbers(rule, UfwWriter.ParseNumbered(listing.Message))
            : Array.Empty<int>();

        IReadOnlyList<string[]> commands = numbers.Count > 0
            ? numbers.OrderByDescending(n => n).Select(n => new[] { "--force", "delete", n.ToString(CultureInfo.InvariantCulture) }).ToList()
            : UfwWriter.BuildDeleteCommands(FirewallRuleSpecs.FromRule(rule));

        var result = RunUfwBatch(commands);
        InvalidateUfwProbe();
        return result;
    }

    private static FirewallOperationResult RunUfwBatch(IReadOnlyList<string[]> commands)
    {
        var ufw = ResolveExecutable("ufw") ?? "ufw";
        var script = string.Join(" && ", commands.Select(argv =>
            Sh(ufw) + " " + string.Join(" ", argv.Select(Sh))));
        return RunPrivilegedBatch(script);
    }

    /// <summary>
    /// Deletes a rule that came from a host scan rather than this app's ledger —
    /// a UFW rule, or a bare nftables rule identified by its handle. The Firewall
    /// Config view lists the whole host firewall, so Delete has to work on rows
    /// Network Sentinel did not write; refusing them would make the list a
    /// read-only report with buttons that lie.
    /// </summary>
    public FirewallOperationResult DeleteHostRule(FirewallRuleInfo rule)
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

        // One of ours: go through the ledger so its bookkeeping stays truthful.
        if (!rule.IsForeign || rule.Kind != FirewallRuleKind.Other)
            return RemoveRule(rule.Name);

        var origin = rule.Origin ?? "";
        if (origin.Equals("UFW", StringComparison.OrdinalIgnoreCase) || BackendIsUfw())
        {
            var viaUfw = RemoveViaUfw(rule);
            return viaUfw.Success
                ? FirewallOperationResult.Ok($"Removed “{rule.LabelText}” from UFW.")
                : FirewallOperationResult.Fail($"UFW refused the delete: {viaUfw.Message}");
        }

        if (rule.Handle.Length > 0 && BackendIsNft())
        {
            // The handle is read back out of a kernel dump, so it is checked rather
            // than trusted: everything after it is interpolated into a shell line.
            if (!long.TryParse(rule.Handle, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                return FirewallOperationResult.Fail(
                    $"“{rule.LabelText}” carries an unreadable nftables handle (“{rule.Handle}”), so it cannot be " +
                    "deleted by handle. Rescan and try again.");

            var family = rule.Family.ToLowerInvariant() switch
            {
                "ipv4" or "ip" => "ip",
                "ipv6" or "ip6" => "ip6",
                "" => "inet",
                var other when other is "inet" or "netdev" or "bridge" or "arp" => other,
                _ => "inet"
            };
            var table = rule.Table.Length > 0 ? rule.Table : "filter";
            var chain = rule.Chain.Length > 0 ? rule.Chain : (rule.IsInbound ? "input" : "output");

            // Sh() is POSIX shell quoting, so the command has to reach a shell. Handed
            // to RunPrivileged — which execs nft directly — the quotes arrived as part
            // of the table and chain names, and nft answered "syntax error, unexpected
            // junk" to every delete of a rule this app had not written itself.
            var nft = ResolveExecutable("nft") ?? "nft";
            var r = RunPrivilegedBatch(
                $"{Sh(nft)} delete rule {family} {Sh(table)} {Sh(chain)} handle {rule.Handle}");
            return r.Success
                ? FirewallOperationResult.Ok($"Removed “{rule.LabelText}” from nftables.")
                : FirewallOperationResult.Fail($"nftables refused the delete: {r.Message}");
        }

        return FirewallOperationResult.Fail(
            $"“{rule.LabelText}” came from {(origin.Length > 0 ? origin : "the kernel")} and carries no handle to " +
            "delete it by. Remove it where it was created.");
    }

    /// <summary>Rule names are the ledger key, so a repeated label gets a suffix.</summary>
    private static string UniqueCustomRuleName(string label, List<FirewallRuleInfo> ledger)
    {
        var baseName = $"{RulePrefix}-Rule-{Sanitize(label)}";
        var name = baseName;
        var suffix = 2;
        while (ledger.Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)))
            name = $"{baseName}-{suffix++}";
        return name;
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
            return NoElevation("modify the host firewall");

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
                Kind = FirewallRuleKind.Other,
                Backend = BackendIsNft() ? NftBackend : IptablesBackend
            });
        }

        return applied;
    }

    public FirewallOperationResult DisableProbeLogging()
    {
        if (!IsAdministrator)
            return NoElevation("modify the host firewall");

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
    ///
    /// On the web console there is no prompt to raise, so the button does the other
    /// useful thing instead: it re-checks whether sudo will run the firewall binaries
    /// now. That is what an operator who has just written the sudoers file wants, and
    /// re-checking is the only way to answer it without waiting out the probe cache.
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (IsRoot)
            return FirewallOperationResult.Ok("Already running as root.");

        InvalidateElevationProbe();
        if (HasDirectKernelAccess())
            return FirewallOperationResult.Ok(
                "Nothing to authorize — this process holds CAP_NET_ADMIN, so rules are written straight to " +
                "the kernel without elevating.");
        if (CanElevateSilently())
            return FirewallOperationResult.Ok(
                "Nothing to authorize — this user already has passwordless sudo for the firewall binaries, " +
                "so rules apply without a prompt.");

        if (!CanApplyRules)
            return NoElevation("apply firewall rules");

        // Touch a harmless privileged read — triggers polkit/sudo password once.
        var probe = BackendIsNft()
            ? RunPrivileged("nft", "list tables")
            : RunPrivileged("iptables", "-L -n");

        if (probe.Success)
            return FirewallOperationResult.Ok(
                "Authorization OK. Firewall changes can proceed (you may be prompted again after a while).");

        var tail = Surface == FirewallUiSurface.Web
            ? $"\n\n{HeadlessElevationHelp()}"
            : "\n\nDo not run the whole app with sudo on Wayland — that breaks the display " +
              "(XOpenDisplay). Run as your user and let pkexec prompt for password.";

        return FirewallOperationResult.Fail("Elevation failed or was cancelled. " + probe.Message + tail);
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

            // Inserted at the head of the chain, not appended: see PrecedenceNote.
            var r = RunPrivileged("nft",
                $"{NftAddVerb(FirewallRuleKind.IpBlock)} rule {NftTable} {chain} {match} counter drop comment \"{Escape(name)}\"");
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
                $"{IptablesChainClause(FirewallRuleKind.IpBlock, table)} {flag} {ip} -j DROP -m comment --comment \"{Escape(name)}\"");
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
                Backend = BackendIsNft() ? NftBackend : IptablesBackend,
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
                $"{NftAddVerb(FirewallRuleKind.PortBlock)} rule {NftTable} {chain} {proto} {portMatch} counter drop comment \"{Escape(name)}\"");
            applied = r.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied (nftables).")
                : FirewallOperationResult.Fail($"Failed nft add {name}: {r.Message}");
        }
        else
        {
            var table = isInbound ? "INPUT" : "OUTPUT";
            var portFlag = isInbound ? "--dport" : "--sport";
            var r = RunPrivileged("iptables",
                $"{IptablesChainClause(FirewallRuleKind.PortBlock, table)} -p {proto} {portFlag} {port} -j DROP -m comment --comment \"{Escape(name)}\"");
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
                Kind = FirewallRuleKind.PortBlock,
                Backend = BackendIsNft() ? NftBackend : IptablesBackend
            });
        }

        return applied;
    }

    /// <summary>
    /// Wording for a rule that is not there to remove. One managed rule can hold
    /// several kernel fragments — a multi-port range, or protocol Any splitting into
    /// TCP and UDP — and the host scan lists one row per fragment. Removing the first
    /// row takes them all, so a click on a sibling row from the same listing arrives
    /// after the rule is already gone. That is the requested end state, not a fault,
    /// and reporting it as "No rule named …" read as delete being broken.
    /// </summary>
    private static string AlreadyGoneText(string name) =>
        $"“{name}” is no longer in the firewall — it was already removed, most likely " +
        "together with another row of the same rule.";

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        bool removed = false;

        // A rule UFW wrote is not in our nft table and has no comment nft can find;
        // it has to come out the way it went in.
        var ledgerEntry = LoadLedger().FirstOrDefault(r =>
            string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        if (ledgerEntry != null && ledgerEntry.Backend.Equals("ufw", StringComparison.OrdinalIgnoreCase))
        {
            removed = RemoveViaUfw(ledgerEntry).Success;
            RemoveFromLedger(name);
            return removed
                ? FirewallOperationResult.Ok($"Removed “{name}”.")
                : FirewallOperationResult.Fail($"UFW would not remove “{name}”.");
        }

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
            // A config rule's name carries no address, so which binary holds it
            // cannot be read off the name the way an IP block's can: one rule can
            // have written fragments into both tables from a mixed v4/v6 address
            // list. Sweeping both is the only way to leave nothing behind.
            var tools = name.StartsWith($"{RulePrefix}-Rule-", StringComparison.OrdinalIgnoreCase)
                ? new[] { "iptables", "ip6tables" }.Where(t => t == "iptables" || CommandExists(t)).ToArray()
                : new[] { IptablesToolFor(name) };

            foreach (var tool in tools)
            {
                removed |= DeleteIptablesByComment(tool, "INPUT", name);
                removed |= DeleteIptablesByComment(tool, "OUTPUT", name);
            }
        }

        // Ledger is always updated so UI stays consistent even if kernel rule was already gone.
        var hadLedger = LoadLedger().Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        RemoveFromLedger(name);

        return removed || hadLedger
            ? FirewallOperationResult.Ok($"Removed “{name}”.")
            : FirewallOperationResult.Fail(AlreadyGoneText(name));
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

        // Whole comment, in iptables' own delimiters — see FindNftHandles for why a
        // substring match deleted the neighbouring "…-2" rule as well.
        var needle = $"/* {name} */";
        var lines = list.Message.Split('\n')
            .Where(l => l.Contains(needle, StringComparison.Ordinal))
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

    /// <summary>
    /// Handles of the rules carrying exactly this comment.
    ///
    /// Matched whole, in nft's own quotes. A bare substring match also hit every rule
    /// whose comment merely <em>starts</em> with this one, and SaveCustomRule mints
    /// precisely that shape — a repeated label becomes "…-2" — so removing
    /// "NetworkSentinel-Rule-SSH" silently took "NetworkSentinel-Rule-SSH-2" out of
    /// the firewall with it, a rule on a different port that nobody had selected.
    /// </summary>
    private static IEnumerable<string> FindNftHandles(string dump, string comment)
    {
        var needle = $"comment \"{comment}\"";
        foreach (var line in dump.Split('\n'))
        {
            if (!line.Contains(needle, StringComparison.Ordinal)) continue;
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

    private static (bool Active, DateTime CheckedUtc) _ufwState;
    private static readonly TimeSpan UfwProbeTtl = TimeSpan.FromSeconds(30);

    /// <summary>
    /// True when UFW is installed and active, which makes it the owner of the
    /// host firewall: it holds the nftables chains and re-applies its rule set on
    /// reload and at boot. A rule written straight into nftables underneath it is
    /// invisible in `ufw status` and does not survive `ufw reload` — so where UFW
    /// is running, every rule this app writes goes through UFW instead.
    ///
    /// Installed-but-inactive does not count. Enabling UFW can lock an operator
    /// out of SSH, and that decision is never ours to make; with UFW off, the
    /// nftables path below is still the live firewall.
    ///
    /// The probe must answer without a password dialog — it runs on the write
    /// path, and prompting twice for one rule is what
    /// <see cref="RunPrivilegedBatch"/> exists to avoid. But `ufw status` needs
    /// root: run as the desktop user it prints "You need to be root to run this
    /// script" to stderr and exits 1, which the old probe read as "UFW is not
    /// active". On the ordinary Ubuntu desktop — UFW enabled, no passwordless
    /// sudo — that sent every rule into nftables while UFW owned the firewall.
    /// The rule was applied and reported added, and was then absent from
    /// `ufw status numbered`, which reads exactly like the write having failed.
    ///
    /// So a refused read falls back to <see cref="UfwEnabledFlag"/> rather than
    /// to "inactive". That file is not a guess at UFW's state: it is the same
    /// flag `ufw status` itself reports, and it is world-readable.
    /// </summary>
    internal static bool BackendIsUfw()
    {
        if (DateTime.UtcNow - _ufwState.CheckedUtc < UfwProbeTtl) return _ufwState.Active;

        var active = false;
        if (CommandExists("ufw"))
        {
            var status = ReadCommand("ufw", "status");
            active = status.Ok && status.StdOut.Trim().Length > 0
                ? status.StdOut.Contains("Status: active", StringComparison.OrdinalIgnoreCase)
                : UfwEnabledFlag() == true;
        }

        _ufwState = (active, DateTime.UtcNow);
        return active;
    }

    /// <summary>UFW's own configuration file, mode 0644 on Debian and its derivatives.</summary>
    private const string UfwConfigFile = "/etc/ufw/ufw.conf";

    private static readonly Regex UfwEnabledSetting = new(
        @"^[ \t]*ENABLED[ \t]*=[ \t]*""?(?<value>[A-Za-z]+)""?[ \t\r]*$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// UFW's enabled flag as ufw.conf holds it: true, false, or null when the file
    /// is missing, unreadable or says nothing about it. Used only when `ufw status`
    /// could not be run — where it can, its answer wins.
    /// </summary>
    private static bool? UfwEnabledFlag()
    {
        try
        {
            return File.Exists(UfwConfigFile) ? ParseUfwEnabledFlag(File.ReadAllText(UfwConfigFile)) : null;
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// Reads ENABLED out of ufw.conf the way UFW's own loader does: shell-style
    /// KEY=value, last assignment wins, commented-out lines ignored. Anything
    /// other than yes/no is not an answer — ufw.conf is edited by hand often
    /// enough that a typo must not be read as a decision either way.
    /// </summary>
    internal static bool? ParseUfwEnabledFlag(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;

        bool? flag = null;
        foreach (Match match in UfwEnabledSetting.Matches(text))
        {
            var value = match.Groups["value"].Value;
            if (value.Equals("yes", StringComparison.OrdinalIgnoreCase)) flag = true;
            else if (value.Equals("no", StringComparison.OrdinalIgnoreCase)) flag = false;
        }
        return flag;
    }

    /// <summary>
    /// Said after a rule goes into nftables on a host that has UFW installed. The
    /// rule is in force, but it is not UFW's, so `ufw status` will not list it —
    /// and an operator who checks there sees nothing and concludes the write
    /// failed. Which of the three reasons it was is worth saying: only one of them
    /// is something they chose.
    /// </summary>
    private static string OutsideUfwNote()
    {
        if (!CommandExists("ufw")) return "";

        return UfwEnabledFlag() switch
        {
            false => " UFW is installed but switched off, so the rule went into nftables — " +
                     "“ufw status” will not list it.",
            true => " UFW’s configuration says it is enabled but “ufw status” reported it inactive, " +
                    "so the rule went into nftables — “ufw status” will not list it. " +
                    "Run “sudo ufw status” to see which of the two is stale.",
            null => " UFW is installed and its state could not be read, so the rule went into nftables — " +
                    "“ufw status” will not list it. Grant this user passwordless sudo for ufw " +
                    "(see “Firewall elevation on a headless server” in the README) to have UFW own the rules."
        };
    }

    /// <summary>Forgets the cached UFW probe — called after a write, which can flip it.</summary>
    private static void InvalidateUfwProbe() => _ufwState = (false, DateTime.MinValue);

    /// <summary>
    /// The only places a firewall tool or an elevation helper is looked for. Every
    /// binary resolved here is run as root (through pkexec or sudo), or *is* the
    /// elevation helper, so PATH is deliberately not consulted: Ubuntu's stock
    /// <c>~/.profile</c> puts <c>~/.local/bin</c> on it, and anything running as the
    /// user could drop an <c>nft</c> there for the next approved prompt — or a fake
    /// <c>pkexec</c> to collect the password. The sbin directories also matter in
    /// their own right: a desktop session on Debian and its derivatives leaves them
    /// out of a normal user's PATH, and <c>nft</c>, <c>iptables</c> and <c>ufw</c> all
    /// live there. The two NixOS entries hold its system profile and its setuid
    /// wrappers (sudo, pkexec), and are root-owned like the rest.
    /// </summary>
    internal static readonly string[] TrustedToolDirectories =
    {
        "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
        "/run/wrappers/bin", "/run/current-system/sw/bin"
    };

    /// <summary>
    /// Whether a command is present. This used to shell out to <c>which</c>, which is
    /// no longer installed by default on Fedora or Debian trixie: on those hosts every
    /// probe answered "missing", so <see cref="IsAdministrator"/> reported no way to
    /// elevate on a machine that had both pkexec and sudo, and the host scan reported
    /// no firewall backend on a machine running UFW. Resolving in-process removes both
    /// the dependency and a subprocess per probe.
    /// </summary>
    private static bool CommandExists(string name) => ResolveExecutable(name) != null;

    /// <summary>
    /// Password dialogs <c>sudo -A</c> can drive, in the order the desktops that ship
    /// them are likely to be running.
    /// </summary>
    private static readonly string[] AskpassCandidates =
    {
        "/usr/bin/ksshaskpass",
        "/usr/libexec/openssh/gnome-ssh-askpass",
        "/usr/lib/openssh/gnome-ssh-askpass",
        "/usr/libexec/seahorse/ssh-askpass",
        "/usr/bin/lxqt-openssh-askpass",
        "/usr/lib/ssh/x11-ssh-askpass",
        "/usr/bin/ssh-askpass"
    };

    /// <summary>
    /// A graphical password prompt for sudo, or null when there is none. This is the
    /// path that makes a sudo-only host usable from the GUI: without pkexec, sudo has
    /// nowhere to prompt — the GUI's stdin is not a terminal — so a rule the operator
    /// had every right to add failed with a message telling them to install sudo.
    /// </summary>
    private static string? FindAskpassHelper()
    {
        if (!PlatformSupported) return null;

        // A helper the operator configured is honoured wherever it is set: they chose
        // it, and it may well be one that prompts without a display.
        var configured = Environment.GetEnvironmentVariable("SUDO_ASKPASS");
        if (!string.IsNullOrWhiteSpace(configured) && IsExecutableFile(configured))
            return configured;

        // The discovered ones are all graphical, so they are only worth trying where
        // there is a display to draw on. Invoked without one they exit non-zero, and
        // sudo reads that as a refused password.
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")) &&
            string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")))
            return null;

        foreach (var candidate in AskpassCandidates)
            if (IsExecutableFile(candidate))
                return candidate;

        return null;
    }

    /// <summary>
    /// Whether sudo could prompt on a terminal. A GUI started from a launcher has no
    /// stdin to read a password from, so this is false there and the askpass path is
    /// the only one left.
    /// </summary>
    private static bool HasTerminal()
    {
        try { return !Console.IsInputRedirected; }
        catch { return false; }
    }

    /// <summary>
    /// Runs a host-firewall tool, elevating with pkexec (preferred) or sudo when
    /// not already root. Never relaunches the Avalonia UI as root.
    /// </summary>
    private static FirewallOperationResult RunPrivileged(string file, string args)
    {
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (IsRootProcess())
            return RunDirect(file, args);

        // Resolve the absolute path here, from the trusted directories only: pkexec and
        // sudo run whatever path they are handed, so this is the decision about what root runs.
        var resolved = ResolveExecutable(file);
        if (resolved == null)
            return FirewallOperationResult.Fail($"{file}: command not found in the system directories.");

        // Nothing to elevate to: the capability is already held, and the command will
        // do exactly what it would do under sudo. Returned whichever way it goes — a
        // failure here is the kernel rejecting the rule, not a missing privilege, and
        // retrying it under sudo would only apply it twice or blame the wrong thing.
        if (HonoursCapabilities(resolved) && HasDirectKernelAccess())
            return RunDirect(resolved, args);

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
            var r = RunDirect("pkexec", $"{Quote(resolved)} {args}", InteractiveProcessTimeoutMs);
            if (r.Success || !LooksLikeMissingHelper(r.Message))
                return r;
        }

        // 2) sudo -n first (passwordless / already cached)
        if (CommandExists("sudo"))
        {
            var cached = RunDirect("sudo", $"-n {Quote(resolved)} {args}");
            if (cached.Success)
                return cached;

            // 3) sudo -A — a password dialog on a host that has sudo but no pkexec.
            // A cancelled or wrong password comes back as sudo's own refusal, which is
            // the answer; only a helper that would not run at all falls through.
            var askpass = FindAskpassHelper();
            if (askpass != null)
            {
                var prompted = RunDirect("sudo", $"-A {Quote(resolved)} {args}",
                    InteractiveProcessTimeoutMs, askpass);
                if (prompted.Success || !LooksLikeMissingHelper(prompted.Message))
                    return prompted;
            }

            // 4) Interactive sudo only if we have a TTY (rare for GUI)
            if (HasTerminal())
                return RunDirect("sudo", $"{Quote(resolved)} {args}", InteractiveProcessTimeoutMs);

            return FirewallOperationResult.Fail(NoPasswordPromptText(cached.Message));
        }

        return FirewallOperationResult.Fail("No elevation helper (pkexec/sudo) available.");
    }

    /// <summary>
    /// The sudo-but-nowhere-to-type-the-password case, with sudo's own refusal kept
    /// so a wrong sudoers entry is not reported as a missing package.
    /// </summary>
    private static string NoPasswordPromptText(string sudoMessage)
    {
        // The desktop wording named a window, a Wayland session and a GUI started with
        // sudo. Read in a browser on a phone, pointed at a systemd service, not one of
        // those three is a thing the operator has — so the web console gets the advice
        // that fits it, with the grant already filled in for this host.
        var text = Surface == FirewallUiSurface.Web
            ? "The web console cannot write firewall rules: sudo is installed but wants a password, and " +
              "there is nowhere to ask for one — no terminal, no cached credentials, and no desktop on " +
              "the server for pkexec or an askpass dialog to draw on. A browser cannot answer a prompt " +
              $"raised on the host.\n\n{HeadlessElevationHelp()}"
            : "Sudo is installed but has no way to ask for a password here: this window is not a terminal, " +
              "no cached credentials are in force, and no pkexec or askpass dialog was found. Install " +
              "policykit-1 (pkexec), or grant this user passwordless sudo for ufw/nft/iptables — see " +
              "“Firewall elevation on a headless server” in the README. Do not start the GUI with plain " +
              "sudo on Wayland.";
        return string.IsNullOrWhiteSpace(sudoMessage) ? text : $"{text}\n\nsudo said: {sudoMessage.Trim()}";
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
        if (!PlatformSupported)
            return FirewallOperationResult.Fail(UnsupportedPlatformText);

        if (IsRootProcess())
            return RunDirectArgs("/bin/sh", new[] { "-c", script });

        // The whole point of the batch is one password for the sequence. With the
        // capability held there is no password to ask for, so the shell runs as us and
        // every nft/iptables it spawns inherits the right to write. A script that calls
        // ufw is excluded: ufw tests the uid, not the capability.
        if (HasDirectKernelAccess() && !MentionsUfw(script))
            return RunDirectArgs("/bin/sh", new[] { "-c", script });

        if (CommandExists("pkexec"))
        {
            var r = RunDirectArgs("pkexec", new[] { "/bin/sh", "-c", script }, InteractiveProcessTimeoutMs);
            if (r.Success || !LooksLikeMissingHelper(r.Message))
                return r;
        }

        if (CommandExists("sudo"))
        {
            var cached = RunDirectArgs("sudo", new[] { "-n", "/bin/sh", "-c", script });
            if (cached.Success)
                return cached;

            var askpass = FindAskpassHelper();
            if (askpass != null)
            {
                var prompted = RunDirectArgs("sudo", new[] { "-A", "/bin/sh", "-c", script },
                    InteractiveProcessTimeoutMs, askpass);
                if (prompted.Success || !LooksLikeMissingHelper(prompted.Message))
                    return prompted;
            }

            if (HasTerminal())
                return RunDirectArgs("sudo", new[] { "/bin/sh", "-c", script }, InteractiveProcessTimeoutMs);

            return FirewallOperationResult.Fail(NoPasswordPromptText(cached.Message));
        }

        return FirewallOperationResult.Fail("No elevation helper (pkexec/sudo) available.");
    }

    /// <summary>
    /// Whether a batch script calls UFW, which refuses a capability-endowed user and
    /// so has to stay on the elevation path.
    ///
    /// Matched as a bare token rather than as a command at the head of a line: the
    /// batch is assembled from <see cref="Sh"/>-quoted argv, so the binary arrives as
    /// <c>'/usr/sbin/ufw'</c> — quoted, mid-string, and invisible to a pattern that
    /// expects a command to follow whitespace. Erring towards a match only costs a
    /// batch the direct path; missing one runs ufw as a non-root uid, which it refuses.
    /// </summary>
    internal static bool MentionsUfw(string script)
        => Regex.IsMatch(script, @"(?<![\w.-])ufw(?![\w.-])");

    private static bool LooksLikeMissingHelper(string message)
        => message.Contains("not found", StringComparison.OrdinalIgnoreCase)
           || message.Contains("No such file", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Absolute path of a command, or null when it is not installed (or is installed
    /// somewhere anyone but root could have replaced it). Resolved in this process
    /// against <see cref="TrustedToolDirectories"/> only — see that list for why PATH is
    /// not used, and <see cref="CommandExists"/> for why <c>which</c> is not either.
    /// </summary>
    internal static string? ResolveExecutable(string name)
    {
        if (name.Contains('/')) return name;

        foreach (var dir in ExecutableSearchPath())
        {
            var candidate = Path.Combine(dir, name);
            if (IsExecutableFile(candidate) && IsSafeToRunPrivileged(candidate))
                return candidate;
        }

        return null;
    }

    /// <summary>The trusted directories, in search order.</summary>
    internal static IEnumerable<string> ExecutableSearchPath() => TrustedToolDirectories;

    /// <summary>
    /// Whether neither the file nor the directory holding it can be rewritten by
    /// anyone outside its owner. The trusted directories are root's on every sane
    /// install; this catches the ones that are not — a group-writable
    /// <c>/usr/local/bin</c> handed to a "staff" group, a binary left mode 0777 — where
    /// a non-root account could swap in what root is about to run.
    /// </summary>
    internal static bool IsSafeToRunPrivileged(string path)
    {
        if (OperatingSystem.IsWindows()) return true;   // no Unix mode to read
        try
        {
            const UnixFileMode othersCanWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
            if ((File.GetUnixFileMode(path) & othersCanWrite) != 0)
                return false;
            var dir = Path.GetDirectoryName(path);
            return dir != null && (File.GetUnixFileMode(dir) & othersCanWrite) == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// A file that exists and carries an execute bit. The mode check matters: PATH
    /// entries routinely hold same-named data files, and a directory named like the
    /// tool would otherwise resolve as the tool.
    /// </summary>
    internal static bool IsExecutableFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            if (OperatingSystem.IsWindows()) return true;   // no Unix mode to read

            const UnixFileMode anyExecute =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            return (File.GetUnixFileMode(path) & anyExecute) != 0;
        }
        catch
        {
            return false;
        }
    }

    // ── Read-only command execution ──────────────────────────────────────
    //
    // HostFirewallScanner reads the live ruleset (`ufw status`, `nft -j list
    // ruleset`, `iptables -S`, `ss -tulpnH`). Those are inspections, not
    // changes, so they must never raise a pkexec password dialog — a firewall
    // view that prompts for a password every refresh is a view nobody opens.
    // The order is: try it as we are, then retry under `sudo -n`, which either
    // works from cached/NOPASSWD credentials or fails immediately.

    private const int ReadProcessTimeoutMs = 8_000;

    /// <summary>Whether a read-only tool is installed. Same resolution as the write path.</summary>
    internal static bool ReadCommandExists(string name) => CommandExists(name);

    /// <summary>
    /// Runs a read-only command and returns its streams separately — unlike
    /// <see cref="RunProcess"/>, which merges them, and would feed stderr into a
    /// JSON parser. Never elevates interactively.
    /// </summary>
    internal static (bool Ok, string StdOut, string StdErr) ReadCommand(string file, params string[] args)
    {
        var resolved = ResolveExecutable(file);
        if (resolved == null) return (false, "", $"{file} not found");

        var direct = ReadProcess(resolved, args);
        if (direct.Ok && direct.StdOut.Trim().Length > 0) return direct;

        // Empty or refused as a normal user is the usual case for `ufw status`
        // and `nft list ruleset`; passwordless sudo is the one retry worth making.
        if (!IsRootProcess() && CommandExists("sudo"))
        {
            var sudo = ResolveExecutable("sudo");
            if (sudo != null)
            {
                var elevated = ReadProcess(sudo, new[] { "-n", resolved }.Concat(args).ToArray());
                if (elevated.Ok && elevated.StdOut.Trim().Length > 0) return elevated;
            }
        }

        return direct;
    }

    private static (bool Ok, string StdOut, string StdErr) ReadProcess(string file, IReadOnlyList<string> args)
    {
        try
        {
            var psi = new ProcessStartInfo(file)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (var arg in args) psi.ArgumentList.Add(arg);

            using var p = Process.Start(psi);
            if (p == null) return (false, "", $"Could not start {file}.");

            // Both pipes drained concurrently — see RunProcess for why reading one
            // to EOF first deadlocks.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(ReadProcessTimeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return (false, "", $"{file} did not finish within {ReadProcessTimeoutMs / 1000}s.");
            }

            return (p.ExitCode == 0,
                    stdoutTask.GetAwaiter().GetResult(),
                    stderrTask.GetAwaiter().GetResult());
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    private const int DefaultProcessTimeoutMs = 30_000;

    /// <summary>Paths that raise a password dialog include a human typing — allow minutes, not seconds.</summary>
    private const int InteractiveProcessTimeoutMs = 300_000;

    /// <summary>
    /// Same as <see cref="RunDirect"/> but passes argv entries individually, so
    /// shell metacharacters in an argument survive verbatim. Required for the
    /// batched elevation path, where the payload is a shell script.
    /// </summary>
    private static FirewallOperationResult RunDirectArgs(string file, string[] argv, int timeoutMs = DefaultProcessTimeoutMs, string? askpass = null)
    {
        if (!TryResolveForSpawn(ref file, out var missing)) return missing!;
        var psi = new ProcessStartInfo(file);
        foreach (var a in argv)
            psi.ArgumentList.Add(a);
        return RunProcess(psi, file, timeoutMs, askpass);
    }

    private static FirewallOperationResult RunDirect(string file, string args, int timeoutMs = DefaultProcessTimeoutMs, string? askpass = null)
    {
        if (!TryResolveForSpawn(ref file, out var missing)) return missing!;
        var psi = new ProcessStartInfo(file, args);
        return RunProcess(psi, file, timeoutMs, askpass);
    }

    /// <summary>
    /// Turns a bare command name into its trusted absolute path. Handing a bare name to
    /// <see cref="ProcessStartInfo"/> makes the runtime search PATH, which is exactly the
    /// lookup <see cref="ResolveExecutable"/> exists to avoid — for <c>sudo</c> and
    /// <c>pkexec</c> above all. The failure text says "not found", so the elevation
    /// fallbacks read it as a missing helper and move on to the next one.
    /// </summary>
    private static bool TryResolveForSpawn(ref string file, out FirewallOperationResult? missing)
    {
        missing = null;
        if (file.Contains('/')) return true;
        var resolved = ResolveExecutable(file);
        if (resolved == null)
        {
            missing = FirewallOperationResult.Fail($"{file}: command not found in the system directories.");
            return false;
        }
        file = resolved;
        return true;
    }

    /// <summary>Starts a process, drains both pipes, and turns its exit into a result.</summary>
    /// <param name="askpass">
    /// Password helper for a <c>sudo -A</c> call. Set in the child's environment rather
    /// than exported into this process, so a helper chosen for one call cannot leak
    /// into an unrelated subprocess.
    /// </param>
    private static FirewallOperationResult RunProcess(ProcessStartInfo psi, string file, int timeoutMs = DefaultProcessTimeoutMs, string? askpass = null)
    {
        try
        {
            psi.UseShellExecute = false;
            // Only legal once UseShellExecute is false, which is why it follows it.
            if (askpass != null)
                psi.Environment["SUDO_ASKPASS"] = askpass;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;

            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail($"Could not start {file}.");

            // Both pipes drained concurrently: reading stdout to EOF before touching
            // stderr deadlocks when the child fills the stderr buffer first — and the
            // blocked read meant the WaitForExit timeout below never engaged, so a
            // hung nft/pkexec pinned the calling thread indefinitely.
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return FirewallOperationResult.Fail($"{file} did not finish within {timeoutMs / 1000}s.");
            }

            string stdout = stdoutTask.GetAwaiter().GetResult();
            string stderr = stderrTask.GetAwaiter().GetResult();
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
    ///
    /// Every backend an entry could live in is consulted, not just the currently
    /// active one: installing nftables flips <see cref="BackendIsNft"/> between runs,
    /// and a missing nft table says nothing about rules iptables wrote. An entry is
    /// only dropped once the backend that owns it has actually been listed — a
    /// backend we could not read leaves its entries alone rather than blackholing
    /// live kernel rules the UI would then have no way to show or remove.
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

            // Entries written before Backend was recorded could be from either, so they
            // pin both — and are only judged once both have been read.
            var needBoth = ledger.Any(r => string.IsNullOrEmpty(r.Backend));
            var wanted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in ledger.Where(r => !string.IsNullOrEmpty(r.Backend)))
                wanted.Add(r.Backend);
            if (needBoth || wanted.Count == 0)
            {
                wanted.Add(NftBackend);
                wanted.Add(IptablesBackend);
            }

            var dump = new StringBuilder();
            var consulted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            _silentElevationOnly = true;
            try
            {
                if (wanted.Contains(NftBackend))
                {
                    if (!CommandExists("nft"))
                    {
                        // No nft binary means no nft rules — reading it is vacuously done.
                        consulted.Add(NftBackend);
                    }
                    else
                    {
                        var list = RunPrivileged("nft", $"list table {NftTable}");
                        if (list.Success)
                        {
                            dump.Append(list.Message).Append('\n');
                            consulted.Add(NftBackend);
                        }
                        else if (LooksLikeMissingTable(list.Message))
                        {
                            // Managed table gone entirely — the post-reboot case. Its
                            // entries are stale; entries iptables owns are not.
                            consulted.Add(NftBackend);
                        }
                    }
                }

                if (wanted.Contains(IptablesBackend))
                {
                    var ok = true;
                    if (!CommandExists("iptables"))
                    {
                        // Same reasoning as nft above.
                    }
                    else
                    {
                        var input = RunPrivileged("iptables", "-L INPUT -n");
                        var output = RunPrivileged("iptables", "-L OUTPUT -n");
                        ok = input.Success && output.Success;
                        if (ok)
                            dump.Append(input.Message).Append('\n').Append(output.Message).Append('\n');
                    }

                    // v6 blocks live in a separate table; miss it and every IPv6 entry
                    // reads as stale.
                    var wantsV6 = ledger.Any(r => IptablesToolFor(r.Name) == "ip6tables");
                    if (ok && wantsV6 && CommandExists("ip6tables"))
                    {
                        var input6 = RunPrivileged("ip6tables", "-L INPUT -n");
                        var output6 = RunPrivileged("ip6tables", "-L OUTPUT -n");
                        ok = input6.Success && output6.Success;
                        if (ok)
                            dump.Append(input6.Message).Append('\n').Append(output6.Message).Append('\n');
                    }

                    if (ok)
                        consulted.Add(IptablesBackend);
                }
            }
            finally
            {
                _silentElevationOnly = false;
            }

            if (consulted.Count == 0)
                return FirewallOperationResult.Fail("Could not list kernel rules — reconciliation skipped.");

            var text = dump.ToString();

            // Rule names carry an -In/-Out suffix, so no managed name is a prefix of
            // another and a plain containment test against the dump is exact enough.
            bool IsStale(FirewallRuleInfo r)
            {
                var owner = string.IsNullOrEmpty(r.Backend) ? null : r.Backend;
                var judged = owner == null
                    ? consulted.Contains(NftBackend) && consulted.Contains(IptablesBackend)
                    : consulted.Contains(owner);
                return judged && !text.Contains(r.Name, StringComparison.Ordinal);
            }

            var stale = ledger.Where(IsStale).Select(r => r.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (stale.Count == 0)
                return FirewallOperationResult.Ok("Ledger matches kernel rules.");

            // Re-read under the lock and drop only the names judged stale: the listing
            // above costs several privileged subprocess calls, and a block written in
            // that window must not be erased by writing back a pre-fetch snapshot.
            lock (_ledgerGate)
            {
                var current = LoadLedger();
                current.RemoveAll(r => stale.Contains(r.Name));
                SaveLedger(current);
            }

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

    /// <summary>
    /// Whether sudo will run a firewall command without asking for anything.
    ///
    /// This used to probe with <c>sudo -n true</c>, which answers no on exactly the
    /// host the README tells operators to build: a grant scoped to <c>nft</c>,
    /// <c>ufw</c> and <c>iptables</c> does not cover <c>true</c>. Auto-block expiry and
    /// ledger reconciliation both gate on this, so on a correctly configured headless
    /// server the expiry sweep quietly never ran and temporary blocks became permanent.
    ///
    /// The answer is cached because a failed <c>sudo -n</c> is written to the auth log,
    /// which this very application watches for break-in attempts; a probe on every
    /// snapshot would have Network Sentinel reporting on itself.
    /// </summary>
    internal static bool CanElevateSilently()
    {
        if (!PlatformSupported) return false;
        if (IsRootProcess()) return true;

        // A held capability is silent by definition — nothing is asked for.
        if (HasDirectKernelAccess()) return true;

        if (!CommandExists("sudo")) return false;

        var now = Environment.TickCount64;
        lock (SilentProbeLock)
        {
            if (_silentProbeStampMs != 0 &&
                now - _silentProbeStampMs < (_silentProbeResult ? SilentProbeOkTtlMs : SilentProbeFailTtlMs))
                return _silentProbeResult;
        }

        var result = ProbeSilentSudo();

        lock (SilentProbeLock)
        {
            _silentProbeResult = result;
            _silentProbeStampMs = Environment.TickCount64;
        }
        return result;
    }

    /// <summary>
    /// Forgets the cached <see cref="CanElevateSilently"/> answer, so an operator who
    /// has just written the sudoers file sees the change on the next Rescan instead of
    /// waiting out the cache.
    /// </summary>
    public static void InvalidateElevationProbe()
    {
        lock (SilentProbeLock)
        {
            _silentProbeStampMs = 0;
            _directProbeStampMs = 0;
        }
    }

    /// <summary>
    /// Whether this process can drive the kernel's firewall without elevating at all.
    ///
    /// A systemd unit given <c>AmbientCapabilities=CAP_NET_ADMIN</c> runs as an
    /// ordinary user and still has every right nftables asks for, and the ambient set
    /// survives <c>execve</c>, so the <c>nft</c> it spawns has it too. The read path
    /// has always benefited from this by accident — it tries the bare command before
    /// reaching for sudo — which is why such a host lists its whole ruleset happily
    /// and then refuses every write: the write path went straight to pkexec/sudo the
    /// moment it saw a non-root euid, and never tried the thing that would have worked.
    ///
    /// Probed rather than read out of <c>/proc/self/status</c>: what matters is whether
    /// a <em>child</em> keeps the capability, which depends on the ambient set, on file
    /// capabilities, and on which of the two granted it. Running the read settles all
    /// of that at once and is exactly the operation the writes will need.
    /// </summary>
    internal static bool HasDirectKernelAccess()
    {
        if (!PlatformSupported) return false;
        if (IsRootProcess()) return true;

        var now = Environment.TickCount64;
        lock (SilentProbeLock)
        {
            if (_directProbeStampMs != 0 &&
                now - _directProbeStampMs < (_directProbeResult ? SilentProbeOkTtlMs : SilentProbeFailTtlMs))
                return _directProbeResult;
        }

        var result = ProbeDirectKernelAccess();

        lock (SilentProbeLock)
        {
            _directProbeResult = result;
            _directProbeStampMs = Environment.TickCount64;
        }
        return result;
    }

    private static bool ProbeDirectKernelAccess()
    {
        try
        {
            // Listing is refused with EPERM for a user without the capability and
            // succeeds for one with it, so it separates the two hosts without writing
            // anything. `nft list tables` is the cheapest form; iptables answers for a
            // host with no nft binary.
            if (CommandExists("nft"))
                return RunDirectArgs("nft", new[] { "list", "tables" }).Success;
            if (CommandExists("iptables"))
                return RunDirectArgs("iptables", new[] { "-S", "-t", "filter" }).Success;
        }
        catch
        {
            // Treated as "no direct access" — the callers all fall back to elevating.
        }
        return false;
    }

    /// <summary>
    /// Whether a tool honours capabilities at all. UFW is a Python script that opens
    /// with a <c>getuid() != 0</c> test, so it refuses a capability-endowed user out of
    /// hand — running it directly only produces "You need to be root to run this
    /// script", which is what the host scan has been reporting all along.
    /// </summary>
    private static bool HonoursCapabilities(string tool)
        => !Path.GetFileName(tool).Equals("ufw", StringComparison.OrdinalIgnoreCase);

    private static bool ProbeSilentSudo()
    {
        try
        {
            // A blanket NOPASSWD grant answers here and costs one process.
            if (RunDirectArgs("sudo", new[] { "-n", "true" }).Success)
                return true;

            // A scoped grant does not, so ask the tools it does name for their version:
            // harmless, and it goes through the same sudoers line the writes will.
            foreach (var tool in PrivilegedTools)
            {
                var resolved = ResolveExecutable(tool);
                if (resolved == null) continue;
                if (RunDirectArgs("sudo", new[] { "-n", resolved, "--version" }).Success)
                    return true;
            }
        }
        catch
        {
            // Treated as "cannot elevate silently" — the callers are all best-effort.
        }
        return false;
    }

    private static readonly object SilentProbeLock = new();
    private static bool _silentProbeResult;
    private static long _silentProbeStampMs;
    private static bool _directProbeResult;
    private static long _directProbeStampMs;

    /// <summary>A grant that works is stable; re-checking it often buys nothing.</summary>
    private const int SilentProbeOkTtlMs = 60_000;

    /// <summary>
    /// A grant that is missing is the case an operator is actively fixing, but every
    /// probe leaves a line in the auth log, so it is re-checked less often than it is
    /// asked about and <see cref="InvalidateElevationProbe"/> covers the impatient.
    /// </summary>
    private const int SilentProbeFailTtlMs = 300_000;

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

    /// <summary>
    /// Serialises read-modify-write of the ledger. Three threads reach it in a normal
    /// session — the expiry-sweep timer, the startup reconcile, and auto-block on its
    /// Task.Run thread — and an unguarded load/save pair silently dropped whichever
    /// entry lost the race, leaving an orphan kernel rule the UI could not see or
    /// expire. Static because the ledger is one file, whatever instance touches it.
    /// </summary>
    private static readonly object _ledgerGate = new();

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
        lock (_ledgerGate)
        {
            var list = LoadLedger();
            list.RemoveAll(r => string.Equals(r.Name, rule.Name, StringComparison.OrdinalIgnoreCase));
            list.Add(rule);
            SaveLedger(list);
        }
    }

    private static void RemoveFromLedger(string name)
    {
        lock (_ledgerGate)
        {
            var list = LoadLedger();
            list.RemoveAll(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            SaveLedger(list);
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
    Other,

    /// <summary>
    /// A rule the operator wrote in the Firewall Config view: any action, any
    /// direction, a protocol, a port range and an address list. The other kinds
    /// are minted by the app (auto-block, manual block, probe logging).
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

    /// <summary>
    /// Which backend actually wrote the kernel rule: <c>"nft"</c> or <c>"iptables"</c>.
    /// Empty on entries written before this was recorded. Reconciliation needs it —
    /// the live backend can change between runs (installing nftables flips it), and
    /// "the nft table is missing" is not evidence about a rule iptables created.
    /// </summary>
    public string Backend { get; init; } = "";

    /// <summary>UTC time this rule stops applying (null = permanent). Set by auto-block expiry.</summary>
    public DateTime? ExpiresUtc { get; init; }

    // ── Host-scan fields ─────────────────────────────────────────────────
    //
    // Set by HostFirewallScanner on rules read back out of the kernel, which is
    // most of what the Firewall Config view lists: UFW's rules, WireGuard's,
    // Docker's, and this app's own. They are never persisted — the ledger holds
    // only rules Network Sentinel wrote, and it already knows their shape.

    /// <summary>
    /// Which subsystem put the rule in the kernel — "UFW", "Network Sentinel",
    /// "WireGuard", "Docker", "nftables". Drives the Created by column, so a
    /// foreign rule is never mistaken for one this app is responsible for.
    /// </summary>
    [JsonIgnore] public string Origin { get; init; } = "";

    /// <summary>nftables rule handle: what <c>nft delete rule … handle N</c> needs.</summary>
    [JsonIgnore] public string Handle { get; init; } = "";

    [JsonIgnore] public string Table { get; init; } = "";
    [JsonIgnore] public string Chain { get; init; } = "";

    /// <summary>nft address family — <c>inet</c>, <c>ip</c>, <c>ip6</c>.</summary>
    [JsonIgnore] public string Family { get; init; } = "";

    /// <summary>
    /// True for a rule read out of the kernel that this app did not write. The
    /// editor still opens it, but deletes route to whichever backend owns it.
    /// </summary>
    [JsonIgnore] public bool IsForeign { get; init; }

    /// <summary>Verdict as the backend words it: Accept, Drop, Reject, Return, Jump.</summary>
    [JsonIgnore] public string Verdict { get; init; } = "";

    /// <summary>
    /// The rule's own kernel comment, empty when it carries none. Distinct from
    /// <see cref="Label"/>, which falls back to a minted name — an unnamed bare
    /// accept in a base chain is plumbing, and only the comment tells them apart.
    /// </summary>
    [JsonIgnore] public string Comment { get; init; } = "";

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
        _ => "Rule"
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
            // A scanned rule already knows who wrote it; the ledger kinds below
            // only describe rules this app minted.
            if (!string.IsNullOrWhiteSpace(Origin)) return Origin;

            if (string.Equals(Name, FirewallService.ProbeLogRuleName, StringComparison.OrdinalIgnoreCase))
                return "Probe logging";

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
