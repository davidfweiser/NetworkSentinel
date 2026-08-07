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

    public string PrivilegeText => IsAdministrator
        ? "Running as Administrator — firewall rules can be applied."
        : "Not elevated — use “Run as Admin” / authorize (UAC) to add or remove firewall rules.";

    /// <summary>
    /// TUI/Web “Authorize” action. On Windows this relaunches the process elevated (UAC).
    /// </summary>
    public FirewallOperationResult AuthorizeElevation()
    {
        if (IsAdministrator)
            return FirewallOperationResult.Ok("Already running as Administrator. Firewall rules can be applied.");

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
        var r1 = RemoveRuleByName(inName);
        var r2 = RemoveRuleByName(outName);
        InvalidateRuleCache();

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

        var r1 = RemoveRuleByName(PortRuleName(port, protocol, true));
        var r2 = RemoveRuleByName(PortRuleName(port, protocol, false));
        InvalidateRuleCache();
        if (!r1.Success && !r2.Success)
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

            InvalidateRuleCache();

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

    /// <param name="skip">Rules to leave in place (e.g. the web console's own allow rule).</param>
    public FirewallOperationResult RemoveAllManagedRules(Func<FirewallRuleInfo, bool>? skip = null)
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        var rules = GetManagedRules();
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

        InvalidateRuleCache();
        var msg = $"Removed {removed} Network Sentinel firewall rule(s).";
        if (kept > 0)
            msg += $" Kept {kept} (web console access).";
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

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        // netsh ONLY — never HNetCfg COM. COM remove/enumerate from MTA thread-pool
        // workers (web UI) can AccessViolation and kill NetworkSentinel.exe.
        var safeName = name.Replace("\"", "").Trim();
        if (string.IsNullOrEmpty(safeName))
            return FirewallOperationResult.Fail("Rule name is empty.");

        var netsh = RunNetsh($"advfirewall firewall delete rule name=\"{safeName}\"");
        if (netsh.Success)
            return FirewallOperationResult.Ok($"Removed \"{safeName}\".");

        if (netsh.Message.Contains("No rules match", StringComparison.OrdinalIgnoreCase) ||
            netsh.Message.Contains("cannot find", StringComparison.OrdinalIgnoreCase))
        {
            return FirewallOperationResult.Fail($"No rule named \"{safeName}\" (it may already be gone).");
        }

        return FirewallOperationResult.Fail(
            string.IsNullOrWhiteSpace(netsh.Message)
                ? $"Failed to remove \"{safeName}\" (netsh error)."
                : netsh.Message);
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
               || name.StartsWith(RulePrefix + "-Web-", StringComparison.OrdinalIgnoreCase);
    }

    private static FirewallRuleKind ClassifyRuleKind(string name, string remote, string localPorts)
    {
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
        var list = new List<FirewallRuleInfo>();
        // Non-verbose still includes every field we parse (name, enabled, direction,
        // remote IP, local port, protocol, action) at a fraction of the output size.
        var result = RunNetsh("advfirewall firewall show rule name=all");
        if (!result.Success && string.IsNullOrWhiteSpace(result.Message))
            return list;

        // Parse netsh dump for our prefix
        string? currentName = null;
        string enabled = "";
        string direction = "";
        string profiles = "";
        string remoteIp = "";
        string localPort = "";
        string protocol = "";
        string action = "";

        void Flush()
        {
            if (string.IsNullOrWhiteSpace(currentName) || !IsManagedRuleName(currentName))
                return;

            var remoteNorm = NormalizeRemote(remoteIp);
            var portsNorm = string.IsNullOrWhiteSpace(localPort) || localPort is "*" ? "" : localPort.Trim();
            var protoNorm = string.IsNullOrWhiteSpace(protocol) ? "Any" : protocol;
            list.Add(new FirewallRuleInfo
            {
                Name = currentName,
                Enabled = enabled.Contains("Yes", StringComparison.OrdinalIgnoreCase),
                IsBlock = action.Contains("Block", StringComparison.OrdinalIgnoreCase),
                Direction = direction.Contains("Out", StringComparison.OrdinalIgnoreCase)
                    ? FirewallDirection.Outbound
                    : FirewallDirection.Inbound,
                RemoteAddresses = remoteNorm,
                LocalPorts = portsNorm,
                Protocol = protoNorm,
                Kind = ClassifyRuleKind(currentName, remoteNorm, portsNorm),
                Description = profiles,
                ExpiresUtc = ExpiryLedger.Get(currentName)
            });
        }

        foreach (var raw in result.Message.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                currentName = line["Rule Name:".Length..].Trim();
                enabled = direction = remoteIp = localPort = protocol = action = profiles = "";
            }
            else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                enabled = line["Enabled:".Length..].Trim();
            else if (line.StartsWith("Direction:", StringComparison.OrdinalIgnoreCase))
                direction = line["Direction:".Length..].Trim();
            else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
                remoteIp = line["RemoteIP:".Length..].Trim();
            else if (line.StartsWith("LocalPort:", StringComparison.OrdinalIgnoreCase))
                localPort = line["LocalPort:".Length..].Trim();
            else if (line.StartsWith("Protocol:", StringComparison.OrdinalIgnoreCase))
                protocol = line["Protocol:".Length..].Trim();
            else if (line.StartsWith("Action:", StringComparison.OrdinalIgnoreCase))
                action = line["Action:".Length..].Trim();
        }

        Flush();
        return list;
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

    private static FirewallOperationResult RunNetsh(string args)
    {
        try
        {
            // Use full path + separate process. Never load firewall COM into this process
            // for delete/list when called from the web UI.
            var netshExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "netsh.exe");
            if (!File.Exists(netshExe))
                netshExe = "netsh";

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

    private void TrySweepExpired()
    {
        try
        {
            var expired = ExpiryLedger.ExpiredNames();
            if (expired.Count == 0) return;
            if (!IsAdministrator) return;

            foreach (var name in expired)
            {
                RemoveRuleByName(name);
                ExpiryLedger.Remove(name);
            }
            InvalidateRuleCache();
        }
        catch
        {
            // sweep is best-effort; it simply retries next minute
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
        _ when Name.Contains("-Web-", StringComparison.OrdinalIgnoreCase) => "Web UI",
        _ => IsBlock ? "Block rule" : "Allow rule"
    };
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
