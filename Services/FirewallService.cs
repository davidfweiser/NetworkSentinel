using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Text;
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

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (IsPrivateOrLocal(normalized))
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
            var r = EnsureIpRule(normalized, isInbound: true, reason);
            ok &= r.Success;
            results.Add(r.Message);
        }

        if (direction is FirewallDirection.Outbound or FirewallDirection.Both)
        {
            var r = EnsureIpRule(normalized, isInbound: false, reason);
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
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

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

            return RemoveRuleByName(ruleName.Trim());
        }
        catch (Exception ex)
        {
            // Never let firewall COM/netsh failures tear down the web host process.
            return FirewallOperationResult.Fail($"Remove failed: {ex.Message}");
        }
    }

    public FirewallOperationResult RemoveAllManagedRules()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        var rules = GetManagedRules();
        int removed = 0;
        foreach (var rule in rules)
        {
            if (RemoveRuleByName(rule.Name).Success)
                removed++;
        }

        return FirewallOperationResult.Ok($"Removed {removed} Network Sentinel firewall rule(s).");
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
        try
        {
            return GetManagedRulesNetsh();
        }
        catch
        {
            return Array.Empty<FirewallRuleInfo>();
        }
    }

    public bool IsIpBlocked(string ip)
    {
        if (!TryNormalizeIp(ip, out var normalized, out _))
            return false;

        var rules = GetManagedRules();
        return rules.Any(r =>
            r.Kind == FirewallRuleKind.IpBlock &&
            string.Equals(r.RemoteAddresses, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public HashSet<string> GetBlockedIps()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in GetManagedRules().Where(r => r.Kind == FirewallRuleKind.IpBlock))
        {
            if (!string.IsNullOrWhiteSpace(rule.RemoteAddresses))
                set.Add(rule.RemoteAddresses);
        }
        return set;
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

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason)
    {
        var name = IpRuleName(ip, isInbound);
        RemoveRuleByName(name); // replace cleanly

        var dir = isInbound ? "in" : "out";
        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";
        // netsh ONLY — HNetCfg COM from web/thread-pool (MTA) can AccessViolation and kill the process.
        var netsh = RunNetsh(
            $"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block remoteip={ip} enable=yes profile=any description=\"{Escape(description)}\"");
        return netsh.Success
            ? FirewallOperationResult.Ok($"Rule \"{name}\" applied.")
            : FirewallOperationResult.Fail($"Failed to add rule {name}: {netsh.Message}");
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
        var result = RunNetsh("advfirewall firewall show rule name=all verbose");
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
                Description = profiles
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

        normalized = address.ToString();
        return true;
    }

    public static bool IsPrivateOrLocal(string ip)
        => GeoIpService.IsNonPublic(ip);
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
