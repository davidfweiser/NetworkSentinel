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

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null, bool overrideAllowlist = false)
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
        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        return RemoveRuleByName(ruleName);
    }

    public FirewallOperationResult RemoveAllManagedRules()
    {
        if (!IsAdministrator)
            return FirewallOperationResult.Fail("No way to elevate (need pkexec or sudo) to modify the host firewall.");

        var rules = GetManagedRules().ToList();
        int removed = 0;
        foreach (var rule in rules)
        {
            if (RemoveRuleByName(rule.Name).Success)
                removed++;
        }

        if (BackendIsNft())
            RunPrivileged("nft", $"flush table {NftTable}");

        SaveLedger(new List<FirewallRuleInfo>());
        return FirewallOperationResult.Ok($"Removed {removed} Network Sentinel firewall rule(s).");
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

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason)
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
            var table = isInbound ? "INPUT" : "OUTPUT";
            var flag = isInbound ? "-s" : "-d";
            var r = RunPrivileged("iptables",
                $"-A {table} {flag} {ip} -j DROP -m comment --comment \"{Escape(name)}\"");
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
                RemoteAddresses = ip,
                LocalPorts = "",
                Protocol = "Any",
                Kind = FirewallRuleKind.IpBlock
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
            removed |= DeleteIptablesByComment("INPUT", name);
            removed |= DeleteIptablesByComment("OUTPUT", name);
        }

        // Ledger is always updated so UI stays consistent even if kernel rule was already gone.
        var hadLedger = LoadLedger().Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
        RemoveFromLedger(name);

        return removed || hadLedger
            ? FirewallOperationResult.Ok($"Removed “{name}”.")
            : FirewallOperationResult.Fail($"No rule named “{name}”.");
    }

    private bool DeleteIptablesByComment(string table, string name)
    {
        var list = RunPrivileged("iptables", $"-L {table} -n --line-numbers");
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
            if (RunPrivileged("iptables", $"-D {table} {num}").Success)
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

    private static FirewallOperationResult RunDirect(string file, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
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
            File.WriteAllText(LedgerPath, JsonSerializer.Serialize(rules, JsonOptions));
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

    public string DirectionText => Direction.ToString();
    public string KindText => Kind switch
    {
        FirewallRuleKind.IpBlock => "IP block",
        FirewallRuleKind.PortBlock => "Port block",
        _ => "Rule"
    };
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
