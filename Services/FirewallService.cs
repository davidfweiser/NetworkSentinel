using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
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

    public string PrivilegeText => IsAdministrator
        ? "Running as Administrator — firewall rules can be applied."
        : "Not elevated — use “Run as Admin” to add or remove firewall rules.";

    public FirewallOperationResult BlockIp(string ip, FirewallDirection direction = FirewallDirection.Both, string? reason = null)
    {
        if (!TryNormalizeIp(ip, out var normalized, out var error))
            return FirewallOperationResult.Fail(error);

        if (IsPrivateOrLocal(normalized))
            return FirewallOperationResult.Fail("Refusing to block private/local addresses (LAN, loopback, link-local).");

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
        if (string.IsNullOrWhiteSpace(ruleName) || !ruleName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
            return FirewallOperationResult.Fail("Only Network Sentinel managed rules can be removed here.");

        if (!IsAdministrator)
            return FirewallOperationResult.Fail("Administrator rights are required to modify the Windows Firewall.");

        return RemoveRuleByName(ruleName);
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

    public IReadOnlyList<FirewallRuleInfo> GetManagedRules()
    {
        try
        {
            return GetManagedRulesCom();
        }
        catch
        {
            return GetManagedRulesNetsh();
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

    public void RestartAsAdministrator()
    {
        var exe = Environment.ProcessPath
                  ?? Process.GetCurrentProcess().MainModule?.FileName
                  ?? throw new InvalidOperationException("Could not resolve executable path.");

        var start = new ProcessStartInfo(exe)
        {
            UseShellExecute = true,
            Verb = "runas"
        };

        Process.Start(start);
    }

    private FirewallOperationResult EnsureIpRule(string ip, bool isInbound, string? reason)
    {
        var name = IpRuleName(ip, isInbound);
        RemoveRuleByName(name); // replace cleanly

        var dir = isInbound ? "in" : "out";
        var description = reason ?? $"Blocked by Network Sentinel at {DateTime.Now:u}";
        // Prefer COM; fall back to netsh
        try
        {
            AddIpRuleCom(name, ip, isInbound, description);
            return FirewallOperationResult.Ok($"Rule “{name}” applied.");
        }
        catch (Exception ex)
        {
            var netsh = RunNetsh(
                $"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block remoteip={ip} enable=yes profile=any description=\"{Escape(description)}\"");
            return netsh.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied via netsh.")
                : FirewallOperationResult.Fail($"Failed to add rule {name}: {ex.Message}; netsh: {netsh.Message}");
        }
    }

    private FirewallOperationResult EnsurePortRule(int port, string protocol, bool isInbound, string? reason)
    {
        var name = PortRuleName(port, protocol, isInbound);
        RemoveRuleByName(name);

        var dir = isInbound ? "in" : "out";
        var description = reason ?? $"Port blocked by Network Sentinel at {DateTime.Now:u}";
        try
        {
            AddPortRuleCom(name, port, protocol, isInbound, description);
            return FirewallOperationResult.Ok($"Rule “{name}” applied.");
        }
        catch (Exception ex)
        {
            var netsh = RunNetsh(
                $"advfirewall firewall add rule name=\"{name}\" dir={dir} action=block protocol={protocol} localport={port} enable=yes profile=any description=\"{Escape(description)}\"");
            return netsh.Success
                ? FirewallOperationResult.Ok($"Rule “{name}” applied via netsh.")
                : FirewallOperationResult.Fail($"Failed to add rule {name}: {ex.Message}; netsh: {netsh.Message}");
        }
    }

    private static void AddIpRuleCom(string name, string ip, bool isInbound, string description)
    {
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        dynamic rule = CreateCom("HNetCfg.FWRule");
        rule.Name = name;
        rule.Description = description;
        rule.Action = 0; // BLOCK
        rule.Direction = isInbound ? 1 : 2;
        rule.Enabled = true;
        rule.Profiles = 0x7FFFFFFF; // all
        rule.InterfaceTypes = "All";
        rule.RemoteAddresses = ip;
        rule.Protocol = 256; // ANY
        policy.Rules.Add(rule);
        Marshal.FinalReleaseComObject(rule);
        Marshal.FinalReleaseComObject(policy);
    }

    private static void AddPortRuleCom(string name, int port, string protocol, bool isInbound, string description)
    {
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        dynamic rule = CreateCom("HNetCfg.FWRule");
        rule.Name = name;
        rule.Description = description;
        rule.Action = 0;
        rule.Direction = isInbound ? 1 : 2;
        rule.Enabled = true;
        rule.Profiles = 0x7FFFFFFF;
        rule.InterfaceTypes = "All";
        rule.Protocol = protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? 17 : 6;
        rule.LocalPorts = port.ToString();
        policy.Rules.Add(rule);
        Marshal.FinalReleaseComObject(rule);
        Marshal.FinalReleaseComObject(policy);
    }

    private FirewallOperationResult RemoveRuleByName(string name)
    {
        try
        {
            dynamic policy = CreateCom("HNetCfg.FwPolicy2");
            policy.Rules.Remove(name);
            Marshal.FinalReleaseComObject(policy);
            return FirewallOperationResult.Ok($"Removed “{name}”.");
        }
        catch
        {
            var netsh = RunNetsh($"advfirewall firewall delete rule name=\"{name}\"");
            return netsh.Success
                ? FirewallOperationResult.Ok($"Removed “{name}”.")
                : FirewallOperationResult.Fail(netsh.Message);
        }
    }

    private static List<FirewallRuleInfo> GetManagedRulesCom()
    {
        var list = new List<FirewallRuleInfo>();
        dynamic policy = CreateCom("HNetCfg.FwPolicy2");
        try
        {
            foreach (dynamic rule in policy.Rules)
            {
                string name = rule.Name ?? "";
                if (!name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                int action = (int)rule.Action;
                int direction = (int)rule.Direction;
                bool enabled = rule.Enabled;
                string remote = rule.RemoteAddresses?.ToString() ?? "";
                string localPorts = rule.LocalPorts?.ToString() ?? "";
                string description = rule.Description?.ToString() ?? "";
                int protocol = 0;
                try { protocol = (int)rule.Protocol; } catch { /* any */ }

                list.Add(new FirewallRuleInfo
                {
                    Name = name,
                    Description = description,
                    Enabled = enabled,
                    IsBlock = action == 0,
                    Direction = direction == 1 ? FirewallDirection.Inbound : FirewallDirection.Outbound,
                    RemoteAddresses = NormalizeRemote(remote),
                    LocalPorts = localPorts is " *" or "*" ? "" : localPorts.Trim(),
                    Protocol = ProtocolName(protocol),
                    Kind = name.Contains("-IP-", StringComparison.OrdinalIgnoreCase)
                        ? FirewallRuleKind.IpBlock
                        : FirewallRuleKind.PortBlock
                });
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }

        return list
            .OrderBy(r => r.Kind)
            .ThenBy(r => r.RemoteAddresses)
            .ThenBy(r => r.LocalPorts)
            .ThenBy(r => r.Direction)
            .ToList();
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
            if (string.IsNullOrWhiteSpace(currentName) ||
                !currentName.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                return;

            list.Add(new FirewallRuleInfo
            {
                Name = currentName,
                Enabled = enabled.Contains("Yes", StringComparison.OrdinalIgnoreCase),
                IsBlock = action.Contains("Block", StringComparison.OrdinalIgnoreCase),
                Direction = direction.Contains("Out", StringComparison.OrdinalIgnoreCase)
                    ? FirewallDirection.Outbound
                    : FirewallDirection.Inbound,
                RemoteAddresses = NormalizeRemote(remoteIp),
                LocalPorts = localPort,
                Protocol = string.IsNullOrWhiteSpace(protocol) ? "Any" : protocol,
                Kind = currentName.Contains("-IP-", StringComparison.OrdinalIgnoreCase)
                    ? FirewallRuleKind.IpBlock
                    : FirewallRuleKind.PortBlock,
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

    private static object CreateCom(string progId)
    {
        var type = Type.GetTypeFromProgID(progId)
                   ?? throw new InvalidOperationException($"COM type {progId} not available.");
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException($"Failed to create {progId}.");
    }

    private static FirewallOperationResult RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null)
                return FirewallOperationResult.Fail("Could not start netsh.");

            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
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

    private static string ProtocolName(int protocol) => protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        256 => "Any",
        0 => "Any",
        _ => protocol.ToString()
    };

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
        // strip port if user pasted ip:port
        if (ip.Contains(':') && IPAddress.TryParse(ip, out _) == false)
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
