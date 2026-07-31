using System.Globalization;
using System.Net;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the ARP table for the standard LAN man-in-the-middle opener:
/// the default gateway's MAC address changing (ARP spoofing redirects the
/// gateway IP to the attacker's MAC), or another IP claiming the gateway's
/// MAC. Nothing connection-based can see this, so it gets its own poller.
///
/// Sources: /proc/net/route for the gateway IP, /proc/net/arp for the
/// neighbour table. Both are world-readable, so nothing here needs root and
/// no external command is spawned.
/// </summary>
public sealed class ArpWatchService : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    private const string RouteTablePath = "/proc/net/route";
    private const string ArpTablePath = "/proc/net/arp";

    /// <summary>RTF_UP | RTF_GATEWAY in the /proc/net/route flags column.</summary>
    private const int RtfUp = 0x0001;
    private const int RtfGateway = 0x0002;

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private string _gatewayIp = "";
    private string _gatewayMac = "";
    private volatile string _status = "ARP watch not started";

    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Watching ARP table / default gateway";
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }
        if (cts == null) return;
        cts.Cancel();
        try { _loop?.Wait(1000); } catch { /* ignore */ }
        cts.Dispose();
        _loop = null;
        _status = "ARP watch stopped";
    }

    public IReadOnlyList<ThreatEvent> DrainPending()
    {
        lock (_gate)
        {
            if (_pending.Count == 0) return Array.Empty<ThreatEvent>();
            var list = _pending.ToList();
            _pending.Clear();
            return list;
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                CheckOnce(DateTime.Now);
            }
            catch
            {
                // /proc read hiccup — try again next round
            }

            try { await Task.Delay(PollInterval, ct); }
            catch (TaskCanceledException) { break; }
        }
    }

    /// <summary>One ARP-table inspection; internal for tests / manual replay.</summary>
    internal void CheckOnce(DateTime now)
    {
        var gateway = ReadGatewayIp();
        if (string.IsNullOrEmpty(gateway))
        {
            _status = "ARP watch: no default gateway (offline?)";
            return;
        }

        var table = ReadArpTable();
        if (table.Count == 0) return;

        if (!table.TryGetValue(gateway, out var mac))
            return; // gateway not resolved yet

        lock (_gate)
        {
            if (_gatewayIp != gateway)
            {
                // New network (Wi-Fi change, VPN, DHCP move) — new baseline, not an attack.
                _gatewayIp = gateway;
                _gatewayMac = mac;
                _status = $"Watching gateway {gateway} ({mac})";
                return;
            }

            if (!string.Equals(_gatewayMac, mac, StringComparison.OrdinalIgnoreCase))
            {
                var old = _gatewayMac;
                _gatewayMac = mac;
                Emit(now, $"gwchange|{gateway}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.ArpSpoof,
                    Level = ThreatLevel.Critical,
                    SourceIp = gateway,
                    Title = "Gateway MAC address changed",
                    Detail = $"The default gateway {gateway} changed MAC address from {old} to {mac}. " +
                             "ARP spoofing redirects the gateway to an attacker's MAC to intercept your traffic. " +
                             "A replaced/rebooted router can also cause this — verify your network hardware.",
                    Origin = "Local network gateway",
                    Method = "ARP table watch (gateway MAC change)"
                });
            }

            // Another IP answering with the gateway's MAC. Routers legitimately
            // share a MAC across a couple of their own addresses, so this is High,
            // not Critical, and lists the twin.
            foreach (var (ip, otherMac) in table)
            {
                if (ip == gateway) continue;
                if (!string.Equals(otherMac, mac, StringComparison.OrdinalIgnoreCase)) continue;
                Emit(now, $"dup|{ip}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.ArpSpoof,
                    Level = ThreatLevel.High,
                    SourceIp = ip,
                    Title = "Duplicate gateway MAC on the LAN",
                    Detail = $"{ip} shares the gateway's MAC address ({mac}). Routers sometimes use one MAC for several of " +
                             "their own IPs, but this is also what a spoofed ARP table looks like mid-attack.",
                    Origin = "Local network",
                    Method = "ARP table watch (duplicate MAC)"
                });
            }
        }
    }

    private void Emit(DateTime now, string key, ThreatEvent threat)
    {
        if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
            return;
        _lastEmit[key] = now;
        _pending.Add(threat);
    }

    /// <summary>
    /// Default gateway from /proc/net/route. Columns are
    /// Iface Destination Gateway Flags RefCnt Use Metric Mask …, with the
    /// addresses as little-endian hex. The default route is the one whose
    /// destination is 0.0.0.0 and whose flags carry RTF_GATEWAY; the lowest
    /// metric wins when several interfaces offer one.
    /// </summary>
    internal static string ReadGatewayIp()
    {
        try
        {
            if (!File.Exists(RouteTablePath)) return "";

            string best = "";
            long bestMetric = long.MaxValue;

            foreach (var line in File.ReadLines(RouteTablePath).Skip(1))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 8) continue;
                if (parts[1] != "00000000") continue;

                // Flags are printed as hex without the 0x prefix ("0003").
                if (!int.TryParse(parts[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var flags))
                    continue;
                if ((flags & RtfGateway) == 0 || (flags & RtfUp) == 0) continue;

                var gateway = HexLeToIp(parts[2]);
                if (gateway.Length == 0 || gateway == "0.0.0.0") continue;

                if (!long.TryParse(parts[6], NumberStyles.Integer, CultureInfo.InvariantCulture, out var metric))
                    metric = 0;

                if (metric < bestMetric)
                {
                    bestMetric = metric;
                    best = gateway;
                }
            }

            return best;
        }
        catch
        {
            return "";
        }
    }

    /// <summary>
    /// Neighbour table from /proc/net/arp:
    /// "IP address  HW type  Flags  HW address  Mask  Device".
    /// Flags 0x0 means the entry is incomplete (no reply yet) and its MAC is
    /// all zeroes, so those rows are dropped.
    /// </summary>
    internal static Dictionary<string, string> ReadArpTable()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(ArpTablePath)) return result;

            foreach (var line in File.ReadLines(ArpTablePath).Skip(1))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;
                if (!IPAddress.TryParse(parts[0], out var ip)) continue;

                var flags = parts[2];
                if (flags.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                    int.TryParse(flags.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var flagBits) &&
                    flagBits == 0)
                    continue; // incomplete entry

                var mac = NormalizeMac(parts[3]);
                if (mac.Length == 0 || mac == "00:00:00:00:00:00") continue;

                result[ip.ToString()] = mac;
            }
        }
        catch
        {
            // /proc/net/arp unreadable — leave the table empty
        }

        return result;
    }

    /// <summary>
    /// Address word from /proc/net/route to dotted-quad. The kernel prints the
    /// in_addr as a host-order hex word, so 192.168.0.1 appears as 0100A8C0 —
    /// the octets are reversed. Read them back pairwise from the end rather
    /// than via BitConverter, which would depend on the CPU's endianness.
    /// </summary>
    private static string HexLeToIp(string hex)
    {
        if (hex.Length != 8) return "";

        var bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            var pair = hex.AsSpan(6 - i * 2, 2);
            if (!byte.TryParse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
                return "";
        }

        return new IPAddress(bytes).ToString();
    }

    /// <summary>Pad and lower-case MAC octets so string comparison is meaningful.</summary>
    internal static string NormalizeMac(string mac)
    {
        var parts = mac.Split(':');
        if (parts.Length != 6) return "";
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length is < 1 or > 2) return "";
            parts[i] = parts[i].PadLeft(2, '0').ToLowerInvariant();
        }
        return string.Join(':', parts);
    }

    public void Dispose() => Stop();
}
