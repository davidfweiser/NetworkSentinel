using System.Net;
using System.Runtime.InteropServices;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the ARP table for the standard LAN man-in-the-middle opener:
/// the default gateway's MAC address changing (ARP spoofing redirects the
/// gateway IP to the attacker's MAC), or another IP claiming the gateway's
/// MAC. Nothing connection-based can see this, so it gets its own poller.
///
/// Sources: GetIpForwardTable for the gateway IP and GetIpNetTable for the
/// neighbour table — the same IP Helper tables "route print" and "arp -a"
/// read. Both are readable by a standard user, so nothing here needs
/// elevation and no external command is spawned.
/// </summary>
public sealed class ArpWatchService : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    /// <summary>MIB_IPNET_TYPE_INVALID — an incomplete entry with no usable MAC.</summary>
    private const uint IpNetTypeInvalid = 2;

    private const int ErrorInsufficientBuffer = 122;
    private const int NoError = 0;

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpForwardTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order);

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order);

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
                // table read hiccup — try again next round
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
    /// Default gateway from GetIpForwardTable: the route whose destination is
    /// 0.0.0.0, lowest metric winning when several interfaces offer one (a
    /// docked laptop on Wi-Fi and Ethernet at once). MIB_IPFORWARDROW is
    /// twenty DWORDs; only destination, next hop and the first metric matter
    /// here.
    /// </summary>
    internal static string ReadGatewayIp()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int size = 0;
            if (GetIpForwardTable(IntPtr.Zero, ref size, true) != ErrorInsufficientBuffer || size <= 0)
                return "";

            buffer = Marshal.AllocHGlobal(size);
            if (GetIpForwardTable(buffer, ref size, true) != NoError)
                return "";

            int count = Marshal.ReadInt32(buffer);
            const int rowSize = 20 * 4;
            string best = "";
            long bestMetric = long.MaxValue;

            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(buffer, 4 + i * rowSize);
                uint dest = (uint)Marshal.ReadInt32(row, 0);
                if (dest != 0) continue;

                uint nextHop = (uint)Marshal.ReadInt32(row, 12);
                if (nextHop == 0) continue;

                long metric = (uint)Marshal.ReadInt32(row, 36);
                if (metric >= bestMetric) continue;

                bestMetric = metric;
                best = new IPAddress(nextHop).ToString();
            }

            return best;
        }
        catch
        {
            return "";
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Neighbour table from GetIpNetTable. MIB_IPNETROW is
    /// { DWORD ifIndex; DWORD physAddrLen; BYTE physAddr[8]; DWORD addr; DWORD type; }.
    /// Entries of type INVALID have no resolved MAC yet, and a zero-length or
    /// all-zero address is the same "no reply" case, so both are dropped.
    /// </summary>
    internal static Dictionary<string, string> ReadArpTable()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int size = 0;
            if (GetIpNetTable(IntPtr.Zero, ref size, true) != ErrorInsufficientBuffer || size <= 0)
                return result;

            buffer = Marshal.AllocHGlobal(size);
            if (GetIpNetTable(buffer, ref size, true) != NoError)
                return result;

            int count = Marshal.ReadInt32(buffer);
            const int rowSize = 24;

            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(buffer, 4 + i * rowSize);
                int physLen = Marshal.ReadInt32(row, 4);
                uint addr = (uint)Marshal.ReadInt32(row, 16);
                uint type = (uint)Marshal.ReadInt32(row, 20);

                if (type == IpNetTypeInvalid) continue;
                if (physLen != 6) continue; // not Ethernet — nothing comparable
                if (addr == 0) continue;

                var mac = new byte[6];
                Marshal.Copy(IntPtr.Add(row, 8), mac, 0, 6);
                var text = NormalizeMac(mac);
                if (text.Length == 0) continue;

                result[new IPAddress(addr).ToString()] = text;
            }
        }
        catch
        {
            // table unreadable — leave it empty
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    /// <summary>Lower-case colon-separated octets so string comparison is meaningful.</summary>
    internal static string NormalizeMac(byte[] mac)
    {
        if (mac.Length != 6) return "";
        if (mac.All(b => b == 0)) return "";
        return string.Join(':', mac.Select(b => b.ToString("x2")));
    }

    public void Dispose() => Stop();
}
