using System.Net;
using System.Runtime.InteropServices;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Data-exfiltration heuristic. Samples per-connection byte counters with TCP
/// ESTATS (the kernel's extended statistics, which the ordinary TCP table does
/// not carry) and alerts when the outbound volume to a single public host
/// exceeds a threshold within a rolling 10-minute window. Cloud sync and
/// streaming stay quiet via the allowlist hook and by skipping private/LAN
/// destinations (NAS backups, local file shares).
///
/// ESTATS reports cumulative bytes per connection, so each sample is diffed
/// against the previous one; the first sighting of a connection is baseline
/// only (its history predates monitoring and must not count).
///
/// Turning ESTATS collection on for a connection requires administrator
/// rights. The GUI runs asInvoker, so an unelevated desktop session reports
/// that in <see cref="Status"/> and collects nothing; the headless web service
/// runs as SYSTEM and gets full coverage. This is the one place the Linux
/// build is less restricted — /proc exposes its byte counters to any user.
///
/// TCP only — UDP carries no equivalent counter, so QUIC/HTTP3 uploads are
/// invisible here and are covered by the connection-rate heuristics instead.
/// </summary>
public sealed class ExfiltrationMonitor : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;
    private const uint ErrorAccessDenied = 5;
    private const int TcpStateEstablished = 5;

    /// <summary>TCP_ESTATS_TYPE.TcpConnectionEstatsData.</summary>
    private const int TcpConnectionEstatsData = 0;

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _lastSeenBytes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<(DateTime Time, long Bytes)>> _perIpWindow = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _perIpProcess = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _enabled = new(StringComparer.Ordinal);
    private readonly ProcessResolver _processes = new();

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _accessDenied;
    private volatile string _status = "Exfiltration monitor not started";

    /// <summary>Megabytes of outbound traffic to one host in the window before alerting.</summary>
    public int ThresholdMb { get; set; } = 250;

    /// <summary>Optional allowlist hook — allowlisted destinations never alert.</summary>
    public Func<string, bool>? IsIpAllowlisted { get; set; }

    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            _accessDenied = false;
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Sampling per-connection byte counts (TCP ESTATS)";
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
        try { _loop?.Wait(1500); } catch { /* ignore */ }
        cts.Dispose();
        _loop = null;
        _status = "Exfiltration monitor stopped";
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
                SampleOnce(DateTime.Now);
            }
            catch (Exception ex)
            {
                _status = $"Exfiltration monitor error: {ex.Message}";
            }

            try { await Task.Delay(SampleInterval, ct); }
            catch (TaskCanceledException) { break; }
        }
    }

    private void SampleOnce(DateTime now)
    {
        var liveKeys = new HashSet<string>(StringComparer.Ordinal);

        lock (_gate)
        {
            SampleV4(now, liveKeys);
            SampleV6(now, liveKeys);

            if (_accessDenied)
            {
                _status = "TCP ESTATS needs administrator rights — exfiltration monitoring off " +
                          "(the headless web service runs as SYSTEM and does collect)";
                return;
            }

            // Forget connections that no longer exist so keys don't grow forever.
            foreach (var gone in _lastSeenBytes.Keys.Where(k => !liveKeys.Contains(k)).ToList())
                _lastSeenBytes.Remove(gone);
            _enabled.RemoveWhere(k => !liveKeys.Contains(k));

            var thresholdBytes = (long)ThresholdMb * 1_000_000;
            foreach (var (ip, window) in _perIpWindow.ToList())
            {
                while (window.Count > 0 && now - window.Peek().Time > Window)
                    window.Dequeue();
                if (window.Count == 0)
                {
                    _perIpWindow.Remove(ip);
                    _perIpProcess.Remove(ip);
                    continue;
                }

                long total = window.Sum(x => x.Bytes);
                if (total < thresholdBytes) continue;
                if (IsIpAllowlisted?.Invoke(ip) == true) continue;
                if (_lastEmit.TryGetValue(ip, out var last) && now - last < EmitCooldown) continue;
                _lastEmit[ip] = now;

                var process = _perIpProcess.TryGetValue(ip, out var p) && p.Length > 0 ? p : "unknown process";
                _pending.Add(new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.DataExfiltration,
                    Level = ThreatLevel.High,
                    SourceIp = ip,
                    Title = $"Large outbound transfer: {total / 1_000_000} MB in {Window.TotalMinutes:0} min",
                    Detail = $"This machine sent {total / 1_000_000} MB to {ip} within the last {Window.TotalMinutes:0} minutes " +
                             $"(process: {process}). Large sustained uploads to a host outside the allowlist can indicate data " +
                             "exfiltration — or a legitimate backup/sync you may want to allowlist.",
                    Origin = "Origin resolving…",
                    Method = "TCP ESTATS per-connection byte counters"
                });
            }

            _status = $"Sampling TCP ESTATS · tracking {_perIpWindow.Count} active remote hosts · " +
                      $"threshold {ThresholdMb} MB / {Window.TotalMinutes:0} min";
        }
    }

    /// <summary>Caller holds the lock.</summary>
    private void SampleV4(DateTime now, HashSet<string> liveKeys)
    {
        foreach (var row in ReadTable<MibTcpRowOwnerPid>(AfInet))
        {
            if (row.State != TcpStateEstablished) continue;

            var remote = new IPAddress(row.RemoteAddr).ToString();
            if (!IsInterestingPeer(remote)) continue;

            var estatsRow = new MibTcpRow
            {
                State = row.State,
                LocalAddr = row.LocalAddr,
                LocalPort = row.LocalPort,
                RemoteAddr = row.RemoteAddr,
                RemotePort = row.RemotePort
            };

            var key = $"4|{row.LocalAddr}:{row.LocalPort}|{row.RemoteAddr}:{row.RemotePort}";
            if (!EnsureEnabledV4(key, ref estatsRow)) continue;
            if (!TryReadBytesOutV4(ref estatsRow, out var bytesOut)) continue;

            liveKeys.Add(key);
            RecordDelta(key, remote, _processes.Resolve((int)row.OwningPid), bytesOut, now);
        }
    }

    /// <summary>Caller holds the lock.</summary>
    private void SampleV6(DateTime now, HashSet<string> liveKeys)
    {
        foreach (var row in ReadTable<MibTcp6RowOwnerPid>(AfInet6))
        {
            if (row.State != TcpStateEstablished) continue;

            var remote = new IPAddress(row.RemoteAddr).ToString();
            if (!IsInterestingPeer(remote)) continue;

            var estatsRow = new MibTcp6Row
            {
                State = row.State,
                LocalAddr = row.LocalAddr,
                LocalScopeId = row.LocalScopeId,
                LocalPort = row.LocalPort,
                RemoteAddr = row.RemoteAddr,
                RemoteScopeId = row.RemoteScopeId,
                RemotePort = row.RemotePort
            };

            var key = $"6|{remote}:{row.RemotePort}|{row.LocalPort}";
            if (!EnsureEnabledV6(key, ref estatsRow)) continue;
            if (!TryReadBytesOutV6(ref estatsRow, out var bytesOut)) continue;

            liveKeys.Add(key);
            RecordDelta(key, remote, _processes.Resolve((int)row.OwningPid), bytesOut, now);
        }
    }

    private static bool IsInterestingPeer(string remote)
    {
        if (remote is "0.0.0.0" or "::" or "") return false;
        if (GeoIpService.IsNonPublic(remote)) return false;
        return !GeoIpService.IsMulticastOrBroadcast(remote);
    }

    /// <summary>
    /// Diff this sample against the previous one for the same connection.
    /// Caller holds the lock.
    /// </summary>
    private void RecordDelta(string key, string ip, string process, long bytesOut, DateTime now)
    {
        long delta;
        if (_lastSeenBytes.TryGetValue(key, out var previous))
        {
            // Counter went backwards → same endpoint pair, new connection.
            delta = bytesOut >= previous ? bytesOut - previous : bytesOut;
        }
        else
        {
            // First sighting: history predates monitoring — baseline only.
            delta = 0;
        }
        _lastSeenBytes[key] = bytesOut;

        if (delta <= 0) return;

        if (!_perIpWindow.TryGetValue(ip, out var window))
        {
            window = new Queue<(DateTime, long)>();
            _perIpWindow[ip] = window;
        }
        window.Enqueue((now, delta));
        if (process.Length > 0)
            _perIpProcess[ip] = process;
    }

    // ── ESTATS ───────────────────────────────────────────────────────────

    /// <summary>
    /// Turns on data collection for a connection the first time it is seen.
    /// Counters start from the moment collection is enabled, which lines up
    /// with the baseline-only first sample in <see cref="RecordDelta"/>.
    /// </summary>
    private bool EnsureEnabledV4(string key, ref MibTcpRow row)
    {
        if (_enabled.Contains(key)) return true;
        if (_accessDenied) return false;

        var rw = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(rw, 1); // TCP_ESTATS_DATA_RW_v0.EnableCollection
            var result = SetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData, rw, 0, 1, 0);
            if (result == ErrorAccessDenied) { _accessDenied = true; return false; }
            if (result != NoError) return false;
            _enabled.Add(key);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rw);
        }
    }

    private bool EnsureEnabledV6(string key, ref MibTcp6Row row)
    {
        if (_enabled.Contains(key)) return true;
        if (_accessDenied) return false;

        var rw = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(rw, 1);
            var result = SetPerTcp6ConnectionEStats(ref row, TcpConnectionEstatsData, rw, 0, 1, 0);
            if (result == ErrorAccessDenied) { _accessDenied = true; return false; }
            if (result != NoError) return false;
            _enabled.Add(key);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rw);
        }
    }

    private static bool TryReadBytesOutV4(ref MibTcpRow row, out long bytes)
    {
        bytes = 0;
        int size = Marshal.SizeOf<TcpEstatsDataRod>();
        var rod = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetPerTcpConnectionEStats(ref row, TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                rod, 0, (uint)size);
            if (result != NoError) return false;
            bytes = (long)Marshal.PtrToStructure<TcpEstatsDataRod>(rod).DataBytesOut;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rod);
        }
    }

    private static bool TryReadBytesOutV6(ref MibTcp6Row row, out long bytes)
    {
        bytes = 0;
        int size = Marshal.SizeOf<TcpEstatsDataRod>();
        var rod = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetPerTcp6ConnectionEStats(ref row, TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                rod, 0, (uint)size);
            if (result != NoError) return false;
            bytes = (long)Marshal.PtrToStructure<TcpEstatsDataRod>(rod).DataBytesOut;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rod);
        }
    }

    // ── TCP table ────────────────────────────────────────────────────────

    private static List<TRow> ReadTable<TRow>(int addressFamily) where TRow : struct
    {
        var result = new List<TRow>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, addressFamily, 5, 0);

        for (int attempt = 0; attempt < 3 && size > 0; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var ret = GetExtendedTcpTable(buffer, ref size, true, addressFamily, 5, 0);
                if (ret == ErrorInsufficientBuffer) continue;
                if (ret != NoError) return result;

                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<TRow>();

                for (int i = 0; i < count; i++)
                {
                    result.Add(Marshal.PtrToStructure<TRow>(rowPtr));
                    rowPtr += rowSize;
                }

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return result;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int ipVersion, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(ref MibTcpRow row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcp6ConnectionEStats(ref MibTcp6Row row, int estatsType, IntPtr rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(
        ref MibTcpRow row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcp6ConnectionEStats(
        ref MibTcp6Row row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    /// <summary>MIB_TCPROW — the ESTATS calls take this, not the owner-PID row.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    /// <summary>MIB_TCP6ROW — note the state comes first here, unlike the owner-PID row.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6Row
    {
        public uint State;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
    }

    /// <summary>
    /// TCP_ESTATS_DATA_ROD_v0. Only DataBytesOut is used, but the whole struct
    /// has to be declared so the size handed to the API matches what it expects
    /// for version 0.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRod
    {
        public ulong DataBytesOut;
        public ulong DataSegsOut;
        public ulong DataBytesIn;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    public void Dispose() => Stop();
}
