using System.Diagnostics;
using System.Globalization;
using System.Net;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Data-exfiltration heuristic. Samples per-socket byte counters with
/// <c>ss -tinp</c> (the kernel's tcp_info, which /proc/net/tcp does not carry)
/// and alerts when the outbound volume to a single public host exceeds a
/// threshold within a rolling 10-minute window. Cloud sync and streaming stay
/// quiet via the allowlist hook and by skipping private/LAN destinations
/// (NAS backups, local file shares).
///
/// tcp_info reports cumulative bytes per socket, so each sample is diffed
/// against the previous one; the first sighting of a socket is baseline only
/// (its history predates monitoring and must not count).
///
/// TCP only — UDP sockets carry no equivalent counter, so QUIC/HTTP3 uploads
/// are invisible here and are covered by the connection-rate heuristics instead.
/// </summary>
public sealed class ExfiltrationMonitor : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _lastSeenBytes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<(DateTime Time, long Bytes)>> _perIpWindow = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _perIpProcess = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loop;
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
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Sampling per-socket byte counts (ss)";
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
        var output = RunSs();
        if (output == null)
        {
            _status = "ss unavailable — exfiltration monitoring off";
            return;
        }

        // Two lines per socket:
        //   ESTAB 0 0 192.168.0.5:46196 34.107.243.93:443 users:(("firefox",pid=15403,fd=146))
        //   <tab> cubic wscale:8,10 … bytes_sent:5825 bytes_acked:5826 …
        string currentKey = "";
        string currentIp = "";
        string currentProcess = "";
        var liveKeys = new HashSet<string>(StringComparer.Ordinal);

        lock (_gate)
        {
            foreach (var raw in output.Split('\n'))
            {
                if (raw.Length == 0) continue;

                // Indented continuation line = the tcp_info for the socket above.
                if (char.IsWhiteSpace(raw[0]))
                {
                    if (currentKey.Length == 0) continue;
                    if (!TryReadCounter(raw, out var bytesOut)) continue;

                    liveKeys.Add(currentKey);
                    RecordDelta(currentKey, currentIp, currentProcess, bytesOut, now);
                    continue;
                }

                currentKey = currentIp = currentProcess = "";

                var cols = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (cols.Length < 5) continue;
                if (cols[0] is "State" or "Netid") continue;
                if (cols[0] != "ESTAB" && cols[0] != "CLOSE-WAIT" && cols[0] != "FIN-WAIT-1") continue;

                if (!TryParseHostPort(cols[4], out var remoteIp, out _)) continue;
                if (remoteIp is "0.0.0.0" or "::" or "") continue;
                if (GeoIpService.IsNonPublic(remoteIp)) continue;
                if (GeoIpService.IsMulticastOrBroadcast(remoteIp)) continue;

                currentKey = $"{cols[3]}<->{cols[4]}";
                currentIp = remoteIp;
                currentProcess = ParseProcessName(cols.Length > 5 ? cols[5] : "");
            }

            // Forget sockets that no longer exist so keys don't grow forever.
            foreach (var gone in _lastSeenBytes.Keys.Where(k => !liveKeys.Contains(k)).ToList())
                _lastSeenBytes.Remove(gone);

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
                    Method = "ss per-socket byte counters"
                });
            }

            _status = $"Sampling ss · tracking {_perIpWindow.Count} active remote hosts · threshold {ThresholdMb} MB / {Window.TotalMinutes:0} min";
        }
    }

    /// <summary>Diff this sample against the previous one for the same socket. Caller holds the lock.</summary>
    private void RecordDelta(string key, string ip, string process, long bytesOut, DateTime now)
    {
        long delta;
        if (_lastSeenBytes.TryGetValue(key, out var previous))
        {
            // Counter went backwards → same local/remote pair, new socket.
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

    /// <summary>
    /// Cumulative outbound bytes from a tcp_info line. bytes_sent is the total
    /// including retransmissions; bytes_acked is the fallback on older kernels
    /// that do not report bytes_sent.
    /// </summary>
    private static bool TryReadCounter(string line, out long bytes)
    {
        if (TryReadTaggedNumber(line, "bytes_sent:", out bytes)) return true;
        return TryReadTaggedNumber(line, "bytes_acked:", out bytes);
    }

    private static bool TryReadTaggedNumber(string line, string tag, out long value)
    {
        value = 0;
        int at = line.IndexOf(tag, StringComparison.Ordinal);
        if (at < 0) return false;

        int start = at + tag.Length;
        int end = start;
        while (end < line.Length && char.IsAsciiDigit(line[end])) end++;
        if (end == start) return false;

        return long.TryParse(line.AsSpan(start, end - start), NumberStyles.Integer,
            CultureInfo.InvariantCulture, out value);
    }

    /// <summary>ss endpoints: "1.2.3.4:443", "[2606::1]:443", "127.0.0.53%lo:53".</summary>
    internal static bool TryParseHostPort(string token, out string ip, out int port)
    {
        ip = "";
        port = 0;
        if (string.IsNullOrWhiteSpace(token)) return false;

        string host;
        string portText;
        if (token.StartsWith('['))
        {
            int close = token.IndexOf(']');
            if (close < 0 || close + 2 > token.Length || token[close + 1] != ':') return false;
            host = token[1..close];
            portText = token[(close + 2)..];
        }
        else
        {
            int colon = token.LastIndexOf(':');
            if (colon <= 0) return false;
            host = token[..colon];
            portText = token[(colon + 1)..];
        }

        // Drop any "%iface" scope suffix before parsing.
        int percent = host.IndexOf('%');
        if (percent >= 0) host = host[..percent];

        if (!IPAddress.TryParse(host, out var address)) return false;
        ip = address.ToString();
        return int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out port);
    }

    /// <summary>users:(("firefox-bin",pid=15403,fd=146)) → firefox-bin.</summary>
    private static string ParseProcessName(string token)
    {
        int open = token.IndexOf("((\"", StringComparison.Ordinal);
        if (open < 0) return "";
        int start = open + 3;
        int end = token.IndexOf('"', start);
        return end > start ? token[start..end] : "";
    }

    private static string? RunSs()
    {
        try
        {
            var psi = new ProcessStartInfo("ss")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            // -t TCP, -i tcp_info (byte counters), -n numeric, -p owning process
            // (only resolvable for our own processes unless running as root).
            foreach (var a in new[] { "-tinp" })
                psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(15_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return null;
            }
            return output.Length > 0 ? output : null;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => Stop();
}
