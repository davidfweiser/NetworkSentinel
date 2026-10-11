using System.IO;
using System.Net;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the Windows Firewall dropped-packet log (pfirewall.log) and turns
/// SYNs aimed at ports this machine does not accept into port-scan threat
/// events.
///
/// This is the piece connection polling fundamentally cannot provide: a probe
/// the firewall drops never reaches the TCP stack, so it never appears in the
/// connection table and a classic nmap sweep is invisible to the snapshot
/// heuristics. With dropped-packet logging on (see
/// <see cref="FirewallService.EnableProbeLogging"/>) every probe leaves a log
/// line and full scans are detected within seconds.
///
/// Only pure SYNs are counted: stray ACK/RST/FIN packets arriving after a
/// session closes are logged as drops too, and counting them would alert on
/// ordinary teardown races. The log holds dropped packets only, so nothing here
/// can double-report a connection the heuristics already saw.
///
/// The Linux build gets the same signal from an nftables/iptables SYN-log rule
/// plus the kernel log; thresholds and threat events are deliberately identical.
/// </summary>
public sealed class ProbeLogMonitor : IDisposable
{
    private static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Default field order of the W3C-style firewall log (Version 1.5). The
    /// header is parsed when present; this is the fallback for a log whose
    /// "#Fields:" line has already scrolled out of the window we read.
    /// </summary>
    private static readonly string[] DefaultFields =
    {
        "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port",
        "size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path"
    };

    private readonly object _gate = new();
    private readonly Dictionary<string, SourceActivity> _sources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();
    private HashSet<int> _listeningPorts = new();
    private Dictionary<string, int> _fieldIndex = BuildFieldIndex(DefaultFields);

    private CancellationTokenSource? _cts;
    private Task? _tailTask;
    private volatile string _status = "Probe log monitoring not started";

    /// <summary>Human-readable state of the firewall log source.</summary>
    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
        }

        var ct = _cts!.Token;
        _tailTask = Task.Run(() => TailFirewallLogAsync(ct), ct);
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
        try { _tailTask?.Wait(2000); } catch { /* ignore */ }
        _tailTask = null;
        cts.Dispose();
        _status = "Probe log monitoring stopped";
    }

    /// <summary>Called each poll so probes can be labelled open vs. closed against live listeners.</summary>
    public void SetListeningPorts(IReadOnlySet<int> ports)
    {
        lock (_gate)
        {
            _listeningPorts = new HashSet<int>(ports);
        }
    }

    /// <summary>Returns threats detected since the last drain (called from the monitor poll loop).</summary>
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

    /// <summary>
    /// Re-reads the log from the previous offset on a timer, opening and closing
    /// the file each pass. A long-lived handle would fight the firewall service
    /// when it rotates pfirewall.log at MaxFileSize.
    /// </summary>
    private async Task TailFirewallLogAsync(CancellationToken ct)
    {
        var path = FirewallService.ResolveProbeLogPath();
        long position = -1;
        var partial = "";
        var announcedMissing = false;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!File.Exists(path))
                {
                    if (!announcedMissing)
                    {
                        _status = $"Firewall log not created yet ({path}) — turn on dropped-packet logging in Settings";
                        announcedMissing = true;
                    }
                    position = -1;
                    partial = "";
                    await Task.Delay(PollInterval, ct);
                    continue;
                }

                announcedMissing = false;
                await using var stream = new FileStream(
                    path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

                // First pass starts at the end: existing history is not live activity.
                // A file shorter than last time means the log rotated — restart at 0.
                if (position < 0)
                {
                    position = stream.Length;
                }
                else if (position > stream.Length)
                {
                    position = 0;
                    partial = "";
                }

                // Byte-exact accounting: read only the bytes appended since last
                // pass and carry any unterminated tail line into the next one, so
                // a line split across two passes is neither lost nor counted twice.
                var pending = stream.Length - position;
                if (pending > 0)
                {
                    stream.Seek(position, SeekOrigin.Begin);
                    var buffer = new byte[pending];
                    var read = 0;
                    while (read < buffer.Length)
                    {
                        var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
                        if (n == 0) break;
                        read += n;
                    }
                    position += read;

                    var text = partial + System.Text.Encoding.ASCII.GetString(buffer, 0, read);
                    var lines = text.Split('\n');
                    partial = lines[^1];
                    for (var i = 0; i < lines.Length - 1; i++)
                        ProcessLine(lines[i].TrimEnd('\r'), DateTime.Now);
                }

                _status = $"Watching {path}";
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (UnauthorizedAccessException)
            {
                _status = "Firewall log not readable by this account — closed-port scan detection off (run as Administrator)";
                break;
            }
            catch (Exception ex)
            {
                _status = $"Firewall log monitoring failed: {ex.Message}";
            }

            try { await Task.Delay(PollInterval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Parses one firewall-log line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        if (line.Length == 0) return;

        if (line[0] == '#')
        {
            // "#Fields: date time action protocol src-ip dst-ip …"
            const string marker = "#Fields:";
            if (line.StartsWith(marker, StringComparison.OrdinalIgnoreCase))
            {
                var names = line[marker.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (names.Length > 0)
                    _fieldIndex = BuildFieldIndex(names);
            }
            return;
        }

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var map = _fieldIndex;

        string Field(string name) =>
            map.TryGetValue(name, out var i) && i < parts.Length ? parts[i] : "";

        if (!Field("action").Equals("DROP", StringComparison.OrdinalIgnoreCase)) return;
        if (!Field("protocol").Equals("TCP", StringComparison.OrdinalIgnoreCase)) return;

        // Inbound only ("path" is RECEIVE / SEND; older logs omit it).
        var direction = Field("path");
        if (direction.Length > 0 && !direction.Equals("RECEIVE", StringComparison.OrdinalIgnoreCase)) return;

        // Pure SYN — a connection attempt, not a late packet from a closed session.
        var flags = Field("tcpflags");
        if (!flags.Contains('S', StringComparison.OrdinalIgnoreCase) ||
            flags.Contains('A', StringComparison.OrdinalIgnoreCase)) return;

        var src = Field("src-ip");
        if (!IPAddress.TryParse(src, out var parsedSrc)) return;
        if (IPAddress.IsLoopback(parsedSrc)) return;
        if (!int.TryParse(Field("dst-port"), out var port)) return;

        lock (_gate)
        {
            if (!_sources.TryGetValue(src, out var activity))
            {
                activity = new SourceActivity();
                _sources[src] = activity;
            }

            activity.Probes.Enqueue((now, port));
            while (activity.Probes.Count > 0 && now - activity.Probes.Peek().Time > LongWindow)
                activity.Probes.Dequeue();

            Evaluate(src, activity, now);

            if (_sources.Count > 2000)
            {
                foreach (var stale in _sources
                             .Where(kv => kv.Value.Probes.Count == 0 ||
                                          now - kv.Value.Probes.Last().Time > LongWindow)
                             .Select(kv => kv.Key).ToList())
                {
                    _sources.Remove(stale);
                }
            }
        }
    }

    private void Evaluate(string src, SourceActivity activity, DateTime now)
    {
        var fastPorts = activity.Probes
            .Where(p => now - p.Time <= FastWindow)
            .Select(p => p.Port).Distinct().Count();
        var longPorts = activity.Probes.Select(p => p.Port).Distinct().Count();

        ThreatLevel? level = null;
        string title, method;
        if (fastPorts >= 8)
        {
            level = ThreatLevel.High;
            title = $"Port scan of closed ports ({fastPorts} ports in {FastWindow.TotalSeconds:0}s)";
            method = "SYNs dropped by Windows Firewall (firewall log)";
        }
        else if (fastPorts >= 4)
        {
            level = ThreatLevel.Medium;
            title = $"Probing of closed ports ({fastPorts} ports in {FastWindow.TotalSeconds:0}s)";
            method = "SYNs dropped by Windows Firewall (firewall log)";
        }
        else if (longPorts >= 16)
        {
            level = ThreatLevel.High;
            title = $"Slow scan of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs dropped by Windows Firewall (firewall log)";
        }
        else if (longPorts >= 10)
        {
            level = ThreatLevel.Medium;
            title = $"Slow probing of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs dropped by Windows Firewall (firewall log)";
        }
        else
        {
            return;
        }

        string emitKey = $"{src}|{level}";
        if (_lastEmit.TryGetValue(emitKey, out var last) && now - last < EmitCooldown)
            return;
        _lastEmit[emitKey] = now;
        if (_lastEmit.Count > 4000)
        {
            foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                         .Select(kv => kv.Key).ToList())
            {
                _lastEmit.Remove(stale);
            }
        }

        var probedPorts = activity.Probes.Select(p => p.Port).Distinct().OrderBy(p => p).ToList();
        var samplePorts = string.Join(", ", probedPorts.Take(12));
        var closedCount = probedPorts.Count(p => !_listeningPorts.Contains(p));
        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.PortScan,
            Level = level.Value,
            SourceIp = src,
            Title = title,
            Detail = $"{src} sent TCP SYNs that Windows Firewall dropped (e.g. {samplePorts}); " +
                     $"{closedCount} of {probedPorts.Count} probed ports are not open on this machine. " +
                     "These probes never show up as connections — they were caught by the firewall log.",
            Origin = "Origin resolving…",
            Method = method,
            // A SYN the firewall dropped goes no further, so nothing here proves the
            // logged source sent it: blocking on it would hand anyone who can forge a
            // source address the power to cut this host off from that address.
            AutoBlockHoldReason = "SYNs the firewall dropped never complete a handshake, so the source address may be forged"
        });
    }

    private static Dictionary<string, int> BuildFieldIndex(IReadOnlyList<string> names)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < names.Count; i++)
            map[names[i]] = i;
        return map;
    }

    public void Dispose() => Stop();

    private sealed class SourceActivity
    {
        public Queue<(DateTime Time, int Port)> Probes { get; } = new();
    }
}
