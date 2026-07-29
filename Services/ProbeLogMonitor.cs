using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the kernel log for the rate-limited "NS-PROBE" lines produced by
/// the firewall probe-log rule (see FirewallService.EnableProbeLogging) and
/// turns SYNs aimed at CLOSED ports into port-scan threat events.
///
/// This is the piece connection polling fundamentally cannot provide: a probe
/// to a closed port is answered with a RST by the kernel and never appears in
/// /proc/net, so a classic nmap sweep is invisible to the snapshot heuristics.
/// With the log rule installed, every probe leaves a kernel log line and full
/// scans are detected within seconds.
///
/// Source preference: `journalctl -k --follow`; falls back to tailing
/// /var/log/kern.log. Reading either may require membership in the
/// systemd-journal or adm group — the monitor degrades gracefully and reports
/// why in <see cref="Status"/>.
/// </summary>
public sealed class ProbeLogMonitor : IDisposable
{
    private static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);

    // "... NS-PROBE IN=eth0 OUT= MAC=... SRC=203.0.113.7 DST=192.168.1.5 ... PROTO=TCP SPT=54321 DPT=8080 ..."
    private static readonly Regex ProbeLine = new(
        @"NS-PROBE\s*.*?SRC=(?<src>[0-9a-fA-F.:]+)\s.*?PROTO=TCP\s.*?DPT=(?<dpt>\d+)",
        RegexOptions.Compiled);

    private readonly object _gate = new();
    private readonly Dictionary<string, SourceActivity> _sources = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();
    private HashSet<int> _listeningPorts = new();

    private Process? _journal;
    private CancellationTokenSource? _cts;
    private Task? _tailTask;
    private volatile string _status = "Probe log monitoring not started";

    /// <summary>Human-readable state of the kernel log source.</summary>
    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
        }

        if (!TryStartJournal())
        {
            var ct = _cts!.Token;
            _tailTask = Task.Run(() => TailKernLogAsync(ct));
        }
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
        try { _journal?.Kill(entireProcessTree: true); } catch { /* already gone */ }
        try { _tailTask?.Wait(1000); } catch { /* ignore */ }
        _journal?.Dispose();
        _journal = null;
        _tailTask = null;
        cts.Dispose();
        _status = "Probe log monitoring stopped";
    }

    /// <summary>Called each poll so probes can be classified open vs. closed against live listeners.</summary>
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

    private bool TryStartJournal()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "journalctl",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            foreach (var arg in new[]
            {
                "-k", "--follow", "--lines=0", "--output=cat", "--quiet", "-g", "NS-PROBE"
            })
            {
                psi.ArgumentList.Add(arg);
            }

            var proc = Process.Start(psi);
            if (proc == null) return false;

            _journal = proc;
            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) ProcessLine(e.Data, DateTime.Now);
            };
            proc.BeginOutputReadLine();
            _status = "Watching kernel log via journald (probe-log rule required — see Settings)";
            return true;
        }
        catch
        {
            _journal?.Dispose();
            _journal = null;
            return false;
        }
    }

    private async Task TailKernLogAsync(CancellationToken ct)
    {
        const string path = "/var/log/kern.log";
        try
        {
            if (!File.Exists(path))
            {
                _status = "Kernel log unavailable (no journalctl, no /var/log/kern.log) — closed-port scan detection off";
                return;
            }

            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.Seek(0, SeekOrigin.End);
            using var reader = new StreamReader(stream);
            _status = "Watching /var/log/kern.log (probe-log rule required — see Settings)";

            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct);
                if (line == null)
                {
                    if (stream.Position > new FileInfo(path).Length)
                        stream.Seek(0, SeekOrigin.Begin);
                    await Task.Delay(1000, ct);
                    continue;
                }
                if (line.Contains("NS-PROBE", StringComparison.Ordinal))
                    ProcessLine(line, DateTime.Now);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        catch (UnauthorizedAccessException)
        {
            _status = "Kernel log not readable by this user — closed-port scan detection off (add user to the 'adm' group)";
        }
        catch (Exception ex)
        {
            _status = $"Kernel log monitoring failed: {ex.Message}";
        }
    }

    /// <summary>Parses one kernel log line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        var m = ProbeLine.Match(line);
        if (!m.Success) return;

        var src = m.Groups["src"].Value;
        if (!IPAddress.TryParse(src, out _)) return;
        if (src is "127.0.0.1" or "::1") return;
        if (!int.TryParse(m.Groups["dpt"].Value, out var port)) return;

        lock (_gate)
        {
            // SYNs to LISTENING ports are already visible to the connection
            // heuristics; only closed-port probes are the new signal here.
            if (_listeningPorts.Contains(port)) return;

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
            method = "SYNs to non-listening ports (kernel log)";
        }
        else if (fastPorts >= 4)
        {
            level = ThreatLevel.Medium;
            title = $"Probing of closed ports ({fastPorts} ports in {FastWindow.TotalSeconds:0}s)";
            method = "SYNs to non-listening ports (kernel log)";
        }
        else if (longPorts >= 16)
        {
            level = ThreatLevel.High;
            title = $"Slow scan of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs to non-listening ports (kernel log)";
        }
        else if (longPorts >= 10)
        {
            level = ThreatLevel.Medium;
            title = $"Slow probing of closed ports ({longPorts} ports in {LongWindow.TotalMinutes:0} min)";
            method = "Paced SYNs to non-listening ports (kernel log)";
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

        var samplePorts = string.Join(", ", activity.Probes.Select(p => p.Port).Distinct().OrderBy(p => p).Take(12));
        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.PortScan,
            Level = level.Value,
            SourceIp = src,
            Title = title,
            Detail = $"{src} sent TCP SYNs to ports this machine is NOT listening on (e.g. {samplePorts}). " +
                     "These probes never show up as connections — they were caught by the firewall probe log.",
            Origin = "Origin resolving…",
            Method = method
        });
    }

    public void Dispose() => Stop();

    private sealed class SourceActivity
    {
        public Queue<(DateTime Time, int Port)> Probes { get; } = new();
    }
}
