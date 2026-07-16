using System.Collections.Concurrent;
using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

public sealed class NetworkMonitorService : IDisposable
{
    private readonly ProcessResolver _processes = new();
    private readonly GeoIpService _geo = new();
    private readonly IntrusionDetector _detector = new();
    private readonly object _sync = new();

    private readonly Dictionary<string, NetworkConnection> _connections = new();
    private readonly Dictionary<string, ListeningPort> _listeners = new();
    private readonly Dictionary<string, RemoteHost> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _threats = new();
    private readonly List<ActivitySample> _activity = new();
    private readonly ConcurrentDictionary<string, byte> _geoQueued = new();

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _firstPass = true;

    public event Action? Updated;
    /// <summary>Raised on the monitor thread with newly detected threats this poll cycle.</summary>
    public event Action<IReadOnlyList<ThreatEvent>>? ThreatsDetected;

    public DashboardStats Stats { get; } = new();
    public IReadOnlyList<NetworkConnection> Connections
    {
        get { lock (_sync) return _connections.Values.OrderByDescending(c => c.LastSeen).ToList(); }
    }
    public IReadOnlyList<ListeningPort> ListeningPorts
    {
        get { lock (_sync) return _listeners.Values.OrderBy(p => p.Port).ThenBy(p => p.Protocol).ToList(); }
    }
    public IReadOnlyList<RemoteHost> RemoteHosts
    {
        get { lock (_sync) return _hosts.Values.OrderByDescending(h => h.ThreatLevel).ThenByDescending(h => h.LastSeen).ToList(); }
    }
    public IReadOnlyList<ThreatEvent> Threats
    {
        get { lock (_sync) return _threats.OrderByDescending(t => t.Timestamp).ToList(); }
    }
    public IReadOnlyList<ActivitySample> Activity
    {
        get { lock (_sync) return _activity.ToList(); }
    }

    public void Start()
    {
        if (_loop != null) return;
        _cts = new CancellationTokenSource();
        Stats.IsMonitoring = true;
        Stats.StatusText = "Monitoring network stack…";
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _loop?.Wait(1000); } catch { /* ignore */ }
        _loop = null;
        Stats.IsMonitoring = false;
        Stats.StatusText = "Monitoring paused";
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                PollOnce();
            }
            catch (Exception ex)
            {
                Stats.StatusText = $"Monitor error: {ex.Message}";
            }

            try
            {
                await Task.Delay(1200, ct);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private void PollOnce()
    {
        var now = DateTime.Now;
        var tcp = IpHelper.GetTcpConnections();
        var udp = IpHelper.GetUdpListeners();

        var liveConnectionKeys = new HashSet<string>();
        var liveListenerKeys = new HashSet<string>();
        var activeByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var newThreats = new List<ThreatEvent>();

        lock (_sync)
        {
            // Listening ports (TCP LISTEN + UDP)
            foreach (var c in tcp.Where(x => x.State == TcpConnectionState.Listen))
            {
                var lp = new ListeningPort
                {
                    Protocol = "TCP",
                    Address = c.LocalAddress,
                    Port = c.LocalPort,
                    ProcessId = c.ProcessId,
                    ServiceHint = PortCatalog.GetHint(c.LocalPort, "TCP"),
                    ProcessName = _processes.Resolve(c.ProcessId)
                };
                liveListenerKeys.Add(lp.Key);
                _listeners[lp.Key] = lp;
            }

            foreach (var u in udp)
            {
                u.ProcessName = _processes.Resolve(u.ProcessId);
                liveListenerKeys.Add(u.Key);
                _listeners[u.Key] = u;
            }

            foreach (var key in _listeners.Keys.Where(k => !liveListenerKeys.Contains(k)).ToList())
                _listeners.Remove(key);

            // Active non-listen TCP
            foreach (var c in tcp.Where(x => x.State != TcpConnectionState.Listen))
            {
                c.ProcessName = _processes.Resolve(c.ProcessId);
                liveConnectionKeys.Add(c.Key);

                if (_connections.TryGetValue(c.Key, out var existing))
                {
                    existing.LastSeen = now;
                    existing.ProcessName = c.ProcessName;
                }
                else
                {
                    c.LastSeen = now;
                    _connections[c.Key] = c;
                }

                if (IsTrackableRemote(c.RemoteAddress))
                {
                    activeByIp.TryGetValue(c.RemoteAddress, out var n);
                    activeByIp[c.RemoteAddress] = n + 1;
                    UpsertHost(c, now);
                }
            }

            foreach (var key in _connections.Keys.Where(k => !liveConnectionKeys.Contains(k)).ToList())
                _connections.Remove(key);

            foreach (var host in _hosts.Values)
            {
                activeByIp.TryGetValue(host.IpAddress, out var n);
                host.ActiveConnections = n;
                host.PortsTouched = host.LocalPortsContacted.Count;
            }

            // Intrusion heuristics
            var activeConns = _connections.Values.ToList();
            newThreats.AddRange(_detector.Analyze(activeConns, _hosts, now));

            foreach (var t in newThreats)
            {
                _threats.Insert(0, t);
                if (_hosts.TryGetValue(t.SourceIp, out var h))
                {
                    if (t.Level > h.ThreatLevel) h.ThreatLevel = t.Level;
                    h.Status = t.TypeText;
                    h.Notes.Add($"{t.TimeText}: {t.Title}");
                }
            }

            if (_threats.Count > 500)
                _threats.RemoveRange(500, _threats.Count - 500);

            _activity.Add(new ActivitySample
            {
                Time = now,
                ConnectionCount = _connections.Count,
                ThreatCount = newThreats.Count,
                RemoteHostCount = _hosts.Count
            });
            while (_activity.Count > 60) _activity.RemoveAt(0);

            Stats.ListeningPorts = _listeners.Count;
            Stats.ActiveConnections = _connections.Count;
            Stats.RemoteHosts = _hosts.Count;
            Stats.ThreatsToday = _threats.Count(t => t.Timestamp.Date == now.Date);
            Stats.HighThreats = _threats.Count(t => t.Level >= ThreatLevel.High);
            Stats.StatusText = _firstPass
                ? "Baseline captured — watching for anomalies"
                : $"Live · {_connections.Count} sessions · {_hosts.Count} remotes · {_threats.Count} events";
            _firstPass = false;
        }

        // Geo lookups off the lock
        foreach (var ip in activeByIp.Keys)
            QueueGeo(ip);

        foreach (var t in newThreats)
            QueueGeo(t.SourceIp);

        if (newThreats.Count > 0)
            ThreatsDetected?.Invoke(newThreats);

        Updated?.Invoke();
    }

    private void UpsertHost(NetworkConnection c, DateTime now)
    {
        if (!_hosts.TryGetValue(c.RemoteAddress, out var host))
        {
            host = new RemoteHost
            {
                IpAddress = c.RemoteAddress,
                FirstSeen = now,
                LastSeen = now,
                Status = "New"
            };
            _hosts[c.RemoteAddress] = host;

            if (!_firstPass)
            {
                _threats.Insert(0, new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.NewRemoteHost,
                    Level = ThreatLevel.Info,
                    SourceIp = c.RemoteAddress,
                    Title = "New remote computer observed",
                    Detail = $"First contact from {c.RemoteAddress} → local {c.LocalAddress}:{c.LocalPort} ({c.State}).",
                    Origin = "Resolving…",
                    Method = "New session appearance"
                });
            }
        }

        host.LastSeen = now;
        host.TotalConnections++;
        host.LocalPortsContacted.Add(c.LocalPort);
        if (c.RemotePort > 0) host.RemotePortsUsed.Add(c.RemotePort);
        if (host.Status == "New" && (now - host.FirstSeen) > TimeSpan.FromSeconds(30))
            host.Status = "Active";
    }

    private void QueueGeo(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return;
        if (!_geoQueued.TryAdd(ip, 0)) return;

        _ = Task.Run(async () =>
        {
            try
            {
                var geo = await _geo.LookupAsync(ip);
                lock (_sync)
                {
                    if (_hosts.TryGetValue(ip, out var host))
                    {
                        host.HostName = geo.HostName;
                        host.Country = geo.Country;
                        host.City = geo.City;
                        host.Isp = geo.Isp;
                        host.GeoSummary = geo.Summary;
                    }

                    foreach (var c in _connections.Values.Where(x => x.RemoteAddress == ip))
                    {
                        c.RemoteHostName = geo.HostName;
                        c.GeoSummary = geo.Summary;
                    }

                    foreach (var t in _threats.Where(x => x.SourceIp == ip &&
                             (x.Origin is "Resolving…" or "Origin resolving…" or "")))
                    {
                        // ThreatEvent properties are init-only; rebuild origin via reflection-free path:
                        // we store origin at creation; update matching host is enough for UI host list.
                        // For threat list display we patch via a mutable approach — recreate not possible.
                    }
                }

                // Patch threat origins by replacing list entries
                lock (_sync)
                {
                    for (int i = 0; i < _threats.Count; i++)
                    {
                        var t = _threats[i];
                        if (t.SourceIp != ip) continue;
                        if (t.Origin is not ("Resolving…" or "Origin resolving…" or "")) continue;
                        _threats[i] = new ThreatEvent
                        {
                            Timestamp = t.Timestamp,
                            Type = t.Type,
                            Level = t.Level,
                            SourceIp = t.SourceIp,
                            Title = t.Title,
                            Detail = t.Detail,
                            Origin = geo.Summary,
                            Method = t.Method
                        };
                    }
                }

                Updated?.Invoke();
            }
            catch
            {
                // ignore lookup failures
            }
            finally
            {
                // allow refresh later if needed — keep cache in GeoIpService
                _geoQueued.TryRemove(ip, out _);
            }
        });
    }

    private static bool IsTrackableRemote(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        if (ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1") return false;
        return true;
    }

    public void ClearThreats()
    {
        lock (_sync) _threats.Clear();
        Stats.ThreatsToday = 0;
        Stats.HighThreats = 0;
        Updated?.Invoke();
    }

    public void Dispose()
    {
        Stop();
        _geo.Dispose();
    }
}
