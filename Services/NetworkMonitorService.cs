using System.Collections.Concurrent;
using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

public sealed class NetworkMonitorService : IDisposable
{
    private readonly ProcessResolver _processes = new();
    private readonly GeoIpService _geo = new();
    private readonly IntrusionDetector _detector = new();
    private readonly AuthLogMonitor _authLog = new();
    private readonly ProbeLogMonitor _probeLog = new();
    private readonly ProcessReputationService _procRep = new();
    private readonly ThreatIntelService _intel = new();
    private readonly HoneypotService _honeypot = new();
    private readonly ArpWatchService _arpWatch = new();
    private readonly PersistenceWatcher _persistenceWatch = new();
    private readonly ExfiltrationMonitor _exfil = new();
    private readonly WebhookNotifier _webhook = new();
    private readonly HostHistoryStore _history = new();
    private readonly object _sync = new();

    private readonly Dictionary<string, NetworkConnection> _connections = new();
    private readonly Dictionary<string, ListeningPort> _listeners = new();
    private readonly Dictionary<string, RemoteHost> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _threats = new();
    private readonly List<ActivitySample> _activity = new();
    private readonly ConcurrentDictionary<string, byte> _geoQueued = new();
    private readonly HashSet<string> _intelChecked = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _hostThreatsThisPollList = new();

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _firstPass = true;

    /// <summary>
    /// First-seen-host threats raised by <see cref="UpsertHost"/> this poll. They are
    /// inserted and counted there rather than via the newThreats list, so the activity
    /// sample has to pick them up separately or the chart shows no threat markers at
    /// all on a quiet machine, where first contact is the only alert that ever fires.
    /// </summary>
    private int _hostThreatsThisPoll;
    private int _threatsTodayCount;
    private int _highThreatCount;
    private DateTime _threatsTodayDate = DateTime.Now.Date;

    public event Action? Updated;
    /// <summary>Raised on the monitor thread with newly detected threats this poll cycle.</summary>
    public event Action<IReadOnlyList<ThreatEvent>>? ThreatsDetected;

    public DashboardStats Stats { get; } = new();

    /// <summary>
    /// Seed the threat list and counters from the persisted log so a relaunch
    /// doesn't look like a clean slate.
    /// </summary>
    public NetworkMonitorService()
    {
        foreach (var t in _history.LoadRecentThreats(200))
        {
            _threats.Add(t);
            if (t.Timestamp.Date == DateTime.Now.Date)
            {
                _threatsTodayCount++;
                if (t.Level >= ThreatLevel.High) _highThreatCount++;
            }
        }

        Stats.ThreatsToday = _threatsTodayCount;
        Stats.HighThreats = _highThreatCount;
    }

    /// <summary>Enables/disables the external geo-IP web lookup (reverse DNS still runs).</summary>
    public bool GeoLookupsEnabled
    {
        get => _geo.LookupsEnabled;
        set => _geo.LookupsEnabled = value;
    }

    private int _pollIntervalMs = DefaultPollIntervalMs;

    public const int DefaultPollIntervalMs = 1200;

    /// <summary>
    /// Milliseconds between polls, clamped to 500–10000. This is also the activity
    /// sample rate, so a slower interval stretches the span the chart covers rather
    /// than showing the same window at lower resolution. Takes effect next cycle.
    /// </summary>
    public int PollIntervalMs
    {
        get => _pollIntervalMs;
        set => _pollIntervalMs = Math.Clamp(value, 500, 10_000);
    }

    private bool _authMonitoringEnabled = true;

    /// <summary>Enables/disables failed-logon detection from the Windows Security event log.</summary>
    public bool AuthMonitoringEnabled
    {
        get => _authMonitoringEnabled;
        set
        {
            if (_authMonitoringEnabled == value) return;
            _authMonitoringEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _authLog.Start();
                else _authLog.Stop();
            }
        }
    }

    /// <summary>State of the auth-log source (Security channel, or why it is unavailable).</summary>
    public string AuthLogStatus => _authLog.Status;

    private bool _probeMonitoringEnabled;

    /// <summary>
    /// Enables/disables closed-port scan detection from the Windows Firewall log.
    /// Dropped-packet logging must also be turned on (FirewallService) for events
    /// to actually appear.
    /// </summary>
    public bool ProbeMonitoringEnabled
    {
        get => _probeMonitoringEnabled;
        set
        {
            if (_probeMonitoringEnabled == value) return;
            _probeMonitoringEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _probeLog.Start();
                else _probeLog.Stop();
            }
        }
    }

    /// <summary>State of the firewall probe-log source.</summary>
    public string ProbeLogStatus => _probeLog.Status;

    /// <summary>Check remote IPs against FireHOL level1 / Spamhaus DROP.</summary>
    public bool ThreatIntelEnabled { get; set; } = true;

    /// <summary>Flag unsigned system binaries, deleted images, suspicious paths, and shells with outbound connections.</summary>
    public bool ProcessReputationEnabled { get; set; } = true;

    /// <summary>Alert when a new port starts listening after baseline or a known port changes owner.</summary>
    public bool NewListenerAlertsEnabled { get; set; } = true;

    public string ThreatIntelStatus => _intel.Status;
    public string HoneypotStatus => _honeypot.Status;
    public string ArpWatchStatus => _arpWatch.Status;
    public string PersistenceWatchStatus => _persistenceWatch.Status;
    public string ExfilStatus => _exfil.Status;
    public string WebhookStatus => _webhook.Status;

    private bool _arpWatchEnabled = true;

    /// <summary>Watch the ARP table for gateway MAC changes (MITM detection).</summary>
    public bool ArpWatchEnabled
    {
        get => _arpWatchEnabled;
        set
        {
            if (_arpWatchEnabled == value) return;
            _arpWatchEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _arpWatch.Start();
                else _arpWatch.Stop();
            }
        }
    }

    private bool _persistenceWatchEnabled = true;

    /// <summary>Watch Startup folders, scheduled tasks and registry Run keys for new or modified startup items.</summary>
    public bool PersistenceWatchEnabled
    {
        get => _persistenceWatchEnabled;
        set
        {
            if (_persistenceWatchEnabled == value) return;
            _persistenceWatchEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _persistenceWatch.Start();
                else _persistenceWatch.Stop();
            }
        }
    }

    private bool _exfilEnabled = true;

    /// <summary>Sample per-connection byte counters (TCP ESTATS) and alert on large sustained outbound transfers.</summary>
    public bool ExfilMonitorEnabled
    {
        get => _exfilEnabled;
        set
        {
            if (_exfilEnabled == value) return;
            _exfilEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _exfil.Start();
                else _exfil.Stop();
            }
        }
    }

    /// <summary>Outbound MB to one host within 10 minutes before the exfiltration alert fires.</summary>
    public int ExfilThresholdMb
    {
        get => _exfil.ThresholdMb;
        set => _exfil.ThresholdMb = Math.Clamp(value, 10, 100_000);
    }

    private bool _honeypotEnabled;
    private IReadOnlyList<int> _honeypotPorts = Array.Empty<int>();

    /// <summary>Bind decoy TCP ports; any completed connection is a Critical alert.</summary>
    public bool HoneypotEnabled
    {
        get => _honeypotEnabled;
        set
        {
            if (_honeypotEnabled == value) return;
            _honeypotEnabled = value;
            if (Stats.IsMonitoring)
            {
                if (value) _honeypot.Start(_honeypotPorts);
                else _honeypot.Stop();
            }
        }
    }

    /// <summary>Decoy ports to bind (applied on next honeypot start).</summary>
    public IReadOnlyList<int> HoneypotPorts
    {
        get => _honeypotPorts;
        set
        {
            _honeypotPorts = value;
            if (Stats.IsMonitoring && _honeypotEnabled)
                _honeypot.Start(_honeypotPorts);
        }
    }

    /// <summary>Webhook URL for pushed alerts (ntfy / Slack / Discord / generic JSON). Empty = off.</summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Minimum level for webhook delivery.</summary>
    public ThreatLevel WebhookMinLevel { get; set; } = ThreatLevel.Critical;

    /// <summary>Allowlist hook used by the exfiltration monitor (set by the front-end).</summary>
    public Func<string, bool>? IsIpAllowlisted
    {
        get => _exfil.IsIpAllowlisted;
        set => _exfil.IsIpAllowlisted = value;
    }

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
        if (_authMonitoringEnabled) _authLog.Start();
        if (_probeMonitoringEnabled) _probeLog.Start();
        if (_arpWatchEnabled) _arpWatch.Start();
        if (_persistenceWatchEnabled) _persistenceWatch.Start();
        if (_exfilEnabled) _exfil.Start();
        if (_honeypotEnabled) _honeypot.Start(_honeypotPorts);
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public void Stop()
    {
        var cts = _cts;
        var loop = _loop;
        cts?.Cancel();
        try { loop?.Wait(2000); } catch { /* ignore */ }
        cts?.Dispose();
        _cts = null;
        _loop = null;
        _authLog.Stop();
        _probeLog.Stop();
        _arpWatch.Stop();
        _persistenceWatch.Stop();
        _exfil.Stop();
        _honeypot.Stop();
        _history.Save();
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
                await Task.Delay(PollIntervalMs, ct);
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
        var (udpListeners, udpConnections) = IpHelper.GetUdpTable();

        var liveConnectionKeys = new HashSet<string>();
        var liveListenerKeys = new HashSet<string>();
        var activeByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var geoIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newThreats = new List<ThreatEvent>();
        var listeningTcpPorts = new HashSet<int>();
        var listeningUdpPorts = new HashSet<int>();

        lock (_sync)
        {
            _hostThreatsThisPoll = 0;
            _hostThreatsThisPollList.Clear();
            if (now.Date != _threatsTodayDate)
            {
                _threatsTodayDate = now.Date;
                _threatsTodayCount = 0;
            }

            // Listening ports (TCP LISTEN + UDP)
            foreach (var c in tcp.Where(x => x.State == TcpConnectionState.Listen))
            {
                listeningTcpPorts.Add(c.LocalPort);
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

            foreach (var u in udpListeners)
            {
                listeningUdpPorts.Add(u.Port);
                u.ProcessName = _processes.Resolve(u.ProcessId);
                liveListenerKeys.Add(u.Key);
                _listeners[u.Key] = u;
            }

            foreach (var key in _listeners.Keys.Where(k => !liveListenerKeys.Contains(k)).ToList())
                _listeners.Remove(key);

            if (NewListenerAlertsEnabled)
                DetectNewListeners(now, newThreats);

            // Active non-listen TCP plus connected UDP sockets with a real peer
            foreach (var polled in tcp.Where(x => x.State != TcpConnectionState.Listen).Concat(udpConnections))
            {
                polled.ProcessName = _processes.Resolve(polled.ProcessId);
                liveConnectionKeys.Add(polled.Key);

                NetworkConnection tracked;
                bool isNewConnection;
                if (_connections.TryGetValue(polled.Key, out var existing))
                {
                    existing.LastSeen = now;
                    existing.ProcessName = polled.ProcessName;
                    tracked = existing;
                    isNewConnection = false;
                }
                else
                {
                    polled.LastSeen = now;
                    // Seed host/geo from a peer we already resolved so Live view
                    // does not sit on "Looking up…" until the next async pass.
                    ApplyKnownGeo(polled);
                    _connections[polled.Key] = polled;
                    tracked = polled;
                    isNewConnection = true;
                }

                if (IsTrackableRemote(tracked.RemoteAddress))
                {
                    activeByIp.TryGetValue(tracked.RemoteAddress, out var n);
                    activeByIp[tracked.RemoteAddress] = n + 1;
                    UpsertHost(tracked, now, isNewConnection);
                }

                // Queue reverse-DNS / geo for every concrete remote, including
                // loopback and LAN — remote hosts table still uses IsTrackableRemote.
                if (ShouldResolveRemote(tracked.RemoteAddress))
                    geoIps.Add(tracked.RemoteAddress);
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
            newThreats.AddRange(_detector.Analyze(activeConns, _hosts, listeningTcpPorts, listeningUdpPorts, now));
            newThreats.AddRange(_authLog.DrainPending());
            _probeLog.SetListeningPorts(listeningTcpPorts);
            newThreats.AddRange(_probeLog.DrainPending());

            if (ProcessReputationEnabled)
            {
                _procRep.Observe(activeConns, listeningTcpPorts, now);
                newThreats.AddRange(_procRep.DrainPending());
            }

            newThreats.AddRange(_honeypot.DrainPending());
            newThreats.AddRange(_arpWatch.DrainPending());
            newThreats.AddRange(_persistenceWatch.DrainPending());
            newThreats.AddRange(_exfil.DrainPending());

            if (ThreatIntelEnabled)
                CheckThreatIntel(activeByIp.Keys, now, newThreats);

            foreach (var t in newThreats)
            {
                _threats.Insert(0, t);
                CountThreat(t);
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
                ThreatCount = newThreats.Count + _hostThreatsThisPoll,
                RemoteHostCount = _hosts.Count
            });
            // ~5 minutes of history at the 1.2 s poll rate (GUI sparkline and
            // web activity chart both render whatever range is here).
            while (_activity.Count > 240) _activity.RemoveAt(0);

            Stats.ListeningPorts = _listeners.Count;
            Stats.ActiveConnections = _connections.Count;
            Stats.RemoteHosts = _hosts.Count;
            // Counters survive the 500-entry cap on the threat list.
            Stats.ThreatsToday = _threatsTodayCount;
            Stats.HighThreats = _highThreatCount;
            Stats.StatusText = _firstPass
                ? "Baseline captured — watching for anomalies"
                : $"Live · {_connections.Count} sessions · {_hosts.Count} remotes · {_threats.Count} events";
            _firstPass = false;
        }

        // Persistence + outbound alerting off the lock
        if (newThreats.Count > 0 || _hostThreatsThisPollList.Count > 0)
            _history.AppendThreats(newThreats.Concat(_hostThreatsThisPollList));
        _history.SaveIfDirty();

        // Geo + reverse-DNS off the lock (LAN/loopback included for Live "source"/host names)
        foreach (var ip in geoIps)
            QueueGeo(ip);

        foreach (var t in newThreats)
            QueueGeo(t.SourceIp);

        if (newThreats.Count > 0)
        {
            ThreatsDetected?.Invoke(newThreats);
            _webhook.Notify(newThreats, WebhookUrl, WebhookMinLevel);
        }

        Updated?.Invoke();
    }

    /// <summary>
    /// Diffs the current listening set against the persisted baseline. A brand-new
    /// (protocol, port) after baseline is the backdoor/implant signature; a known
    /// port changing owner process is a service being replaced. Loopback-only and
    /// ephemeral-range (49152+) listeners are skipped — dev servers and per-app
    /// dynamic ports churn constantly and are unreachable or meaningless to a
    /// remote attacker respectively.
    ///
    /// Owners are tracked per signature as a SET: services routinely share a
    /// port (a service host and its workers, or several sockets bound to the
    /// same port on different addresses), so an owner-change alert fires only
    /// when the current owners have no overlap at all with every owner ever
    /// recorded — a complete replacement, not co-tenancy or flapping between
    /// known tenants.
    /// </summary>
    private void DetectNewListeners(DateTime now, List<ThreatEvent> newThreats)
    {
        var honeypotPorts = _honeypot.ActivePorts;

        // Group by (protocol, port): several sockets/processes can share one port.
        var bySignature = new Dictionary<string, List<ListeningPort>>(StringComparer.OrdinalIgnoreCase);
        foreach (var lp in _listeners.Values)
        {
            if (lp.Port >= 49152) continue;
            if (lp.Address is "127.0.0.1" or "::1") continue;
            if (lp.ProcessId == Environment.ProcessId) continue;
            if (honeypotPorts.Contains(lp.Port)) continue;

            var signature = $"{lp.Protocol}:{lp.Port}";
            if (!bySignature.TryGetValue(signature, out var list))
            {
                list = new List<ListeningPort>();
                bySignature[signature] = list;
            }
            list.Add(lp);
        }

        foreach (var (signature, listeners) in bySignature)
        {
            var owners = listeners
                .Select(l => l.ProcessName)
                .Where(IsMeaningfulProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var sample = listeners[0];

            if (!_history.TryGetListener(signature, out var knownJoined))
            {
                _history.RecordListener(signature, string.Join("|", owners));
                if (_firstPass) continue; // very first run seeds silently; later runs alert
                if (!TryNoteListenerAlert(signature, now)) continue;

                newThreats.Add(new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.NewListener,
                    Level = ThreatLevel.Medium,
                    SourceIp = "127.0.0.1",
                    Title = $"New listening port: {sample.Protocol} {sample.Port}",
                    Detail = $"{sample.ProcessName} (PID {sample.ProcessId}) started listening on {sample.DisplayEndpoint} " +
                             $"({sample.ServiceHint}) — this port was not in the baseline. A new open port is how a " +
                             "backdoor or implant accepts connections; verify you recognize the process.",
                    Origin = "This computer",
                    Method = "Listening-port baseline diff"
                });
                continue;
            }

            if (owners.Count == 0) continue; // only "PID 1234" placeholders — nothing comparable

            var known = knownJoined.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (known.Count == 0)
            {
                _history.RecordListener(signature, string.Join("|", owners));
                continue;
            }

            if (owners.Any(known.Contains))
            {
                // Same tenants (possibly a subset, or a new co-tenant) — remember the
                // union so flapping between known owners stays permanently quiet.
                known.UnionWith(owners);
                _history.RecordListener(signature, string.Join("|",
                    known.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).Take(6)));
                continue;
            }

            // Complete replacement: none of the current owners were ever seen here.
            known.UnionWith(owners);
            _history.RecordListener(signature, string.Join("|",
                known.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).Take(6)));
            if (_firstPass) continue;
            if (!TryNoteListenerAlert(signature, now)) continue;

            newThreats.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.NewListener,
                Level = ThreatLevel.High,
                SourceIp = "127.0.0.1",
                Title = $"Listening port changed owner: {sample.Protocol} {sample.Port}",
                Detail = $"Port {sample.Port} ({sample.ServiceHint}) was served by \"{knownJoined.Replace("|", ", ")}\" but is now " +
                         $"bound by \"{string.Join(", ", owners)}\" (PID {sample.ProcessId}). A different process taking over " +
                         "a known port can be a service being impersonated or replaced.",
                Origin = "This computer",
                Method = "Listening-port baseline diff"
            });
        }
    }

    private readonly Dictionary<string, DateTime> _listenerAlertAt = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan ListenerAlertCooldown = TimeSpan.FromHours(6);

    private bool TryNoteListenerAlert(string signature, DateTime now)
    {
        if (_listenerAlertAt.TryGetValue(signature, out var last) && now - last < ListenerAlertCooldown)
            return false;
        _listenerAlertAt[signature] = now;
        return true;
    }

    private static bool IsMeaningfulProcessName(string name)
        => !string.IsNullOrWhiteSpace(name) &&
           name is not ("—" or "System" or "Kernel / unknown") &&
           !name.StartsWith("PID ", StringComparison.Ordinal);

    /// <summary>
    /// One-time (per session, per IP) lookup of active peers against the
    /// threat-intel CIDR feeds. A hit is Critical regardless of behaviour —
    /// these ranges exist only to attack or be attacked.
    /// </summary>
    private void CheckThreatIntel(IEnumerable<string> activeIps, DateTime now, List<ThreatEvent> newThreats)
    {
        _intel.EnsureFresh();
        if (_intel.EntryCount == 0)
            return; // feeds not loaded yet — leave IPs unchecked so they retry

        foreach (var ip in activeIps)
        {
            if (!_intelChecked.Add(ip)) continue;
            if (GeoIpService.IsNonPublic(ip)) continue;
            if (!_intel.IsListed(ip, out var feed)) continue;

            newThreats.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.KnownBadAddress,
                Level = ThreatLevel.Critical,
                SourceIp = ip,
                Title = "Connection with a known-bad address",
                Detail = $"{ip} is listed on the {feed} threat-intel blocklist. These ranges are attack " +
                         "infrastructure or hijacked space — there is no legitimate reason for traffic to or from them.",
                Origin = "Origin resolving…",
                Method = $"Threat-intel feed ({feed})"
            });
        }
    }

    private void UpsertHost(NetworkConnection c, DateTime now, bool isNewConnection)
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

            // "First seen" consults persistent history, so a relaunch (or a
            // patient attacker waiting one out) doesn't make every known peer
            // look brand new again.
            if (!_firstPass && !_history.IsKnownHost(c.RemoteAddress))
            {
                var t = new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.NewRemoteHost,
                    Level = ThreatLevel.Info,
                    SourceIp = c.RemoteAddress,
                    Title = "New remote computer observed",
                    Detail = $"First contact from {c.RemoteAddress} → local {c.LocalAddress}:{c.LocalPort} ({c.State}).",
                    Origin = "Resolving…",
                    Method = "New session appearance"
                };
                _threats.Insert(0, t);
                CountThreat(t);
                _hostThreatsThisPoll++;
                _hostThreatsThisPollList.Add(t);
            }
        }

        _history.TouchHost(c.RemoteAddress);

        host.LastSeen = now;
        if (isNewConnection) host.TotalConnections++;
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

                    // Origin is mutable + INPC, so patch in place — keeps the
                    // same ThreatEvent instances stable for UI diffing.
                    foreach (var t in _threats.Where(x => x.SourceIp == ip &&
                             (x.Origin is "Resolving…" or "Origin resolving…" or "")))
                    {
                        t.Origin = geo.Summary;
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
        // mDNS/SSDP multicast and broadcast destinations are not real peers.
        if (GeoIpService.IsMulticastOrBroadcast(ip)) return false;
        return true;
    }

    /// <summary>Any remote address we can reverse-DNS / label in Live Connections.</summary>
    private static bool ShouldResolveRemote(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        return ip is not ("0.0.0.0" or "::");
    }

    private void ApplyKnownGeo(NetworkConnection c)
    {
        if (!_hosts.TryGetValue(c.RemoteAddress, out var host))
            return;
        if (string.IsNullOrWhiteSpace(host.GeoSummary) ||
            host.GeoSummary is "Resolving…" or "Looking up…")
            return;

        if (!string.IsNullOrWhiteSpace(host.HostName))
            c.RemoteHostName = host.HostName;
        c.GeoSummary = host.GeoSummary;
    }

    private void CountThreat(ThreatEvent t)
    {
        _threatsTodayCount++;
        if (t.Level >= ThreatLevel.High) _highThreatCount++;
    }

    public void ClearThreats()
    {
        lock (_sync)
        {
            _threats.Clear();
            _threatsTodayCount = 0;
            _highThreatCount = 0;
        }
        // Clear the persisted log too, or the entries come back on relaunch.
        _history.ClearThreatLog();
        Stats.ThreatsToday = 0;
        Stats.HighThreats = 0;
        Updated?.Invoke();
    }

    public void Dispose()
    {
        Stop();
        _authLog.Dispose();
        _probeLog.Dispose();
        _arpWatch.Dispose();
        _persistenceWatch.Dispose();
        _exfil.Dispose();
        _honeypot.Dispose();
        _intel.Dispose();
        _webhook.Dispose();
        _history.Save();
        _geo.Dispose();
    }
}
