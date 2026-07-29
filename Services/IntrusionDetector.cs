using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// Heuristic intrusion / break-in attempt detector based on connection patterns.
/// This is awareness tooling — not a full IDS/IPS replacement.
///
/// Counting model: a "hit" is recorded only when a connection key appears that
/// was not present in the previous poll (a NEW connection event), never for a
/// long-lived session that is simply still open. Heuristics only consider
/// INBOUND events — connections landing on a local port this machine is
/// actually listening on (or in SYN-RECEIVED) — so outbound ephemeral local
/// ports from ordinary client traffic can never look like a port scan.
/// </summary>
public sealed class IntrusionDetector
{
    private readonly object _gate = new();
    private readonly Dictionary<string, HostActivity> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _emitted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<(DateTime Time, string Key)> _emitHistory = new();

    private static readonly TimeSpan Window = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Outbound destination ports that ordinary client software hammers all
    /// day (web, mail, DNS, NTP, SSH); excluded from beacon detection.
    /// </summary>
    private static readonly HashSet<int> CommonOutboundPorts = new()
    {
        53, 80, 123, 443, 22, 25, 110, 143, 465, 587, 993, 995, 8080, 8443
    };

    public IReadOnlyList<ThreatEvent> Analyze(
        IReadOnlyList<NetworkConnection> snapshot,
        IReadOnlyDictionary<string, RemoteHost> knownHosts,
        IReadOnlySet<int> listeningTcpPorts,
        DateTime now)
    {
        var threats = new List<ThreatEvent>();
        lock (_gate)
        {
            PruneEmitHistory(now);

            // Group this snapshot's interesting connections by remote IP
            var byIp = new Dictionary<string, List<NetworkConnection>>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in snapshot)
            {
                if (!IsInterestingRemote(c)) continue;
                if (!byIp.TryGetValue(c.RemoteAddress, out var list))
                {
                    list = new List<NetworkConnection>();
                    byIp[c.RemoteAddress] = list;
                }
                list.Add(c);
            }

            foreach (var (ip, conns) in byIp)
            {
                if (!_hosts.TryGetValue(ip, out var activity))
                {
                    activity = new HostActivity();
                    _hosts[ip] = activity;
                }

                // Record an event only for connections that were NOT present
                // last poll — i.e. genuinely new sessions, not resampled ones.
                var currentKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var c in conns)
                {
                    currentKeys.Add(c.Key);
                    if (activity.ActiveKeys.Contains(c.Key))
                        continue;

                    bool inbound = listeningTcpPorts.Contains(c.LocalPort) ||
                                   c.State == TcpConnectionState.SynReceived;
                    activity.Events.Enqueue((now, c.LocalPort, c.State, inbound));
                    if (inbound)
                        activity.LongInbound.Enqueue((now, c.LocalPort));
                    else
                        activity.OutboundNew.Enqueue((now, c.RemotePort, c.ProcessName));
                }

                activity.ActiveKeys = currentKeys;
                activity.LastSeen = now;

                while (activity.Events.Count > 0 && now - activity.Events.Peek().Time > Window)
                    activity.Events.Dequeue();
                while (activity.LongInbound.Count > 0 && now - activity.LongInbound.Peek().Time > LongWindow)
                    activity.LongInbound.Dequeue();
                while (activity.OutboundNew.Count > 0 && now - activity.OutboundNew.Peek().Time > LongWindow)
                    activity.OutboundNew.Dequeue();

                EvaluateHost(ip, activity, knownHosts, now, threats);
            }

            // Drop stale host activity
            var stale = _hosts.Where(kv => now - kv.Value.LastSeen > TimeSpan.FromMinutes(10))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _hosts.Remove(key);
        }

        return threats;
    }

    private void EvaluateHost(
        string ip,
        HostActivity activity,
        IReadOnlyDictionary<string, RemoteHost> knownHosts,
        DateTime now,
        List<ThreatEvent> threats)
    {
        string origin = knownHosts.TryGetValue(ip, out var host) && !string.IsNullOrWhiteSpace(host.GeoSummary)
            ? host.GeoSummary
            : "Origin resolving…";

        EvaluateSlowScan(ip, activity, origin, now, threats);
        EvaluateOutboundBeacon(ip, activity, origin, now, threats);

        // Only inbound events count — outbound client connections use random
        // ephemeral local ports and must never register as probing.
        var recent = activity.Events.Where(e => e.Inbound).ToList();
        if (recent.Count == 0) return;

        var distinctLocalPorts = recent.Select(x => x.LocalPort).Distinct().Count();
        var sensitiveHits = recent.Count(x => PortCatalog.SensitivePorts.Contains(x.LocalPort));
        var rdpHits = recent.Count(x => x.LocalPort == 3389);
        var smbHits = recent.Count(x => x.LocalPort is 445 or 139);
        var sshHits = recent.Count(x => x.LocalPort == 22);
        var shortLivedLike = recent.Count(x =>
            x.State is TcpConnectionState.SynSent or TcpConnectionState.SynReceived
                or TcpConnectionState.TimeWait or TcpConnectionState.FinWait1
                or TcpConnectionState.FinWait2 or TcpConnectionState.CloseWait);

        // Port scan: many different local service ports hit from one remote IP in a short window
        if (distinctLocalPorts >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.High,
                "Port scan pattern detected",
                $"{ip} opened connections to {distinctLocalPorts} different local ports within {Window.TotalSeconds:0}s.",
                origin,
                "Sequential / multi-port probing");
        }
        else if (distinctLocalPorts >= 5)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.Medium,
                "Possible port reconnaissance",
                $"{ip} contacted {distinctLocalPorts} local ports in a short window.",
                origin,
                "Multi-port probing");
        }

        // Brute-force style hammering of login services (repeated NEW sessions)
        if (rdpHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.Critical,
                "RDP brute-force pattern",
                $"{ip} opened {rdpHits} new RDP (3389) sessions in {Window.TotalSeconds:0}s.",
                origin,
                "Remote Desktop (TCP 3389) hammering");
        }

        if (smbHits >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SMB access burst",
                $"{ip} opened {smbHits} new SMB/NetBIOS sessions in {Window.TotalSeconds:0}s.",
                origin,
                "SMB / NetBIOS (445/139)");
        }

        if (sshHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SSH brute-force pattern",
                $"{ip} opened {sshHits} new SSH (22) sessions in {Window.TotalSeconds:0}s.",
                origin,
                "SSH (TCP 22) hammering");
        }

        // Sensitive port probes
        if (sensitiveHits >= 3 && distinctLocalPorts >= 2)
        {
            var ports = string.Join(", ", recent
                .Where(x => PortCatalog.SensitivePorts.Contains(x.LocalPort))
                .Select(x => x.LocalPort)
                .Distinct()
                .OrderBy(x => x));
            TryAdd(threats, now, ip, ThreatType.SensitivePortProbe, ThreatLevel.Medium,
                "Sensitive service probing",
                $"{ip} probed sensitive ports: {ports}.",
                origin,
                "Admin / file-share / remote-access ports");
        }

        // Rapid reconnect / half-open noise
        if (shortLivedLike >= 12)
        {
            TryAdd(threats, now, ip, ThreatType.ManyShortConnections, ThreatLevel.Medium,
                "Short-lived connection burst",
                $"{ip} produced {shortLivedLike} non-established / transitional inbound sessions in {Window.TotalSeconds:0}s.",
                origin,
                "Syn flood style / scan noise / flapping");
        }

        if (recent.Count >= 20 && distinctLocalPorts <= 2)
        {
            TryAdd(threats, now, ip, ThreatType.RapidReconnect, ThreatLevel.Low,
                "Rapid reconnect activity",
                $"{ip} opened {recent.Count} new inbound sessions against few ports.",
                origin,
                "High-frequency reconnects");
        }
    }

    /// <summary>
    /// Paced reconnaissance: many distinct listening ports probed by one IP,
    /// spread out enough that the 45s fast window never fires (e.g. nmap -T1).
    /// </summary>
    private void EvaluateSlowScan(
        string ip, HostActivity activity, string origin, DateTime now, List<ThreatEvent> threats)
    {
        var distinct = activity.LongInbound.Select(x => x.LocalPort).Distinct().Count();
        if (distinct >= 16)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.High,
                "Slow port scan detected",
                $"{ip} touched {distinct} different local ports over the last {LongWindow.TotalMinutes:0} minutes — paced scanning below the fast-scan threshold.",
                origin,
                "Low-and-slow multi-port probing");
        }
        else if (distinct >= 10)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.Medium,
                "Possible slow port reconnaissance",
                $"{ip} touched {distinct} different local ports over the last {LongWindow.TotalMinutes:0} minutes.",
                origin,
                "Low-and-slow multi-port probing");
        }
    }

    /// <summary>
    /// Beacon-like outbound traffic: repeated NEW sessions from this machine
    /// to the same remote host on an uncommon destination port at a regular
    /// cadence — the signature of C2 check-ins after a compromise. Common
    /// client ports (web, mail, DNS…) and private/LAN peers are excluded, so
    /// browsers and local chatter never trip it.
    /// </summary>
    private void EvaluateOutboundBeacon(
        string ip, HostActivity activity, string origin, DateTime now, List<ThreatEvent> threats)
    {
        if (activity.OutboundNew.Count < 6) return;
        if (GeoIpService.IsNonPublic(ip)) return;

        foreach (var group in activity.OutboundNew
                     .Where(x => !CommonOutboundPorts.Contains(x.RemotePort))
                     .GroupBy(x => x.RemotePort))
        {
            var times = group.Select(x => x.Time).OrderBy(t => t).ToList();
            if (times.Count < 6) continue;

            var intervals = new List<double>();
            for (int i = 1; i < times.Count; i++)
                intervals.Add((times[i] - times[i - 1]).TotalSeconds);

            double mean = intervals.Average();
            // Bursts (rapid retries) are normal failure behavior, not beaconing.
            if (mean < 15) continue;

            double variance = intervals.Sum(v => (v - mean) * (v - mean)) / intervals.Count;
            double cv = Math.Sqrt(variance) / mean;
            if (cv > 0.5) continue;

            var process = group.Select(x => x.ProcessName)
                .LastOrDefault(p => !string.IsNullOrWhiteSpace(p) && p != "—") ?? "unknown process";
            TryAdd(threats, now, ip, ThreatType.SuspiciousOutbound, ThreatLevel.Medium,
                "Possible outbound beaconing",
                $"This machine opened {times.Count} sessions to {ip}:{group.Key} at a regular ~{mean:0}s interval over {LongWindow.TotalMinutes:0} minutes (process: {process}). Regular check-ins to an uncommon port can indicate malware calling home.",
                origin,
                $"Periodic outbound to port {group.Key}");
            break;
        }
    }

    private void TryAdd(
        List<ThreatEvent> threats,
        DateTime now,
        string ip,
        ThreatType type,
        ThreatLevel level,
        string title,
        string detail,
        string origin,
        string method)
    {
        string key = $"{ip}|{type}";
        if (_emitted.Contains(key)) return;

        _emitted.Add(key);
        _emitHistory.Enqueue((now, key));

        threats.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = type,
            Level = level,
            SourceIp = ip,
            Title = title,
            Detail = detail,
            Origin = origin,
            Method = method
        });
    }

    private void PruneEmitHistory(DateTime now)
    {
        while (_emitHistory.Count > 0 && now - _emitHistory.Peek().Time > EmitCooldown)
        {
            var old = _emitHistory.Dequeue();
            _emitted.Remove(old.Key);
        }
    }

    private static bool IsInterestingRemote(NetworkConnection c)
    {
        if (c.Protocol != "TCP") return false;
        if (string.IsNullOrWhiteSpace(c.RemoteAddress)) return false;
        if (c.RemoteAddress is "0.0.0.0" or "::" or "127.0.0.1" or "::1") return false;
        if (c.State == TcpConnectionState.Listen) return false;
        return true;
    }

    private sealed class HostActivity
    {
        public Queue<(DateTime Time, int LocalPort, TcpConnectionState State, bool Inbound)> Events { get; } = new();
        public Queue<(DateTime Time, int LocalPort)> LongInbound { get; } = new();
        public Queue<(DateTime Time, int RemotePort, string ProcessName)> OutboundNew { get; } = new();
        public HashSet<string> ActiveKeys { get; set; } = new(StringComparer.Ordinal);
        public DateTime LastSeen { get; set; } = DateTime.Now;
    }
}
