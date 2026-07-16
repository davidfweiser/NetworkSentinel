using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// Heuristic intrusion / break-in attempt detector based on connection patterns.
/// This is awareness tooling — not a full IDS/IPS replacement.
/// </summary>
public sealed class IntrusionDetector
{
    private readonly object _gate = new();
    private readonly Dictionary<string, HostActivity> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _emitted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<(DateTime Time, string Key)> _emitHistory = new();

    private static readonly TimeSpan Window = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);

    public IReadOnlyList<ThreatEvent> Analyze(
        IReadOnlyList<NetworkConnection> snapshot,
        IReadOnlyDictionary<string, RemoteHost> knownHosts,
        DateTime now)
    {
        var threats = new List<ThreatEvent>();
        lock (_gate)
        {
            PruneEmitHistory(now);

            // Per-IP activity from this snapshot + recent history
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

                foreach (var c in conns)
                {
                    activity.PortHits.Enqueue((now, c.LocalPort, c.State, c.RemotePort));
                    activity.LastSeen = now;
                }

                while (activity.PortHits.Count > 0 && now - activity.PortHits.Peek().Time > Window)
                    activity.PortHits.Dequeue();

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
        var recent = activity.PortHits.ToList();
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

        string origin = knownHosts.TryGetValue(ip, out var host) && !string.IsNullOrWhiteSpace(host.GeoSummary)
            ? host.GeoSummary
            : "Origin resolving…";

        // Port scan: many different local ports from one remote IP in a short window
        if (distinctLocalPorts >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.High,
                "Port scan pattern detected",
                $"{ip} touched {distinctLocalPorts} different local ports within {Window.TotalSeconds:0}s.",
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

        // Brute-force style hammering of login services
        if (rdpHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.Critical,
                "RDP brute-force pattern",
                $"{ip} opened {rdpHits} RDP (3389) related sessions/hits in {Window.TotalSeconds:0}s.",
                origin,
                "Remote Desktop (TCP 3389) hammering");
        }

        if (smbHits >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SMB access burst",
                $"{ip} generated {smbHits} SMB/NetBIOS hits in {Window.TotalSeconds:0}s.",
                origin,
                "SMB / NetBIOS (445/139)");
        }

        if (sshHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SSH brute-force pattern",
                $"{ip} generated {sshHits} SSH (22) hits in {Window.TotalSeconds:0}s.",
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
                $"{ip} produced {shortLivedLike} non-established / transitional TCP states in {Window.TotalSeconds:0}s.",
                origin,
                "Syn flood style / scan noise / flapping");
        }

        if (recent.Count >= 20 && distinctLocalPorts <= 2)
        {
            TryAdd(threats, now, ip, ThreatType.RapidReconnect, ThreatLevel.Low,
                "Rapid reconnect activity",
                $"{ip} generated {recent.Count} connection events against few ports.",
                origin,
                "High-frequency reconnects");
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
        public Queue<(DateTime Time, int LocalPort, TcpConnectionState State, int RemotePort)> PortHits { get; } = new();
        public DateTime LastSeen { get; set; } = DateTime.Now;
    }
}
