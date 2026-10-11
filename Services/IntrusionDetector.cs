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
///
/// Attribution: a socket in SYN-RECEIVED carries whatever source address the SYN
/// claimed, and a forged one never gets further. So an inbound session only counts
/// as evidence against its address once it has completed the handshake (seen in any
/// post-handshake state, then or on a later poll). Patterns that only trip when the
/// half-open sessions are counted too are still reported, but carry an
/// <see cref="ThreatEvent.AutoBlockHoldReason"/> so they never drive an auto-block —
/// otherwise six forged SYNs to port 3389 "from" the admin's address would firewall the
/// admin out. The price is that a stealth SYN scan (which never completes a handshake
/// either) is detected but not auto-blocked; a connect scan still is.
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
        IReadOnlySet<int> listeningUdpPorts,
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

                    // A half-open session first seen on an earlier poll that has since
                    // completed its handshake: the address really did send it.
                    if (activity.AwaitingHandshake.TryGetValue(c.Key, out var waiting) && CompletedHandshake(c))
                    {
                        waiting.Confirmed = true;
                        activity.AwaitingHandshake.Remove(c.Key);
                    }

                    if (activity.ActiveKeys.Contains(c.Key))
                        continue;

                    // Inbound = landing on a port this machine serves. UDP has no
                    // handshake, so a peer talking to one of our UDP listeners is
                    // the closest equivalent.
                    bool inbound = c.Protocol == "UDP"
                        ? listeningUdpPorts.Contains(c.LocalPort)
                        : listeningTcpPorts.Contains(c.LocalPort) ||
                          c.State == TcpConnectionState.SynReceived;
                    var ev = new SessionEvent(now, c.LocalPort, c.State, inbound)
                    {
                        Confirmed = CompletedHandshake(c)
                    };
                    activity.Events.Enqueue(ev);
                    if (inbound)
                    {
                        activity.LongInbound.Enqueue(ev);
                        if (!ev.Confirmed && c.Protocol == "TCP")
                            activity.AwaitingHandshake[c.Key] = ev;
                    }
                    else
                    {
                        activity.OutboundNew.Enqueue((now, c.RemotePort, c.ProcessName));
                    }
                }

                // A session that vanished while half-open never completed: it stays unconfirmed.
                if (activity.AwaitingHandshake.Count > 0)
                    foreach (var gone in activity.AwaitingHandshake.Keys.Where(k => !currentKeys.Contains(k)).ToList())
                        activity.AwaitingHandshake.Remove(gone);

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

        // Each pattern is judged twice: on every inbound session (to alert), and on the
        // handshake-confirmed ones only (to decide whether the address may be blocked).
        var all = new InboundStats(recent);
        var proven = new InboundStats(recent.Where(e => e.Confirmed).ToList());

        // Port scan: many different local service ports hit from one remote IP in a short window
        if (all.DistinctLocalPorts >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.High,
                "Port scan pattern detected",
                $"{ip} opened connections to {all.DistinctLocalPorts} different local ports within {Window.TotalSeconds:0}s.",
                origin,
                "Sequential / multi-port probing",
                attributed: proven.DistinctLocalPorts >= 8);
        }
        else if (all.DistinctLocalPorts >= 5)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.Medium,
                "Possible port reconnaissance",
                $"{ip} contacted {all.DistinctLocalPorts} local ports in a short window.",
                origin,
                "Multi-port probing",
                attributed: proven.DistinctLocalPorts >= 5);
        }

        // Brute-force style hammering of login services (repeated NEW sessions)
        if (all.RdpHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.Critical,
                "RDP brute-force pattern",
                $"{ip} opened {all.RdpHits} new RDP (3389) sessions in {Window.TotalSeconds:0}s.",
                origin,
                "Remote Desktop (TCP 3389) hammering",
                attributed: proven.RdpHits >= 6);
        }

        if (all.SmbHits >= 8)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SMB access burst",
                $"{ip} opened {all.SmbHits} new SMB/NetBIOS sessions in {Window.TotalSeconds:0}s.",
                origin,
                "SMB / NetBIOS (445/139)",
                attributed: proven.SmbHits >= 8);
        }

        if (all.SshHits >= 6)
        {
            TryAdd(threats, now, ip, ThreatType.BruteForcePattern, ThreatLevel.High,
                "SSH brute-force pattern",
                $"{ip} opened {all.SshHits} new SSH (22) sessions in {Window.TotalSeconds:0}s.",
                origin,
                "SSH (TCP 22) hammering",
                attributed: proven.SshHits >= 6);
        }

        // Sensitive port probes
        if (all.SensitiveHits >= 3 && all.DistinctLocalPorts >= 2)
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
                "Admin / file-share / remote-access ports",
                attributed: proven.SensitiveHits >= 3 && proven.DistinctLocalPorts >= 2);
        }

        // Rapid reconnect / half-open noise
        if (all.ShortLivedLike >= 12)
        {
            TryAdd(threats, now, ip, ThreatType.ManyShortConnections, ThreatLevel.Medium,
                "Short-lived connection burst",
                $"{ip} produced {all.ShortLivedLike} non-established / transitional inbound sessions in {Window.TotalSeconds:0}s.",
                origin,
                "Syn flood style / scan noise / flapping",
                attributed: proven.ShortLivedLike >= 12);
        }

        if (all.Count >= 20 && all.DistinctLocalPorts <= 2)
        {
            TryAdd(threats, now, ip, ThreatType.RapidReconnect, ThreatLevel.Low,
                "Rapid reconnect activity",
                $"{ip} opened {all.Count} new inbound sessions against few ports.",
                origin,
                "High-frequency reconnects",
                attributed: proven.Count >= 20 && proven.DistinctLocalPorts <= 2);
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
        var provenDistinct = activity.LongInbound.Where(x => x.Confirmed).Select(x => x.LocalPort).Distinct().Count();
        if (distinct >= 16)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.High,
                "Slow port scan detected",
                $"{ip} touched {distinct} different local ports over the last {LongWindow.TotalMinutes:0} minutes — paced scanning below the fast-scan threshold.",
                origin,
                "Low-and-slow multi-port probing",
                attributed: provenDistinct >= 16);
        }
        else if (distinct >= 10)
        {
            TryAdd(threats, now, ip, ThreatType.PortScan, ThreatLevel.Medium,
                "Possible slow port reconnaissance",
                $"{ip} touched {distinct} different local ports over the last {LongWindow.TotalMinutes:0} minutes.",
                origin,
                "Low-and-slow multi-port probing",
                attributed: provenDistinct >= 10);
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
        string method,
        bool attributed = true)
    {
        // Attribution is part of the key: a pattern first seen only through half-open
        // sessions must still be able to fire again, blockable, once the same address
        // completes enough handshakes to prove it is really the one connecting.
        string key = $"{ip}|{type}|{(attributed ? "proven" : "unproven")}";
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
            Method = method,
            AutoBlockHoldReason = attributed ? null : UnprovenSourceReason
        });
    }

    internal const string UnprovenSourceReason =
        "the sessions never completed a TCP handshake, so the source address may be forged";

    private static bool CompletedHandshake(NetworkConnection c)
        => c.Protocol == "TCP" && c.State is TcpConnectionState.Established
            or TcpConnectionState.FinWait1 or TcpConnectionState.FinWait2
            or TcpConnectionState.CloseWait or TcpConnectionState.Closing
            or TcpConnectionState.LastAck or TcpConnectionState.TimeWait;

    /// <summary>The counts the inbound patterns are judged on, over one set of sessions.</summary>
    private readonly struct InboundStats
    {
        public InboundStats(List<SessionEvent> events)
        {
            Count = events.Count;
            DistinctLocalPorts = events.Select(x => x.LocalPort).Distinct().Count();
            SensitiveHits = events.Count(x => PortCatalog.SensitivePorts.Contains(x.LocalPort));
            RdpHits = events.Count(x => x.LocalPort == 3389);
            SmbHits = events.Count(x => x.LocalPort is 445 or 139);
            SshHits = events.Count(x => x.LocalPort == 22);
            ShortLivedLike = events.Count(x =>
                x.State is TcpConnectionState.SynSent or TcpConnectionState.SynReceived
                    or TcpConnectionState.TimeWait or TcpConnectionState.FinWait1
                    or TcpConnectionState.FinWait2 or TcpConnectionState.CloseWait);
        }

        public int Count { get; }
        public int DistinctLocalPorts { get; }
        public int SensitiveHits { get; }
        public int RdpHits { get; }
        public int SmbHits { get; }
        public int SshHits { get; }
        public int ShortLivedLike { get; }
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
        if (c.Protocol is not ("TCP" or "UDP")) return false;
        if (string.IsNullOrWhiteSpace(c.RemoteAddress)) return false;
        if (c.RemoteAddress is "0.0.0.0" or "::" or "127.0.0.1" or "::1") return false;
        if (c.State == TcpConnectionState.Listen) return false;
        // Multicast/broadcast peers (mDNS, SSDP) are LAN chatter, not hosts.
        if (GeoIpService.IsMulticastOrBroadcast(c.RemoteAddress)) return false;
        return true;
    }

    /// <summary>
    /// One new session. <see cref="Confirmed"/> is mutable because a session first seen
    /// half-open is confirmed on whichever later poll finds it past the handshake.
    /// </summary>
    private sealed class SessionEvent
    {
        public SessionEvent(DateTime time, int localPort, TcpConnectionState state, bool inbound)
        {
            Time = time;
            LocalPort = localPort;
            State = state;
            Inbound = inbound;
        }

        public DateTime Time { get; }
        public int LocalPort { get; }
        public TcpConnectionState State { get; }
        public bool Inbound { get; }
        public bool Confirmed { get; set; }
    }

    private sealed class HostActivity
    {
        public Queue<SessionEvent> Events { get; } = new();
        public Queue<SessionEvent> LongInbound { get; } = new();
        public Dictionary<string, SessionEvent> AwaitingHandshake { get; } = new(StringComparer.Ordinal);
        public Queue<(DateTime Time, int RemotePort, string ProcessName)> OutboundNew { get; } = new();
        public HashSet<string> ActiveKeys { get; set; } = new(StringComparer.Ordinal);
        public DateTime LastSeen { get; set; } = DateTime.Now;
    }
}
