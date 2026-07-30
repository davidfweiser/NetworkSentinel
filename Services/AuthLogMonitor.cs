using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Xml.Linq;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the Windows Security event log for failed remote logons and turns
/// bursts into FailedLogonBurst threat events. This closes the gap the
/// connection-based heuristics cannot see: a brute-force that reuses one TCP
/// session (RDP/SMB/WinRM re-auth), or paced attempts below the connection-rate
/// thresholds.
///
/// Source: EventLogWatcher on the Security channel, event IDs 4625 (an account
/// failed to log on) and 4771 (Kerberos pre-authentication failed). Reading the
/// Security channel needs Administrator — or membership in the local
/// "Event Log Readers" group. Without it the monitor degrades to "unavailable"
/// and says so in <see cref="Status"/>; nothing else in the app is affected.
///
/// The Linux build reads journald / auth.log for the same signal; the threat
/// events, thresholds, and cooldowns are deliberately identical so both
/// front-ends and the web console behave the same way on either OS.
/// </summary>
public sealed class AuthLogMonitor : IDisposable
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);
    private const int HighThreshold = 4;
    private const int CriticalThreshold = 10;

    // 4625 = failed logon (all logon types), 4771 = Kerberos pre-auth failed (DCs).
    // Both carry the caller's IP; 4776 (NTLM validation failure) does not, so it
    // is left out — an alert with no source IP could never be blocked.
    private const string SecurityQuery = "*[System[(EventID=4625 or EventID=4771)]]";

    private readonly object _gate = new();
    private readonly Dictionary<string, IpFailures> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();

    private EventLogWatcher? _watcher;
    private volatile string _status = "Auth log monitoring not started";

    /// <summary>Human-readable state of the log source (or why it is unavailable).</summary>
    public string Status => _status;

    public void Start()
    {
        try
        {
            // Subscribing to an unreadable channel succeeds silently — Enabled = true
            // does not throw, events simply never arrive — so probe with a real read
            // first. Without this, an unelevated run would claim to be watching while
            // seeing nothing.
            if (!CanReadSecurityLog(out var accessError))
            {
                _status = accessError;
                return;
            }

            // Subscribe under the lock so a second Start cannot leave an orphaned
            // watcher running. Delivery callbacks also take _gate, so they simply
            // wait for this to finish; Stop() never holds the lock while it waits
            // on the watcher, so there is no cycle.
            lock (_gate)
            {
                if (_watcher != null) return;

                var query = new EventLogQuery("Security", PathType.LogName, SecurityQuery)
                {
                    TolerateQueryErrors = true
                };
                // No bookmark: start from "now" so a fresh start never replays days of
                // history as live threats.
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += OnEventRecordWritten;
                watcher.Enabled = true;
                _watcher = watcher;
            }

            _status = "Watching Windows Security log (failed logons 4625 / 4771)";
        }
        catch (UnauthorizedAccessException)
        {
            _status = "Security event log not readable by this account — logon monitoring off " +
                      "(run as Administrator, or add the account to the local “Event Log Readers” group)";
        }
        catch (EventLogException ex)
        {
            _status = $"Security event log unavailable — logon monitoring off ({ex.Message})";
        }
        catch (Exception ex)
        {
            _status = $"Auth log monitoring failed: {ex.Message}";
        }
    }

    /// <summary>
    /// One-shot read of the Security channel to prove this account can actually
    /// see it. An empty log is fine — only an access failure matters.
    /// TolerateQueryErrors stays off here on purpose: with it on, the read returns
    /// null instead of throwing on a denied channel, which is exactly the false
    /// "all good" this probe exists to catch.
    /// </summary>
    private static bool CanReadSecurityLog(out string error)
    {
        try
        {
            var probe = new EventLogQuery("Security", PathType.LogName)
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(probe);
            reader.ReadEvent(TimeSpan.FromSeconds(5))?.Dispose();
            error = "";
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            error = "Security event log not readable by this account — logon monitoring off " +
                    "(run as Administrator, or add the account to the local “Event Log Readers” group)";
            return false;
        }
        catch (EventLogException ex)
        {
            error = $"Security event log unavailable — logon monitoring off ({ex.Message})";
            return false;
        }
    }

    public void Stop()
    {
        EventLogWatcher? watcher;
        lock (_gate)
        {
            watcher = _watcher;
            _watcher = null;
        }
        if (watcher == null) return;

        try
        {
            watcher.EventRecordWritten -= OnEventRecordWritten;
            watcher.Enabled = false;
        }
        catch
        {
            // channel already gone / access revoked
        }
        watcher.Dispose();
        _status = "Auth log monitoring stopped";
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

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord == null) return;
            using var record = e.EventRecord;
            ProcessRecord(record.ToXml(), record.Id, DateTime.Now);
        }
        catch
        {
            // A single unreadable record must never take the subscription down.
        }
    }

    /// <summary>Parses one Security-log event XML payload; internal for tests / manual replay.</summary>
    internal void ProcessRecord(string eventXml, int eventId, DateTime now)
    {
        string ip, user;
        try
        {
            var doc = XDocument.Parse(eventXml);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            string Data(string name) => doc.Descendants(ns + "Data")
                .FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value ?? "";

            ip = NormalizeEventIp(Data("IpAddress"));
            user = Data("TargetUserName").Trim();
            if (eventId == 4771 && string.IsNullOrEmpty(user))
                user = Data("ServiceName").Trim();
        }
        catch
        {
            return;
        }

        if (string.IsNullOrEmpty(ip)) return;

        RecordFailure(ip, user, now);
    }

    /// <summary>
    /// Security-log IPs arrive as "-" for local logons and as IPv4-mapped IPv6
    /// ("::ffff:203.0.113.7") from Kerberos; normalize to the plain form the rest
    /// of the app (hosts table, firewall rules) uses. Returns "" for anything
    /// local or unparseable.
    /// </summary>
    private static string NormalizeEventIp(string raw)
    {
        var value = raw.Trim();
        if (value.Length == 0 || value == "-") return "";

        if (!IPAddress.TryParse(value, out var parsed)) return "";
        if (parsed.IsIPv4MappedToIPv6)
            parsed = parsed.MapToIPv4();
        if (IPAddress.IsLoopback(parsed) || parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any))
            return "";

        return parsed.ToString();
    }

    private void RecordFailure(string ip, string user, DateTime now)
    {
        lock (_gate)
        {
            if (!_failures.TryGetValue(ip, out var f))
            {
                f = new IpFailures();
                _failures[ip] = f;
            }

            f.Attempts.Enqueue(now);
            if (!string.IsNullOrWhiteSpace(user) && user != "-")
                f.Users.Add(user);
            while (f.Attempts.Count > 0 && now - f.Attempts.Peek() > Window)
                f.Attempts.Dequeue();

            var count = f.Attempts.Count;
            ThreatLevel? level = null;
            if (count >= CriticalThreshold) level = ThreatLevel.Critical;
            else if (count >= HighThreshold) level = ThreatLevel.High;
            if (level == null) return;

            // Per-IP cooldown, but let an escalation to Critical break through.
            string emitKey = $"{ip}|{level}";
            if (_lastEmit.TryGetValue(emitKey, out var last) && now - last < EmitCooldown)
                return;
            _lastEmit[emitKey] = now;

            var users = f.Users.Count > 0
                ? $" Accounts tried: {string.Join(", ", f.Users.Take(8))}{(f.Users.Count > 8 ? ", …" : "")}."
                : "";
            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.FailedLogonBurst,
                Level = level.Value,
                SourceIp = ip,
                Title = $"{count} failed logons in {Window.TotalMinutes:0} min",
                Detail = $"{ip} produced {count} failed Windows logon attempts within {Window.TotalMinutes:0} minutes.{users}",
                Origin = "Origin resolving…",
                Method = "Windows Security log (failed logon 4625 / 4771)"
            });

            // Keep the per-IP tables from growing without bound.
            if (_failures.Count > 2000)
            {
                foreach (var stale in _failures
                             .Where(kv => kv.Value.Attempts.Count == 0 ||
                                          now - kv.Value.Attempts.Last() > Window)
                             .Select(kv => kv.Key).ToList())
                {
                    _failures.Remove(stale);
                }
            }
            if (_lastEmit.Count > 4000)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    public void Dispose() => Stop();

    private sealed class IpFailures
    {
        public Queue<DateTime> Attempts { get; } = new();
        public HashSet<string> Users { get; } = new(StringComparer.Ordinal);
    }
}
