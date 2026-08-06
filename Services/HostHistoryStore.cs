using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Persists what the monitor has learned across restarts: remote hosts already
/// seen (so "first-seen host" survives a relaunch and a patient attacker can't
/// reset it by waiting for a reboot), the listening-port baseline (so
/// new-listener detection compares against history, not just this session),
/// and a bounded threat-event log.
///
/// Lives in the XDG data directory (~/.local/share/NetworkSentinel):
/// host-history.json plus threat-log.jsonl (append-only, rotated).
/// </summary>
public sealed class HostHistoryStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>A host seen longer ago than this counts as new again.</summary>
    private static readonly TimeSpan HostMemory = TimeSpan.FromDays(30);
    private static readonly TimeSpan SaveThrottle = TimeSpan.FromSeconds(60);
    private const int MaxHosts = 20_000;
    private const long ThreatLogRotateBytes = 2_000_000;
    private const int ThreatLogKeepOnRotate = 1000;

    private readonly object _gate = new();
    private Dictionary<string, HostRecord> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, ListenerRecord> _listeners = new(StringComparer.OrdinalIgnoreCase);
    private bool _dirty;
    private DateTime _lastSaveUtc = DateTime.MinValue;

    private static string HistoryPath => Path.Combine(AppPaths.DataDirectory, "host-history.json");
    private static string ThreatLogPath => Path.Combine(AppPaths.DataDirectory, "threat-log.jsonl");

    public HostHistoryStore()
    {
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(HistoryPath)) return;
            var file = JsonSerializer.Deserialize<HistoryFile>(File.ReadAllText(HistoryPath), JsonOptions);
            if (file == null) return;
            lock (_gate)
            {
                _hosts = file.Hosts ?? new Dictionary<string, HostRecord>(StringComparer.OrdinalIgnoreCase);
                _listeners = file.Listeners ?? new Dictionary<string, ListenerRecord>(StringComparer.OrdinalIgnoreCase);
            }
        }
        catch
        {
            // corrupt history is not fatal — start fresh
        }
    }

    /// <summary>True when this IP was already observed within the memory window.</summary>
    public bool IsKnownHost(string ip)
    {
        lock (_gate)
        {
            return _hosts.TryGetValue(ip, out var rec) &&
                   DateTime.UtcNow - rec.LastSeenUtc < HostMemory;
        }
    }

    public void TouchHost(string ip)
    {
        var now = DateTime.UtcNow;
        lock (_gate)
        {
            if (_hosts.TryGetValue(ip, out var rec))
            {
                // Only dirty the store when the change is worth persisting.
                if (now - rec.LastSeenUtc > TimeSpan.FromMinutes(5))
                {
                    rec.LastSeenUtc = now;
                    _dirty = true;
                }
                else
                {
                    rec.LastSeenUtc = now;
                }
            }
            else
            {
                _hosts[ip] = new HostRecord { FirstSeenUtc = now, LastSeenUtc = now };
                _dirty = true;
            }
        }
    }

    /// <summary>
    /// True when this listener signature (protocol:port) is already part of the
    /// baseline. <paramref name="knownProcess"/> is the recorded owner.
    /// </summary>
    public bool TryGetListener(string signature, out string knownProcess)
    {
        lock (_gate)
        {
            if (_listeners.TryGetValue(signature, out var rec))
            {
                knownProcess = rec.Process;
                return true;
            }
        }
        knownProcess = "";
        return false;
    }

    public void RecordListener(string signature, string process)
    {
        lock (_gate)
        {
            if (_listeners.TryGetValue(signature, out var rec))
            {
                if (!string.Equals(rec.Process, process, StringComparison.OrdinalIgnoreCase))
                {
                    rec.Process = process;
                    _dirty = true;
                }
            }
            else
            {
                _listeners[signature] = new ListenerRecord
                {
                    Process = process,
                    FirstSeenUtc = DateTime.UtcNow
                };
                _dirty = true;
            }
        }
    }

    /// <summary>Throttled persist; call from the poll loop.</summary>
    public void SaveIfDirty()
    {
        lock (_gate)
        {
            if (!_dirty || DateTime.UtcNow - _lastSaveUtc < SaveThrottle)
                return;
        }
        Save();
    }

    public void Save()
    {
        try
        {
            HistoryFile file;
            lock (_gate)
            {
                if (_hosts.Count > MaxHosts)
                {
                    foreach (var stale in _hosts.OrderBy(kv => kv.Value.LastSeenUtc)
                                 .Take(_hosts.Count - MaxHosts).Select(kv => kv.Key).ToList())
                    {
                        _hosts.Remove(stale);
                    }
                }

                file = new HistoryFile
                {
                    Hosts = new Dictionary<string, HostRecord>(_hosts, StringComparer.OrdinalIgnoreCase),
                    Listeners = new Dictionary<string, ListenerRecord>(_listeners, StringComparer.OrdinalIgnoreCase)
                };
                _dirty = false;
                _lastSaveUtc = DateTime.UtcNow;
            }

            AppPaths.WriteAtomic(HistoryPath, JsonSerializer.Serialize(file, JsonOptions));
        }
        catch
        {
            // best-effort persistence
        }
    }

    // ── Threat log ───────────────────────────────────────────────────────

    public void AppendThreats(IEnumerable<ThreatEvent> threats)
    {
        try
        {
            var lines = threats.Select(t => JsonSerializer.Serialize(new ThreatRecord
            {
                Time = t.Timestamp,
                Type = t.Type.ToString(),
                Level = t.Level.ToString(),
                Ip = t.SourceIp,
                Title = t.Title,
                Detail = t.Detail,
                Origin = t.Origin,
                Method = t.Method
            }, JsonOptions)).ToList();
            if (lines.Count == 0) return;

            File.AppendAllLines(ThreatLogPath, lines);

            var info = new FileInfo(ThreatLogPath);
            if (info.Length > ThreatLogRotateBytes)
            {
                var keep = File.ReadAllLines(ThreatLogPath);
                AppPaths.WriteAtomic(ThreatLogPath,
                    string.Join(Environment.NewLine, keep.TakeLast(ThreatLogKeepOnRotate)) + Environment.NewLine);
            }
        }
        catch
        {
            // best-effort
        }
    }

    /// <summary>Wipe the persisted threat log (the user clicked Clear threats).</summary>
    public void ClearThreatLog()
    {
        try
        {
            File.Delete(ThreatLogPath);
        }
        catch
        {
            // best-effort
        }
    }

    /// <summary>Most recent persisted threats, newest first, for seeding the UI after a restart.</summary>
    public IReadOnlyList<ThreatEvent> LoadRecentThreats(int max)
    {
        var result = new List<ThreatEvent>();
        try
        {
            if (!File.Exists(ThreatLogPath)) return result;
            foreach (var line in File.ReadAllLines(ThreatLogPath).TakeLast(max))
            {
                try
                {
                    var rec = JsonSerializer.Deserialize<ThreatRecord>(line, JsonOptions);
                    if (rec == null) continue;
                    result.Add(new ThreatEvent
                    {
                        Timestamp = rec.Time,
                        Type = Enum.TryParse<ThreatType>(rec.Type, out var type) ? type : ThreatType.NewRemoteHost,
                        Level = Enum.TryParse<ThreatLevel>(rec.Level, out var level) ? level : ThreatLevel.Info,
                        SourceIp = rec.Ip ?? "",
                        Title = rec.Title ?? "",
                        Detail = rec.Detail ?? "",
                        Origin = rec.Origin ?? "",
                        Method = rec.Method ?? ""
                    });
                }
                catch
                {
                    // skip corrupt line
                }
            }
        }
        catch
        {
            // best-effort
        }

        result.Reverse();
        return result;
    }

    private sealed class HistoryFile
    {
        [JsonPropertyName("hosts")]
        public Dictionary<string, HostRecord>? Hosts { get; set; }

        [JsonPropertyName("listeners")]
        public Dictionary<string, ListenerRecord>? Listeners { get; set; }
    }

    private sealed class HostRecord
    {
        [JsonPropertyName("first")]
        public DateTime FirstSeenUtc { get; set; }

        [JsonPropertyName("last")]
        public DateTime LastSeenUtc { get; set; }
    }

    private sealed class ListenerRecord
    {
        [JsonPropertyName("process")]
        public string Process { get; set; } = "";

        [JsonPropertyName("first")]
        public DateTime FirstSeenUtc { get; set; }
    }

    private sealed class ThreatRecord
    {
        [JsonPropertyName("time")]
        public DateTime Time { get; set; }

        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("level")]
        public string? Level { get; set; }

        [JsonPropertyName("ip")]
        public string? Ip { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("detail")]
        public string? Detail { get; set; }

        [JsonPropertyName("origin")]
        public string? Origin { get; set; }

        [JsonPropertyName("method")]
        public string? Method { get; set; }
    }
}
