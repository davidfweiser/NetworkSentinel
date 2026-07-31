using System.IO;
using Microsoft.Win32;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the Windows persistence locations attackers use right after a
/// successful intrusion: the Startup folders, the Scheduled Tasks store, and
/// the Run / RunOnce / Winlogon registry keys. A new startup entry is how a
/// payload survives reboot, so the alert fires on creation and modification,
/// with removal logged at Info level.
///
/// Folders are event-driven (FileSystemWatcher). The registry cannot be
/// watched that way, so the Run keys are snapshotted at start and diffed on a
/// timer — the entries present when monitoring begins are the baseline and
/// never alert, only what changes afterwards does. Locations that need
/// elevation to read (HKLM, most of System32\Tasks) are simply skipped, which
/// is why an unelevated run reports fewer watched locations in
/// <see cref="Status"/>.
/// </summary>
public sealed class PersistenceWatcher : IDisposable
{
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RegistryPollInterval = TimeSpan.FromSeconds(30);

    /// <summary>Editor swap files, installer staging files and other write noise.</summary>
    private static readonly string[] IgnoredSuffixes =
    {
        "~", ".swp", ".tmp", ".temp", ".bak", ".log", ".partial", ".crdownload"
    };

    /// <summary>Entries this app installs itself — not an intrusion.</summary>
    private const string OwnNamePrefix = "networksentinel";

    /// <summary>
    /// Registry autostart locations. Both registry views of the HKLM keys are
    /// checked because a 32-bit installer writes to Wow6432Node and a 64-bit
    /// one does not, and an implant can use either. Winlogon is included for
    /// its Shell and Userinit values, the classic logon hijack.
    /// </summary>
    private static readonly (RegistryHive Hive, RegistryView View, string Path, string Scope)[] RegistryLocations =
    {
        (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Run",
            "a program that starts when you log in"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "a program that runs once at your next login"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\Run",
            "a program that starts for every user at boot"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"Software\Microsoft\Windows\CurrentVersion\Run",
            "a 32-bit program that starts for every user at boot"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "a program that runs once at the next boot"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "part of the Windows logon sequence")
    };

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, (DateTime Time, ThreatLevel Level)> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Dictionary<string, Dictionary<string, string>> _registryBaseline = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _registryTimer;
    private volatile string _status = "Startup-item watch not started";

    public string Status => _status;

    public void Start()
    {
        Stop();

        var locations = new List<(string Path, string Scope, bool Recurse)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                "one of your login items", false),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                "a login item for every user on this machine", false),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks"),
                "a scheduled task", true)
        };

        var watching = new List<string>();
        lock (_gate)
        {
            foreach (var (dir, scope, recurse) in locations)
            {
                try
                {
                    if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                    var w = new FileSystemWatcher(dir)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        IncludeSubdirectories = recurse
                    };
                    w.Created += (_, e) => OnChange(e.FullPath, scope, "created", ThreatLevel.High);
                    w.Changed += (_, e) => OnChange(e.FullPath, scope, "modified", ThreatLevel.Medium);
                    w.Renamed += (_, e) => OnChange(e.FullPath, scope, "created (renamed into place)", ThreatLevel.High);
                    w.Deleted += (_, e) => OnChange(e.FullPath, scope, "removed", ThreatLevel.Info);
                    w.EnableRaisingEvents = true;
                    _watchers.Add(w);
                    watching.Add(dir);
                }
                catch
                {
                    // unreadable (admin-only) or unwatchable directory — skip
                }
            }

            // Snapshot the registry autostart values as the baseline.
            int keys = 0;
            foreach (var location in RegistryLocations)
            {
                var key = LocationKey(location);
                var values = ReadRegistryValues(location);
                if (values == null) continue; // key absent or access denied
                _registryBaseline[key] = values;
                keys++;
            }

            if (keys > 0)
                _registryTimer = new Timer(_ => PollRegistry(), null, RegistryPollInterval, RegistryPollInterval);

            _status = watching.Count > 0 || keys > 0
                ? $"Watching {watching.Count} startup folders and {keys} registry autostart keys"
                : "Startup-item watch: no watchable locations found";
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            foreach (var w in _watchers)
            {
                try { w.Dispose(); } catch { /* ignore */ }
            }
            _watchers.Clear();

            _registryTimer?.Dispose();
            _registryTimer = null;
            _registryBaseline.Clear();
        }
        _status = "Startup-item watch stopped";
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

    private void OnChange(string path, string scope, string action, ThreatLevel level)
    {
        var file = Path.GetFileName(path);
        if (file.Length == 0) return;
        if (file.StartsWith(OwnNamePrefix, StringComparison.OrdinalIgnoreCase)) return;
        if (file.StartsWith('.')) return;
        if (IgnoredSuffixes.Any(s => file.EndsWith(s, StringComparison.OrdinalIgnoreCase))) return;
        // desktop.ini governs folder appearance, not what runs at startup.
        if (file.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) return;

        var now = DateTime.Now;
        lock (_gate)
        {
            // One alert per file per window: a single save fires several
            // filesystem events (create + write + attrib). A higher-severity
            // event still breaks through so "created" isn't hidden by the
            // "modified" that raced ahead of it.
            if (_lastEmit.TryGetValue(path, out var last) &&
                now - last.Time < CoalesceWindow && level <= last.Level)
                return;
            _lastEmit[path] = (now, level);

            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.PersistenceChange,
                Level = level,
                SourceIp = "127.0.0.1",
                Title = $"Startup item {action}: {file}",
                Detail = $"{path} was {action} — {scope}. If you did not just install or update software, " +
                         "inspect this entry: startup folders and scheduled tasks are the standard way malware " +
                         "persists across reboots.",
                Origin = "This computer",
                Method = "Startup folder / scheduled task watch"
            });

            TrimEmitHistory(now);
        }
    }

    /// <summary>
    /// Diffs each registry autostart key against its baseline and re-baselines
    /// so a given change alerts once. Keys that disappear or become unreadable
    /// between polls are left alone rather than reported as mass removals.
    /// </summary>
    private void PollRegistry()
    {
        try
        {
            var now = DateTime.Now;
            foreach (var location in RegistryLocations)
            {
                var key = LocationKey(location);
                var current = ReadRegistryValues(location);
                if (current == null) continue;

                lock (_gate)
                {
                    if (!_registryBaseline.TryGetValue(key, out var previous))
                    {
                        _registryBaseline[key] = current;
                        continue;
                    }

                    foreach (var (name, data) in current)
                    {
                        if (!previous.TryGetValue(name, out var old))
                            EmitRegistry(now, key, location.Scope, name, data, "created", ThreatLevel.High);
                        else if (!string.Equals(old, data, StringComparison.Ordinal))
                            EmitRegistry(now, key, location.Scope, name, data, "modified", ThreatLevel.High);
                    }

                    foreach (var (name, _) in previous)
                    {
                        if (!current.ContainsKey(name))
                            EmitRegistry(now, key, location.Scope, name, "", "removed", ThreatLevel.Info);
                    }

                    _registryBaseline[key] = current;
                }
            }
        }
        catch
        {
            // best-effort; the next tick tries again
        }
    }

    /// <summary>Caller holds the lock.</summary>
    private void EmitRegistry(DateTime now, string keyPath, string scope, string name, string data, string action, ThreatLevel level)
    {
        if (name.StartsWith(OwnNamePrefix, StringComparison.OrdinalIgnoreCase)) return;
        if (data.Contains(OwnNamePrefix, StringComparison.OrdinalIgnoreCase)) return;

        var emitKey = $"{keyPath}|{name}";
        if (_lastEmit.TryGetValue(emitKey, out var last) &&
            now - last.Time < CoalesceWindow && level <= last.Level)
            return;
        _lastEmit[emitKey] = (now, level);

        var target = data.Length > 0 ? $" It runs: {data}" : "";
        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.PersistenceChange,
            Level = level,
            SourceIp = "127.0.0.1",
            Title = $"Startup entry {action}: {name}",
            Detail = $"The registry value \"{name}\" under {keyPath} was {action} — {scope}.{target} " +
                     "If you did not just install or update software, inspect this entry: the Run keys are the " +
                     "most common way malware persists across reboots.",
            Origin = "This computer",
            Method = "Registry autostart key watch"
        });

        TrimEmitHistory(now);
    }

    /// <summary>Caller holds the lock.</summary>
    private void TrimEmitHistory(DateTime now)
    {
        if (_lastEmit.Count <= 500) return;
        foreach (var stale in _lastEmit.Where(kv => now - kv.Value.Time > CoalesceWindow)
                     .Select(kv => kv.Key).ToList())
        {
            _lastEmit.Remove(stale);
        }
    }

    private static string LocationKey((RegistryHive Hive, RegistryView View, string Path, string Scope) location)
    {
        var hive = location.Hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
        var view = location.View == RegistryView.Registry32 ? " (32-bit)" : "";
        return $@"{hive}\{location.Path}{view}";
    }

    /// <summary>Value name → data for one key, or null when it is absent or unreadable.</summary>
    private static Dictionary<string, string>? ReadRegistryValues(
        (RegistryHive Hive, RegistryView View, string Path, string Scope) location)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(location.Hive, location.View);
            using var key = baseKey.OpenSubKey(location.Path);
            if (key == null) return null;

            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in key.GetValueNames())
            {
                var value = key.GetValue(name);
                result[name] = value switch
                {
                    null => "",
                    string[] multi => string.Join(" | ", multi),
                    byte[] bytes => Convert.ToHexString(bytes),
                    _ => value.ToString() ?? ""
                };
            }
            return result;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose() => Stop();
}
