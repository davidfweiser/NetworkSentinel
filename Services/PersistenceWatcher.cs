using System.IO;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches the Linux persistence locations attackers use right after a
/// successful intrusion: systemd units (system and user), cron drop-in
/// directories, XDG autostart entries and the SysV init scripts. A new unit
/// or cron job is how a payload survives reboot, so the alert fires on
/// creation and modification, with removal logged at Info level.
///
/// Purely event-driven (FileSystemWatcher) — no baseline scan, no elevation.
/// Directories that need root to read are simply skipped, which is why
/// /var/spool/cron often does not appear in <see cref="Status"/> for an
/// unprivileged run.
/// </summary>
public sealed class PersistenceWatcher : IDisposable
{
    private static readonly TimeSpan CoalesceWindow = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Where to watch, what to tell the user it means, and whether the
    /// interesting activity happens in subdirectories too (enabling a systemd
    /// unit drops a symlink into <c>*.wants/</c>, which is the moment it starts
    /// running at boot).
    /// </summary>
    private static readonly (string Path, string Scope, bool Recurse)[] Locations =
    {
        ("/etc/systemd/system", "a system service (runs as root at boot)", true),
        ("/run/systemd/system", "a transient system service", true),
        ("/etc/cron.d", "a system cron job", false),
        ("/etc/cron.hourly", "an hourly system cron job", false),
        ("/etc/cron.daily", "a daily system cron job", false),
        ("/etc/cron.weekly", "a weekly system cron job", false),
        ("/etc/cron.monthly", "a monthly system cron job", false),
        ("/var/spool/cron", "a user crontab", true),
        ("/etc/init.d", "a SysV init script", false),
        ("/etc/xdg/autostart", "a desktop login item for all users", false)
    };

    /// <summary>Editor swap files, package-manager staging files and other write noise.</summary>
    private static readonly string[] IgnoredSuffixes =
    {
        "~", ".swp", ".swx", ".tmp", ".temp", ".bak",
        ".dpkg-new", ".dpkg-tmp", ".dpkg-old", ".dpkg-dist", ".rpmnew", ".rpmsave", ".ucf-new"
    };

    /// <summary>Units this app installs itself — not an intrusion.</summary>
    private const string OwnUnitPrefix = "networksentinel";

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, (DateTime Time, ThreatLevel Level)> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = new();
    private volatile string _status = "Startup-item watch not started";

    public string Status => _status;

    public void Start()
    {
        Stop();

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var configHome = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(home, ".config");

        var locations = Locations.Concat(new[]
        {
            (Path.Combine(configHome, "systemd", "user"), "one of your user services", true),
            (Path.Combine(configHome, "autostart"), "one of your desktop login items", false)
        }).ToList();

        var watching = new List<string>();
        lock (_gate)
        {
            foreach (var (dir, scope, recurse) in locations)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;
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
                    // unreadable (root-only) or unwatchable directory — skip
                }
            }
        }

        _status = watching.Count > 0
            ? $"Watching {watching.Count} startup-item folders (systemd / cron / autostart)"
            : "Startup-item watch: no watchable folders found";
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
        if (file.StartsWith(OwnUnitPrefix, StringComparison.OrdinalIgnoreCase)) return;
        if (file.StartsWith('.')) return; // .#lockfiles, editor temporaries
        if (IgnoredSuffixes.Any(s => file.EndsWith(s, StringComparison.OrdinalIgnoreCase))) return;

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
                         "inspect this file: services and cron jobs are the standard way malware persists " +
                         "across reboots.",
                Origin = "This computer",
                Method = "systemd / cron / autostart folder watch"
            });

            if (_lastEmit.Count > 500)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value.Time > CoalesceWindow)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    public void Dispose() => Stop();
}
