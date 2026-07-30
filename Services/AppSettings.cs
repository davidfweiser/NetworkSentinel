using System.IO;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public bool AutoBlockEnabled { get; set; }
    public string AutoBlockMinLevel { get; set; } = nameof(ThreatLevel.High);
    public bool AutoBlockInbound { get; set; } = true;
    public bool AutoBlockOutbound { get; set; } = true;

    /// <summary>Geo lookups use a free web endpoint (HTTPS preferred); set false to disable.</summary>
    public bool GeoLookupEnabled { get; set; } = true;

    /// <summary>Watch system auth logs (journald / auth.log) for failed-logon bursts; set false to disable.</summary>
    public bool AuthLogMonitorEnabled { get; set; } = true;

    /// <summary>
    /// Detect scans of CLOSED ports via a firewall SYN-log rule + kernel log watch.
    /// Off by default because installing the rule needs firewall elevation (pkexec).
    /// </summary>
    public bool ProbeLogEnabled { get; set; }

    /// <summary>Refresh the allowlist from this repo's GitHub feed; set false to use only local/built-in lists.</summary>
    public bool AllowlistUseRemoteFeed { get; set; } = true;

    /// <summary>
    /// Actively warn when a Critical-level threat is detected: desktop notification
    /// in the GUI, tab-title badge + browser notification in the web console.
    /// </summary>
    public bool CriticalAlertsEnabled { get; set; } = true;

    /// <summary>
    /// Milliseconds between monitor polls (clamped to 500–10000 when applied).
    /// Doubles as the activity-chart sample rate.
    /// </summary>
    public int MonitorPollMs { get; set; } = NetworkMonitorService.DefaultPollIntervalMs;

    /// <summary>
    /// IPs the user manually unblocked/removed. Auto-block will not recreate rules for these
    /// until the UTC expiry (or the user blocks the IP again). Shared across GUI / TUI / web.
    /// </summary>
    public Dictionary<string, DateTime> AutoBlockSuppressedUntil { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public ThreatLevel GetMinLevel()
    {
        return Enum.TryParse<ThreatLevel>(AutoBlockMinLevel, true, out var level)
            ? level
            : ThreatLevel.High;
    }

    public void SetMinLevel(ThreatLevel level) => AutoBlockMinLevel = level.ToString();

    private static string SettingsPath
        => Path.Combine(AppPaths.DataDirectory, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            var path = SettingsPath;
            if (!File.Exists(path))
                return new AppSettings();

            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            settings.AutoBlockSuppressedUntil ??= new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        try
        {
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch
        {
            // best-effort persistence
        }
    }
}
