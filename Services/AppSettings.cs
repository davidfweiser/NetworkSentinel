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

    /// <summary>Watch the Windows Security event log for failed-logon bursts (4625); set false to disable.</summary>
    public bool AuthLogMonitorEnabled { get; set; } = true;

    /// <summary>
    /// Detect scans of CLOSED ports by watching the Windows Firewall dropped-packet log.
    /// Off by default because turning that logging on needs Administrator.
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

    /// <summary>Check remote IPs against public threat-intel blocklists (FireHOL level1, Spamhaus DROP).</summary>
    public bool ThreatIntelEnabled { get; set; } = true;

    /// <summary>Flag unsigned system binaries, fileless processes, suspicious install paths, and shell/script hosts with outbound connections.</summary>
    public bool ProcessReputationEnabled { get; set; } = true;

    /// <summary>Alert when a new port starts listening after baseline, or a known port changes owner process.</summary>
    public bool NewListenerAlertsEnabled { get; set; } = true;

    /// <summary>Watch the ARP table for gateway MAC changes (ARP spoofing / MITM).</summary>
    public bool ArpWatchEnabled { get; set; } = true;

    /// <summary>Watch Startup folders, Run keys and the Scheduled Tasks store for new or modified startup items.</summary>
    public bool PersistenceWatchEnabled { get; set; } = true;

    /// <summary>Sample per-connection byte counts (TCP ESTATS) and alert on large sustained outbound transfers.</summary>
    public bool ExfilMonitorEnabled { get; set; } = true;

    /// <summary>Outbound megabytes to a single uncommon public host within 10 minutes before alerting.</summary>
    public int ExfilMbPer10Min { get; set; } = 250;

    /// <summary>Listen on decoy ports; any completed connection is a Critical alert. Off by default (binds ports).</summary>
    public bool HoneypotEnabled { get; set; }

    /// <summary>Comma-separated decoy TCP ports for the honeypot.</summary>
    public string HoneypotPorts { get; set; } = "2323,3389,5900";

    /// <summary>
    /// Minutes before auto-created block rules expire (0 = never). An expired rule stops
    /// counting as blocking immediately; the netsh rule itself is dropped by the background
    /// sweep on its next pass.
    /// </summary>
    public int AutoBlockExpiryMinutes { get; set; }

    /// <summary>POST alerts to this webhook URL (ntfy / Slack / Discord / generic JSON). Empty = off.</summary>
    public string WebhookUrl { get; set; } = "";

    /// <summary>Minimum threat level that triggers the webhook.</summary>
    public string WebhookMinLevel { get; set; } = nameof(ThreatLevel.Critical);

    public ThreatLevel GetWebhookMinLevel()
        => Enum.TryParse<ThreatLevel>(WebhookMinLevel, true, out var level) ? level : ThreatLevel.Critical;

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
