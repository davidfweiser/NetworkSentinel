using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// The shared service graph: monitor, firewall, allowlist, prevention, settings —
/// constructed, cross-wired, and disposed in ONE place.
///
/// Each frontend (GUI, TUI, web console) used to build this graph itself with a
/// copied ~40-line block, and the copies drifted exactly the way the auto-block
/// logic once did (see <see cref="PreventionService"/>'s header): the TUI never
/// disposed the allowlist, only the GUI applied the poll interval from settings,
/// and every new setting had to be wired three times to exist everywhere. The
/// frontends now own only what is genuinely theirs: event handlers, presentation,
/// and user interaction.
/// </summary>
public sealed class SentinelCore : IDisposable
{
    public AppSettings Settings { get; }
    public NetworkMonitorService Monitor { get; } = new();
    public FirewallService Firewall { get; } = new();
    public AllowlistService Allowlist { get; } = new();
    public PreventionService Prevention { get; }

    public SentinelCore(AppSettings? settings = null)
    {
        Settings = settings ?? AppSettings.Load();

        Prevention = new PreventionService(Firewall, Allowlist, Settings);
        // A persisted value outside the offered range (hand-edited settings.json)
        // must not silently arm auto-block at Low.
        if (Prevention.MinLevel is not (ThreatLevel.Medium or ThreatLevel.High or ThreatLevel.Critical))
            Prevention.MinLevel = ThreatLevel.High;

        Firewall.Allowlist = Allowlist;
        Firewall.AutoBlockExpiry = ExpiryMinutesToSpan(Settings.AutoBlockExpiryMinutes);
        Firewall.StartExpirySweep();

        Monitor.GeoLookupsEnabled = Settings.GeoLookupEnabled;
        Monitor.AuthMonitoringEnabled = Settings.AuthLogMonitorEnabled;
        Monitor.ProbeMonitoringEnabled = Settings.ProbeLogEnabled;
        Monitor.PollIntervalMs = Settings.MonitorPollMs;
        Monitor.ThreatIntelEnabled = Settings.ThreatIntelEnabled;
        Monitor.ProcessReputationEnabled = Settings.ProcessReputationEnabled;
        Monitor.NewListenerAlertsEnabled = Settings.NewListenerAlertsEnabled;
        Monitor.ArpWatchEnabled = Settings.ArpWatchEnabled;
        Monitor.PersistenceWatchEnabled = Settings.PersistenceWatchEnabled;
        Monitor.ExfilMonitorEnabled = Settings.ExfilMonitorEnabled;
        Monitor.ExfilThresholdMb = Settings.ExfilMbPer10Min;
        Monitor.HoneypotPorts = HoneypotService.ParsePorts(Settings.HoneypotPorts);
        Monitor.HoneypotEnabled = Settings.HoneypotEnabled;
        Monitor.ConntrackEventsEnabled = Settings.ConntrackEventsEnabled;
        Monitor.SuricataEvePath = Settings.SuricataEvePath;
        Monitor.SuricataMaxSeverity = Settings.SuricataMaxSeverity;
        Monitor.SuricataIgnoredSids = Settings.SuricataIgnoredSids;
        Monitor.SuricataEnabled = Settings.SuricataEnabled;
        Monitor.WireGuardPeerMbPer10Min = Settings.WireGuardPeerMbPer10Min;
        Monitor.WireGuardMonitorEnabled = Settings.WireGuardMonitorEnabled;
        Monitor.DnsApprovedResolvers = Settings.DnsApprovedResolvers;
        Monitor.DnsHygieneEnabled = Settings.DnsHygieneEnabled;
        Monitor.WebhookUrl = Settings.WebhookUrl;
        Monitor.WebhookMinLevel = Settings.GetWebhookMinLevel();

        // Lets the DNS monitor see every allowlist answer and catch poisoning of the never-block list.
        Allowlist.ResolutionObserver = Monitor.AllowlistResolutionObserver;
        Monitor.IsIpAllowlisted = ip => Allowlist.IsAllowed(ip, out _);
        // A WireGuard peer's public endpoint must never be auto-blocked — that kills the tunnel.
        Prevention.IsProtectedAddress = Monitor.IsWireGuardPeerEndpoint;

        // Root can re-install the probe-log rule silently; unprivileged runs wait
        // for the user to authorize elevation instead of failing at startup.
        if (Settings.ProbeLogEnabled && Firewall.IsRoot)
            _ = Task.Run(() => Firewall.EnableProbeLogging());

        Allowlist.UseRemoteFeed = Settings.AllowlistUseRemoteFeed;
    }

    /// <summary>0 (and anything negative) means auto-block rules never expire.</summary>
    public static TimeSpan? ExpiryMinutesToSpan(int minutes)
        => minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;

    public void Dispose()
    {
        Monitor.Dispose();
        Allowlist.Dispose();
    }
}
