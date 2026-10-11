using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    /// Meter bytes in/out from the adapter counters and keep the daily history
    /// behind the dashboard's data-flow charts. Unprivileged and cheap, so on by
    /// default; turning it off also stops the history file from growing.
    /// </summary>
    public bool TrafficMeterEnabled { get; set; } = true;

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
    /// Decide and report auto-blocks without writing firewall rules. The safe way to
    /// promote a new detection source (a fresh Suricata ruleset especially) from
    /// alerting to blocking: watch what it would have dropped before it drops anything.
    /// </summary>
    public bool PreventionDryRun { get; set; }

    /// <summary>
    /// Subscribe to kernel flow events (ETW, Microsoft-Windows-Kernel-Network) so the
    /// monitor samples the moment a flow appears instead of on the next timer tick.
    /// Needs Administrator; falls back to timed polling with no loss of function.
    /// </summary>
    public bool FlowEventsEnabled { get; set; } = true;

    /// <summary>
    /// Watch WireGuard peers via `wg show`. WireGuard's single unconnected UDP socket is
    /// invisible to the connection heuristics, so without this a VPN server has no view of
    /// who is connected. Needs Administrator.
    /// </summary>
    public bool WireGuardMonitorEnabled { get; set; }

    /// <summary>
    /// Megabytes sent to one WireGuard peer within 10 minutes before alerting (0 = off).
    /// Off by default — a VPN user streaming video legitimately moves gigabytes.
    /// </summary>
    public int WireGuardPeerMbPer10Min { get; set; }

    /// <summary>
    /// Watch DNS hygiene: plaintext queries leaving the host, encrypted DNS silently
    /// falling back to plaintext, queries to unapproved resolvers, VPN clients bypassing
    /// the resolver, and allowlisted domains resolving into unfamiliar networks.
    /// Driven by ETW flow events, so it needs Administrator.
    /// </summary>
    public bool DnsHygieneEnabled { get; set; }

    /// <summary>
    /// Comma-separated resolver IPs this host is meant to use. Queries anywhere else are
    /// flagged, and 443 traffic to these addresses is recognised as DoH (which is otherwise
    /// indistinguishable from ordinary HTTPS).
    /// </summary>
    public string DnsApprovedResolvers { get; set; } = "";

    /// <summary>
    /// Address of the filtering resolver's admin API — the AdGuard Home that
    /// <c>scripts/setup-dns-filter.ps1</c> installs, e.g. <c>http://10.8.0.1:3000</c>.
    /// Empty means no resolver is under this app's control, which is what the DNS
    /// filtering switch offers to fix rather than pretending to work. Setup fills
    /// this in; nothing else writes it except the operator typing an address.
    /// </summary>
    public string DnsFilterUrl { get; set; } = "";

    /// <summary>Admin user for the filtering resolver's API. Empty means it needs no auth.</summary>
    public string DnsFilterUsername { get; set; } = "";

    /// <summary>
    /// Admin password for the filtering resolver's API. Kept here for the same reason
    /// the DuckDNS token and the TLS key password are: the switch cannot work without
    /// being able to authenticate.
    ///
    /// Note the storage is not owner-only, as it is on the sibling POSIX build.
    /// <see cref="AppPaths"/> grants BUILTIN\Users Modify on %ProgramData%\NetworkSentinel
    /// so the desktop GUI, the TUI and the SYSTEM web service share one state, which
    /// means any local user can read this file. That is already true of every other
    /// secret here; it is written down because a resolver admin password is worth
    /// knowing that about.
    /// </summary>
    public string DnsFilterPassword { get; set; } = "";

    /// <summary>Ingest Suricata's EVE JSON alerts as threat events (payload inspection / signatures).</summary>
    public bool SuricataEnabled { get; set; }

    /// <summary>Path to Suricata's EVE JSON log.</summary>
    public string SuricataEvePath { get; set; } = SuricataService.DefaultEvePath;

    /// <summary>Highest Suricata severity number to accept — Suricata counts down, so 1 is most severe.</summary>
    public int SuricataMaxSeverity { get; set; } = 3;

    /// <summary>Comma-separated Suricata signature IDs to ignore (per-rule mute for false positives).</summary>
    public string SuricataIgnoredSids { get; set; } = "";

    /// <summary>
    /// Minutes before auto-created block rules expire (0 = never). An expired rule stops
    /// counting as blocking immediately; the netsh rule itself is dropped by the background
    /// sweep on its next pass.
    ///
    /// Defaults to 24 hours: a permanent default turned every misattributed block into an
    /// outage that lasted until someone noticed. Existing settings files keep whatever
    /// value they already hold, including 0.
    /// </summary>
    public int AutoBlockExpiryMinutes { get; set; } = 1440;

    /// <summary>
    /// Serve the web console over HTTPS in addition to HTTP. Needs <see cref="WebTlsCertPath"/>;
    /// endpoint changes only take effect when the web console restarts.
    /// </summary>
    public bool WebHttpsEnabled { get; set; }

    /// <summary>TCP port for the HTTPS endpoint. Ports below 1024 need elevation.</summary>
    public int WebHttpsPort { get; set; } = 18443;

    /// <summary>PEM fullchain (Let's Encrypt fullchain.cer) or a .pfx / .p12 bundle.</summary>
    public string WebTlsCertPath { get; set; } = "";

    /// <summary>PEM private key. Ignored for .pfx / .p12 certificates.</summary>
    public string WebTlsKeyPath { get; set; } = "";

    /// <summary>Password for a .pfx / .p12 certificate. Empty for PEM.</summary>
    public string WebTlsPfxPassword { get; set; } = "";

    /// <summary>
    /// Redirect plain-HTTP requests to HTTPS when the request arrived by hostname.
    /// Requests to a bare IP keep serving HTTP — the certificate only covers the name,
    /// so redirecting those would trade a working page for a certificate warning.
    /// </summary>
    public bool WebHttpsRedirect { get; set; } = true;

    /// <summary>
    /// Serve the web console over HTTPS only — don't bind the plain-HTTP listener, so the
    /// master password can never cross the wire in the clear. Honored only when
    /// <see cref="WebHttpsEnabled"/> is on and the certificate actually loads at startup;
    /// otherwise plain HTTP stays up so a bad certificate can't lock the console out.
    /// </summary>
    public bool WebHttpsOnly { get; set; }

    /// <summary>
    /// Address the Let's Encrypt account is registered against. Only read the first time
    /// Posh-ACME is set up; kept so a retry does not ask for it again. Not a credential.
    /// </summary>
    public string AcmeAccountEmail { get; set; } = "";

    /// <summary>
    /// Multiplier the desktop window's content is drawn at, on top of whatever Windows
    /// is already scaling by. Read through <see cref="GetUiScale"/>, which clamps — a
    /// hand-edited 12 here would draw one stat tile across the screen with no way back
    /// to the setting that did it.
    ///
    /// Defaults to 1.0, unlike the Linux build's 1.75. That number exists because a
    /// desktop session which does not scale leaves Avalonia rendering 9px labels on a
    /// 4K panel; app.manifest declares PerMonitorV2, so WPF is told the monitor's scale
    /// factor and has already applied it. This multiplies whatever Windows chose, so a
    /// default above 1.0 would compound with it — 175% here on a 150% display renders
    /// at ~260%. It is a preference knob, not a fix for an unreadable window.
    /// GUI only: the TUI is sized by the terminal and the web console by the browser.
    /// </summary>
    public double UiScale { get; set; } = DefaultUiScale;

    /// <summary>Windows already scales by monitor DPI, so the default adds nothing to it.</summary>
    public const double DefaultUiScale = 1.0;

    public const double MinUiScale = 1.0;
    public const double MaxUiScale = 2.5;

    /// <summary>UiScale, clamped, with a non-finite or out-of-range value falling back to the default.</summary>
    public double GetUiScale()
        => double.IsFinite(UiScale) ? Math.Clamp(UiScale, MinUiScale, MaxUiScale) : DefaultUiScale;

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

    /// <summary>
    /// Why settings.json could not be loaded, or null. The defaults are then in effect,
    /// and the defaults are not a safe stand-in for a console someone had locked down:
    /// HTTPS off (plain HTTP on every interface), geo lookups and the remote allowlist
    /// back on. The web console refuses to start on them; the GUI and TUI carry on.
    /// </summary>
    [JsonIgnore]
    public string? LoadError { get; private set; }

    /// <summary>
    /// Set when the damaged file could not be copied aside: saving would then overwrite
    /// the only copy of the operator's settings (TLS paths, the .pfx password, resolver
    /// credentials) with defaults.
    /// </summary>
    private bool _saveBlocked;

    public static AppSettings Load() => Load(SettingsPath);

    internal static AppSettings Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new AppSettings { _path = path };

            var json = File.ReadAllText(path);
            var settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
            settings.AutoBlockSuppressedUntil ??= new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            settings._path = path;
            return settings;
        }
        catch (Exception ex)
        {
            // A single hand-edit type error ("MonitorPollMs": "1000") used to discard the
            // whole file silently, and the next Save() overwrote it with defaults.
            var backup = $"{path}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}";
            var saved = false;
            try
            {
                // The web console exits on this, and its scheduled task starts it again:
                // one copy per distinct damaged file, not one per restart.
                var bytes = File.ReadAllBytes(path);
                var existing = Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + ".corrupt-*")
                    .FirstOrDefault(f => File.ReadAllBytes(f).AsSpan().SequenceEqual(bytes));
                if (existing != null)
                    backup = existing;
                else
                    File.Copy(path, backup, overwrite: false);
                saved = true;
            }
            catch
            {
                // Unreadable or no room: then nothing may overwrite the original either.
            }

            return new AppSettings
            {
                _path = path,
                _saveBlocked = !saved,
                LoadError = $"settings.json could not be loaded ({ex.Message}). " +
                            (saved
                                ? $"A copy was kept as {Path.GetFileName(backup)}. "
                                : "It was left untouched, and settings will not be saved over it. ") +
                            "Fix or remove settings.json, then start again."
            };
        }
    }

    private string? _path;

    public void Save()
    {
        if (_saveBlocked)
            return;
        try
        {
            // Owner-only like web-master.json and duckdns.json: settings.json can hold
            // the .pfx password and the webhook URL, which are secrets too.
            AppPaths.WriteAtomic(_path ?? SettingsPath, JsonSerializer.Serialize(this, JsonOptions),
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // best-effort persistence
        }
    }
}
