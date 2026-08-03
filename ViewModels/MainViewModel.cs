using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly NetworkMonitorService _monitor = new();
    private readonly FirewallService _firewall = new();
    private readonly AllowlistService _allowlist = new();
    private readonly DesktopNotifier _notifier = new();
    private readonly DuckDnsUpdater _duckDns = new();
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _clockTimer;
    private readonly object _autoBlockGate = new();
    // Attempt markers expire so a failed auto-block can be retried later.
    private readonly Dictionary<string, DateTime> _autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    // After the user removes/unblocks a rule, do not auto-recreate it for a while.
    private readonly Dictionary<string, DateTime> _autoBlockSuppressedUntil = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan AutoBlockRetryAfter = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ManualUnblockSuppressFor = TimeSpan.FromHours(24);
    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _blockedIpsRefreshedAt = DateTime.MinValue;
    private bool _blockedIpsRefreshInFlight;
    private int _monitorRefreshQueued;
    private bool _suppressProbeLogHandler;

    [ObservableProperty] private string _clockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
    [ObservableProperty] private string _selectedNav = "Dashboard";
    [ObservableProperty] private bool _showDashboard = true;
    [ObservableProperty] private bool _showConnections;
    [ObservableProperty] private bool _showHosts;
    [ObservableProperty] private bool _showThreats;
    [ObservableProperty] private bool _showPorts;
    [ObservableProperty] private bool _showFirewall;
    [ObservableProperty] private bool _showSettings;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _heroSubtitle = "Watching local ports, remote peers, and break-in patterns in real time.";
    [ObservableProperty] private string _firewallStatusText = "";
    [ObservableProperty] private string _firewallMessage = "";
    [ObservableProperty] private string _autoBlockStatusText = "Auto-block is off.";
    [ObservableProperty] private string _allowlistStatusText = "Loading known-good allowlist…";
    [ObservableProperty] private string _allowlistInput = "";
    [ObservableProperty] private bool _isAdmin;
    [ObservableProperty] private bool _autoBlockEnabled;
    [ObservableProperty] private string _autoBlockMinLevel = nameof(ThreatLevel.High);
    [ObservableProperty] private string _manualBlockIp = "";
    [ObservableProperty] private string _manualBlockPort = "";
    [ObservableProperty] private string _manualBlockProtocol = "TCP";
    [ObservableProperty] private bool _blockInbound = true;
    [ObservableProperty] private bool _blockOutbound = true;
    [ObservableProperty] private FirewallRuleInfo? _selectedFirewallRule;
    [ObservableProperty] private AllowlistEntryView? _selectedAllowlistEntry;
    [ObservableProperty] private RemoteHost? _selectedHost;
    [ObservableProperty] private ThreatEvent? _selectedThreat;
    [ObservableProperty] private NetworkConnection? _selectedConnection;
    [ObservableProperty] private ListeningPort? _selectedPort;

    // ── Settings view (mirrors the web console's Settings tab) ─────────────────
    [ObservableProperty] private bool _geoLookupEnabled = true;
    [ObservableProperty] private bool _authLogMonitorEnabled = true;
    [ObservableProperty] private bool _probeLogEnabled;
    [ObservableProperty] private bool _allowlistUseRemoteFeed = true;
    [ObservableProperty] private bool _criticalAlertsEnabled = true;
    [ObservableProperty] private string _selectedMonitorPoll = "1.2 seconds (default)";
    [ObservableProperty] private string _authLogStatusText = "";
    [ObservableProperty] private string _probeLogStatusText = "";
    [ObservableProperty] private string _settingsMessage = "";
    [ObservableProperty] private bool _threatIntelEnabled = true;
    [ObservableProperty] private bool _processReputationEnabled = true;
    [ObservableProperty] private bool _newListenerAlertsEnabled = true;
    [ObservableProperty] private bool _arpWatchEnabled = true;
    [ObservableProperty] private bool _persistenceWatchEnabled = true;
    [ObservableProperty] private bool _exfilMonitorEnabled = true;
    [ObservableProperty] private string _exfilThresholdMbText = "250";
    [ObservableProperty] private bool _honeypotEnabled;
    [ObservableProperty] private string _honeypotPortsText = "2323,3389,5900";
    [ObservableProperty] private string _webhookUrl = "";
    [ObservableProperty] private string _selectedAutoBlockExpiry = "Never (permanent)";
    [ObservableProperty] private string _arpWatchStatusText = "";
    [ObservableProperty] private string _persistenceWatchStatusText = "";
    [ObservableProperty] private string _exfilStatusText = "";
    [ObservableProperty] private string _honeypotStatusText = "";
    [ObservableProperty] private string _webhookStatusText = "";

    // ── Remote access (web console HTTPS + DuckDNS) ────────────────────────────
    // These configure the headless console (`--web`); this GUI only edits and
    // persists them. The DuckDNS refresh does run here too, so the hostname stays
    // current whenever either front-end is open.
    [ObservableProperty] private bool _httpsEnabled;
    [ObservableProperty] private string _httpsPortText = "18443";
    [ObservableProperty] private string _tlsCertPath = "";
    [ObservableProperty] private string _tlsKeyPath = "";
    [ObservableProperty] private bool _httpsRedirect = true;
    [ObservableProperty] private bool _duckDnsEnabled;
    [ObservableProperty] private string _duckDnsDomain = "";
    [ObservableProperty] private string _duckDnsToken = "";
    [ObservableProperty] private string _remoteAccessStatus = "";

    /// <summary>Registered with Let's Encrypt the first time Posh-ACME is set up; unused after that.</summary>
    [ObservableProperty] private string _acmeEmail = "";

    /// <summary>True while the issuance script runs — disables the button and drives the spinner text.</summary>
    [ObservableProperty] private bool _isIssuingCertificate;

    /// <summary>Availability of the desktop notification channel (fixed at startup).</summary>
    public string CriticalAlertStatusText => _notifier.StatusText;

    // ── Activity chart legend (mirrors the web chart's legend row) ─────────────
    [ObservableProperty] private string _activityConnectionsText = "connections";
    [ObservableProperty] private string _activityThreatText = "threat detected (none in window)";
    [ObservableProperty] private string _activityFromText = "";
    [ObservableProperty] private string _activityToText = "";
    [ObservableProperty] private string _activityWindowText = "collecting…";

    public string AppVersion { get; } = FormatAppVersion();
    public string WindowTitle => $"Network Sentinel  ·  {AppVersion}";

    public string DataDirectoryText { get; } = AppPaths.DataDirectory;

    public DashboardStats Stats => _monitor.Stats;
    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    public ObservableCollection<ListeningPort> ListeningPorts { get; } = new();
    public ObservableCollection<RemoteHost> RemoteHosts { get; } = new();
    public ObservableCollection<ThreatEvent> Threats { get; } = new();
    public ObservableCollection<FirewallRuleInfo> FirewallRules { get; } = new();
    public ObservableCollection<AllowlistEntryView> AllowlistEntries { get; } = new();
    public ObservableCollection<double> ActivitySeries { get; } = new();
    public ObservableCollection<double> ThreatSeries { get; } = new();
    public ObservableCollection<string> ProtocolOptions { get; } = new() { "TCP", "UDP" };
    public ObservableCollection<string> MonitorPollOptions { get; } = new()
    {
        "0.5 seconds",
        "1.2 seconds (default)",
        "2.5 seconds",
        "5 seconds",
        "10 seconds"
    };
    public ObservableCollection<string> AutoBlockLevelOptions { get; } = new()
    {
        nameof(ThreatLevel.Medium),
        nameof(ThreatLevel.High),
        nameof(ThreatLevel.Critical)
    };
    public ObservableCollection<string> AutoBlockExpiryOptions { get; } = new()
    {
        "Never (permanent)",
        "1 hour",
        "6 hours",
        "24 hours",
        "7 days"
    };

    public MainViewModel()
    {
        _settings = AppSettings.Load();
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (!AutoBlockLevelOptions.Contains(_autoBlockMinLevel))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;

        // Assign backing fields, not properties: the generated setters would fire the
        // OnXChanged handlers below and re-save settings (or re-elevate) during startup.
        _geoLookupEnabled = _settings.GeoLookupEnabled;
        _authLogMonitorEnabled = _settings.AuthLogMonitorEnabled;
        _probeLogEnabled = _settings.ProbeLogEnabled;
        _allowlistUseRemoteFeed = _settings.AllowlistUseRemoteFeed;
        _criticalAlertsEnabled = _settings.CriticalAlertsEnabled;
        _selectedMonitorPoll = PollMsToLabel(_settings.MonitorPollMs);
        _threatIntelEnabled = _settings.ThreatIntelEnabled;
        _processReputationEnabled = _settings.ProcessReputationEnabled;
        _newListenerAlertsEnabled = _settings.NewListenerAlertsEnabled;
        _arpWatchEnabled = _settings.ArpWatchEnabled;
        _persistenceWatchEnabled = _settings.PersistenceWatchEnabled;
        _exfilMonitorEnabled = _settings.ExfilMonitorEnabled;
        _exfilThresholdMbText = _settings.ExfilMbPer10Min.ToString();
        _honeypotEnabled = _settings.HoneypotEnabled;
        _honeypotPortsText = _settings.HoneypotPorts;
        _webhookUrl = _settings.WebhookUrl;
        _selectedAutoBlockExpiry = ExpiryMinutesToLabel(_settings.AutoBlockExpiryMinutes);

        // Backing fields, not properties: assigning the property here would fire the
        // OnChanged handlers below and re-save settings during construction.
        _httpsEnabled = _settings.WebHttpsEnabled;
        _httpsPortText = _settings.WebHttpsPort.ToString();
        _tlsCertPath = _settings.WebTlsCertPath;
        _tlsKeyPath = _settings.WebTlsKeyPath;
        _httpsRedirect = _settings.WebHttpsRedirect;
        _duckDnsEnabled = _duckDns.Config.Enabled;
        _duckDnsDomain = _duckDns.Config.Domain;
        _duckDnsToken = _duckDns.Config.Token;
        _acmeEmail = _settings.AcmeAccountEmail;
        if (_duckDns.Config.IsUsable)
            _duckDns.Start();
        _remoteAccessStatus = BuildRemoteAccessStatus();

        _firewall.Allowlist = _allowlist;
        _firewall.AutoBlockExpiry = ExpiryMinutesToSpan(_settings.AutoBlockExpiryMinutes);
        _firewall.StartExpirySweep();
        _monitor.GeoLookupsEnabled = _settings.GeoLookupEnabled;
        _monitor.AuthMonitoringEnabled = _settings.AuthLogMonitorEnabled;
        _monitor.ProbeMonitoringEnabled = _settings.ProbeLogEnabled;
        _monitor.PollIntervalMs = _settings.MonitorPollMs;
        _monitor.ThreatIntelEnabled = _settings.ThreatIntelEnabled;
        _monitor.ProcessReputationEnabled = _settings.ProcessReputationEnabled;
        _monitor.NewListenerAlertsEnabled = _settings.NewListenerAlertsEnabled;
        _monitor.ArpWatchEnabled = _settings.ArpWatchEnabled;
        _monitor.PersistenceWatchEnabled = _settings.PersistenceWatchEnabled;
        _monitor.ExfilMonitorEnabled = _settings.ExfilMonitorEnabled;
        _monitor.ExfilThresholdMb = _settings.ExfilMbPer10Min;
        _monitor.HoneypotPorts = HoneypotService.ParsePorts(_settings.HoneypotPorts);
        _monitor.HoneypotEnabled = _settings.HoneypotEnabled;
        _monitor.WebhookUrl = _settings.WebhookUrl;
        _monitor.WebhookMinLevel = _settings.GetWebhookMinLevel();
        _monitor.IsIpAllowlisted = ip => _allowlist.IsAllowed(ip, out _);
        if (_settings.ProbeLogEnabled && _firewall.IsAdministrator)
            _ = Task.Run(() => _firewall.EnableProbeLogging());
        _allowlist.UseRemoteFeed = _settings.AllowlistUseRemoteFeed;
        LoadPersistedAutoBlockSuppressions();
        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
        _monitor.Start();

        IsAdmin = _firewall.IsAdministrator;
        FirewallStatusText = _firewall.PrivilegeText;
        UpdateAutoBlockStatusText();
        RefreshFirewallRules();
        _ = InitializeAllowlistAsync();

        _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clockTimer.Tick += (_, _) =>
        {
            ClockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
            // The DuckDNS half of this updates on its own schedule, so poll the
            // cached parts rather than leaving a stale "refreshing…" on screen.
            if (ShowSettings)
                RefreshRemoteAccessStatus();
        };
        _clockTimer.Start();
        RefreshMonitorStatusText();
    }

    private async Task InitializeAllowlistAsync()
    {
        try
        {
            await _allowlist.InitializeAsync();
            await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                SyncAllowlistUi();
                // Recovery: free any known-good IPs that were blocked before allowlist existed
                if (IsAdmin)
                {
                    var restored = _firewall.UnblockAllowlistedAddresses();
                    if (restored.Success && !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                    {
                        FirewallMessage = restored.Message;
                        RefreshFirewallRules();
                    }
                }
            });
        }
        catch (Exception ex)
        {
            await Application.Current.Dispatcher.InvokeAsync(() =>
                AllowlistStatusText = $"Allowlist load error: {ex.Message}");
        }
    }

    private void SyncAllowlistUi()
    {
        AllowlistEntries.Clear();
        foreach (var e in _allowlist.GetEntries())
            AllowlistEntries.Add(e);
        AllowlistStatusText = _allowlist.StatusText;
    }

    private void OnMonitorUpdated()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null) return;

        if (dispatcher.CheckAccess())
        {
            RefreshCollections();
            return;
        }

        // BeginInvoke (not Invoke) so the monitor thread never stalls behind
        // the UI, with coalescing so refreshes don't pile up in the queue.
        if (System.Threading.Interlocked.CompareExchange(ref _monitorRefreshQueued, 1, 0) != 0)
            return;

        dispatcher.BeginInvoke(() =>
        {
            System.Threading.Interlocked.Exchange(ref _monitorRefreshQueued, 0);
            RefreshCollections();
        }, DispatcherPriority.Background);
    }

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (threats.Count == 0)
            return;

        if (CriticalAlertsEnabled)
        {
            var critical = threats.Where(t => t.Level >= ThreatLevel.Critical).ToList();
            if (critical.Count > 0)
                _ = Task.Run(() => _notifier.NotifyCritical(critical));
        }

        if (!AutoBlockEnabled)
            return;

        // Run auto-block on the thread pool — firewall COM/netsh calls must
        // not stall the monitor's polling loop.
        _ = Task.Run(() =>
        {
            try
            {
                ProcessAutoBlocks(threats);
            }
            catch (Exception ex)
            {
                var dispatcher = Application.Current?.Dispatcher;
                dispatcher?.BeginInvoke(() =>
                {
                    FirewallMessage = $"Auto-block error: {ex.Message}";
                    UpdateAutoBlockStatusText();
                });
            }
        });
    }

    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        if (!AutoBlockEnabled)
            return;

        if (!_firewall.IsAdministrator)
        {
            var d = Application.Current?.Dispatcher;
            d?.BeginInvoke(() =>
            {
                AutoBlockStatusText = "Auto-block is ON, but Administrator rights are required — click Run as Admin.";
                FirewallMessage = "Auto-block skipped: not running as Administrator.";
            });
            return;
        }

        var minLevel = ParseMinLevel(AutoBlockMinLevel);
        var direction = ResolveDirection();
        var messages = new List<string>();

        foreach (var threat in threats)
        {
            if (threat.Level < minLevel)
                continue;

            // Never auto-block mere first-seen noise.
            if (threat.Type == ThreatType.NewRemoteHost)
                continue;

            if (!FirewallService.TryNormalizeIp(threat.SourceIp, out var ip, out _))
                continue;

            if (FirewallService.IsPrivateOrLocal(ip))
                continue;

            // Never auto-block known-good services (GitHub, Grok/xAI, Microsoft, …)
            if (_allowlist.IsAllowed(ip, out _))
                continue;

            lock (_autoBlockGate)
            {
                // Use the cached blocked set — enumerating firewall rules per
                // threat (IsIpBlocked) is far too slow for this path.
                if (_blockedIps.Contains(ip))
                    continue;
                if (_autoBlockSuppressedUntil.TryGetValue(ip, out var until) && DateTime.UtcNow < until)
                    continue;
                if (_autoBlockAttempted.TryGetValue(ip, out var lastAttempt) &&
                    DateTime.UtcNow - lastAttempt < AutoBlockRetryAfter)
                    continue;
                _autoBlockAttempted[ip] = DateTime.UtcNow;
            }

            var reason = $"Auto-block · {threat.LevelText} · {threat.TypeText}: {threat.Title}";
            var result = _firewall.BlockIp(ip, direction, reason, expiresAfter: _firewall.AutoBlockExpiry);
            if (result.Success)
            {
                lock (_autoBlockGate) _blockedIps.Add(ip);
                messages.Add($"Auto-blocked {ip} ({threat.LevelText}: {threat.Title})");
            }
            else
            {
                messages.Add($"Auto-block failed for {ip}: {result.Message}");
                lock (_autoBlockGate) _autoBlockAttempted.Remove(ip);
            }
        }

        if (messages.Count == 0)
            return;

        var dispatcher = Application.Current?.Dispatcher;
        dispatcher?.BeginInvoke(() =>
        {
            FirewallMessage = string.Join(" · ", messages);
            UpdateAutoBlockStatusText();
            RefreshFirewallRules();
            RefreshCollections();
        });
    }

    private void RefreshCollections()
    {
        // Blocked set refreshes on a background thread at most every 15s —
        // enumerating all firewall rules on the UI thread each tick froze the UI.
        RefreshBlockedIpsInBackground();

        foreach (var host in _monitor.RemoteHosts)
            host.IsBlocked = _blockedIps.Contains(host.IpAddress);

        Sync(Connections, FilterConnections(_monitor.Connections));
        Sync(ListeningPorts, _monitor.ListeningPorts);
        Sync(RemoteHosts, FilterHosts(_monitor.RemoteHosts));
        Sync(Threats, FilterThreats(_monitor.Threats));

        var activity = _monitor.Activity;
        ActivitySeries.Clear();
        ThreatSeries.Clear();
        foreach (var sample in activity)
        {
            ActivitySeries.Add(sample.ConnectionCount);
            ThreatSeries.Add(sample.ThreatCount);
        }
        UpdateActivityLegend(activity);

        var high = Stats.HighThreats;
        var blocked = _blockedIps.Count;
        var auto = AutoBlockEnabled ? $"Auto-block ON (≥{AutoBlockMinLevel})" : "Auto-block OFF";
        HeroSubtitle = high > 0
            ? $"{high} high/critical · {blocked} blocked · {auto}"
            : $"{blocked} IPs blocked · {auto}";
    }

    /// <summary>
    /// Fills the chart legend the way the web console does: current and peak
    /// connection counts, total alerts in the window, and the window's time range.
    /// </summary>
    private void UpdateActivityLegend(IReadOnlyList<ActivitySample> activity)
    {
        if (activity.Count < 2)
        {
            ActivityConnectionsText = "connections";
            ActivityThreatText = "threat detected (none in window)";
            ActivityFromText = "";
            ActivityToText = "";
            ActivityWindowText = "collecting…";
            return;
        }

        var first = activity[0];
        var last = activity[^1];
        var peak = activity.Max(a => a.ConnectionCount);
        var threatTotal = activity.Sum(a => a.ThreatCount);
        var span = last.Time - first.Time;

        ActivityConnectionsText = $"connections (now {last.ConnectionCount}, peak {peak})";
        ActivityThreatText = threatTotal > 0
            ? $"threat detected ({threatTotal} in window)"
            : "threat detected (none in window)";
        ActivityFromText = first.Time.ToString("HH:mm:ss");
        ActivityToText = last.Time.ToString("HH:mm:ss");
        // The span is derived, not assumed: a slower poll interval widens it.
        ActivityWindowText = span.TotalMinutes >= 1
            ? $"last {Math.Round(span.TotalMinutes)} min"
            : $"last {Math.Max(1, (int)span.TotalSeconds)} s";
    }

    private void RefreshBlockedIpsInBackground(bool force = false)
    {
        if (_blockedIpsRefreshInFlight)
            return;
        if (!force && DateTime.UtcNow - _blockedIpsRefreshedAt < TimeSpan.FromSeconds(15))
            return;

        _blockedIpsRefreshInFlight = true;
        _ = Task.Run(() =>
        {
            HashSet<string>? set = null;
            try { set = _firewall.GetBlockedIps(); }
            catch { /* keep previous set */ }

            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher == null)
            {
                _blockedIpsRefreshInFlight = false;
                return;
            }

            dispatcher.BeginInvoke(() =>
            {
                _blockedIpsRefreshInFlight = false;
                _blockedIpsRefreshedAt = DateTime.UtcNow;
                if (set == null) return;
                _blockedIps = set;
                foreach (var host in _monitor.RemoteHosts)
                    host.IsBlocked = _blockedIps.Contains(host.IpAddress);
            });
        });
    }

    private static ThreatLevel ParseMinLevel(string value)
        => Enum.TryParse<ThreatLevel>(value, true, out var level) ? level : ThreatLevel.High;

    private void UpdateAutoBlockStatusText()
    {
        if (!AutoBlockEnabled)
        {
            AutoBlockStatusText = "Auto-block is off. Threats are logged only; nothing is blocked automatically.";
            return;
        }

        if (!IsAdmin)
        {
            AutoBlockStatusText = $"Auto-block is ON (≥ {AutoBlockMinLevel}), but you must Run as Admin for rules to apply.";
            return;
        }

        AutoBlockStatusText =
            $"Auto-block is ON — public IPs at {AutoBlockMinLevel}+ severity are blocked in Windows Firewall " +
            $"({(BlockInbound ? "in" : "")}{(BlockInbound && BlockOutbound ? "+" : "")}{(BlockOutbound ? "out" : "")}).";
    }

    private void PersistSettings()
    {
        _settings.AutoBlockEnabled = AutoBlockEnabled;
        _settings.AutoBlockMinLevel = AutoBlockMinLevel;
        _settings.AutoBlockInbound = BlockInbound;
        _settings.AutoBlockOutbound = BlockOutbound;
        _settings.Save();
        UpdateAutoBlockStatusText();
    }

    partial void OnAutoBlockEnabledChanged(bool value)
    {
        PersistSettings();
        if (value && !IsAdmin)
        {
            FirewallMessage = "Auto-block enabled, but Administrator rights are required to create firewall rules.";
        }
        else if (value)
        {
            FirewallMessage = $"Auto-block enabled for {AutoBlockMinLevel}+ threats.";
        }
        else
        {
            FirewallMessage = "Auto-block disabled.";
        }
    }

    partial void OnAutoBlockMinLevelChanged(string value) => PersistSettings();
    partial void OnBlockInboundChanged(bool value) => PersistSettings();
    partial void OnBlockOutboundChanged(bool value) => PersistSettings();

    private IEnumerable<NetworkConnection> FilterConnections(IReadOnlyList<NetworkConnection> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(c =>
            c.DisplayLocal.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.DisplayRemote.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.StateText.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private IEnumerable<RemoteHost> FilterHosts(IReadOnlyList<RemoteHost> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(h =>
            h.IpAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.HostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.Status.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.BlockStatusText.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    private IEnumerable<ThreatEvent> FilterThreats(IReadOnlyList<ThreatEvent> source)
    {
        if (string.IsNullOrWhiteSpace(SearchText)) return source;
        var q = SearchText.Trim();
        return source.Where(t =>
            t.SourceIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Detail.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Origin.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Method.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// In-place diff against the target collection instead of Clear()+re-add.
    /// The monitor hands out stable object instances, so removing the missing
    /// and moving/inserting the rest preserves selection and scroll position.
    /// </summary>
    private static void Sync<T>(ObservableCollection<T> target, IEnumerable<T> source) where T : class
    {
        var list = source.ToList();
        var wanted = new HashSet<T>(list);

        for (int i = target.Count - 1; i >= 0; i--)
        {
            if (!wanted.Contains(target[i]))
                target.RemoveAt(i);
        }

        for (int i = 0; i < list.Count; i++)
        {
            var item = list[i];
            int currentIndex = target.IndexOf(item);
            if (currentIndex == i) continue;
            if (currentIndex >= 0)
                target.Move(currentIndex, i);
            else
                target.Insert(i, item);
        }
    }

    partial void OnSearchTextChanged(string value) => RefreshCollections();

    [RelayCommand]
    private void Navigate(string? page)
    {
        SelectedNav = page ?? "Dashboard";
        ShowDashboard = SelectedNav == "Dashboard";
        ShowConnections = SelectedNav == "Connections";
        ShowHosts = SelectedNav == "Hosts";
        ShowThreats = SelectedNav == "Threats";
        ShowPorts = SelectedNav == "Ports";
        ShowFirewall = SelectedNav == "Firewall";
        ShowSettings = SelectedNav == "Settings";

        if (ShowFirewall)
            RefreshFirewallRules();
        if (ShowSettings)
            RefreshMonitorStatusText();
    }

    // ── Settings handlers ─────────────────────────────────────────────────────
    // Each mirrors the equivalent set_setting case in the web console so the two
    // front-ends produce identical state in settings.json.

    partial void OnGeoLookupEnabledChanged(bool value)
    {
        _monitor.GeoLookupsEnabled = value;
        _settings.GeoLookupEnabled = value;
        _settings.Save();
        SettingsMessage = $"Geo lookups: {(value ? "on" : "off")}";
    }

    partial void OnAuthLogMonitorEnabledChanged(bool value)
    {
        _monitor.AuthMonitoringEnabled = value;
        _settings.AuthLogMonitorEnabled = value;
        _settings.Save();
        RefreshMonitorStatusText();
        SettingsMessage = value
            ? $"Failed-logon monitoring: on ({_monitor.AuthLogStatus})"
            : "Failed-logon monitoring: off";
    }

    partial void OnProbeLogEnabledChanged(bool value)
    {
        // Set while reverting the toggle after a failed logging change, so the revert
        // doesn't re-enter this handler and try to undo itself.
        if (_suppressProbeLogHandler) return;

        _settings.ProbeLogEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? "Turning on Windows Firewall dropped-packet logging…"
            : "Turning off Windows Firewall dropped-packet logging…";

        // Changing firewall logging shells out to netsh, so keep it off the UI thread.
        _ = Task.Run(() =>
        {
            var result = value ? _firewall.EnableProbeLogging() : _firewall.DisableProbeLogging();
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher == null) return;

            dispatcher.BeginInvoke(() =>
            {
                _monitor.ProbeMonitoringEnabled = value && result.Success;
                if (value && !result.Success)
                {
                    // Logging could not be turned on (usually not elevated) — don't
                    // leave the toggle claiming a detection that isn't running.
                    _settings.ProbeLogEnabled = false;
                    _settings.Save();
                    _suppressProbeLogHandler = true;
                    try { ProbeLogEnabled = false; }
                    finally { _suppressProbeLogHandler = false; }
                    SettingsMessage = $"Closed-port scan detection: could not change firewall logging — {result.Message}";
                }
                else
                {
                    SettingsMessage = value
                        ? "Closed-port scan detection: on (firewall dropped-packet logging enabled)"
                        : "Closed-port scan detection: off";
                }
                RefreshMonitorStatusText();
            });
        });
    }

    partial void OnCriticalAlertsEnabledChanged(bool value)
    {
        _settings.CriticalAlertsEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Critical threat alerts: on — {_notifier.StatusText}"
            : "Critical threat alerts: off";
    }

    partial void OnAllowlistUseRemoteFeedChanged(bool value)
    {
        _allowlist.UseRemoteFeed = value;
        _settings.AllowlistUseRemoteFeed = value;
        _settings.Save();
        SettingsMessage = $"Allowlist remote feed: {(value ? "on" : "off")}";
    }

    partial void OnSelectedMonitorPollChanged(string value)
    {
        var ms = PollLabelToMs(value);
        _monitor.PollIntervalMs = ms;
        _settings.MonitorPollMs = ms;
        _settings.Save();
        SettingsMessage = $"Monitor poll interval: {value}";
    }

    partial void OnThreatIntelEnabledChanged(bool value)
    {
        _monitor.ThreatIntelEnabled = value;
        _settings.ThreatIntelEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Threat-intel feeds: on ({_monitor.ThreatIntelStatus})"
            : "Threat-intel feeds: off";
    }

    partial void OnProcessReputationEnabledChanged(bool value)
    {
        _monitor.ProcessReputationEnabled = value;
        _settings.ProcessReputationEnabled = value;
        _settings.Save();
        SettingsMessage = $"Process reputation checks: {(value ? "on" : "off")}";
    }

    partial void OnNewListenerAlertsEnabledChanged(bool value)
    {
        _monitor.NewListenerAlertsEnabled = value;
        _settings.NewListenerAlertsEnabled = value;
        _settings.Save();
        SettingsMessage = $"New-listener alerts: {(value ? "on" : "off")}";
    }

    partial void OnArpWatchEnabledChanged(bool value)
    {
        _monitor.ArpWatchEnabled = value;
        _settings.ArpWatchEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"ARP / gateway watch: on ({_monitor.ArpWatchStatus})"
            : "ARP / gateway watch: off";
    }

    partial void OnPersistenceWatchEnabledChanged(bool value)
    {
        _monitor.PersistenceWatchEnabled = value;
        _settings.PersistenceWatchEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Startup-item watch: on ({_monitor.PersistenceWatchStatus})"
            : "Startup-item watch: off";
    }

    partial void OnExfilMonitorEnabledChanged(bool value)
    {
        _monitor.ExfilMonitorEnabled = value;
        _settings.ExfilMonitorEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Exfiltration monitor: on ({_monitor.ExfilStatus})"
            : "Exfiltration monitor: off";
    }

    partial void OnExfilThresholdMbTextChanged(string value)
    {
        if (!int.TryParse(value?.Trim(), out var mb) || mb < 10)
        {
            SettingsMessage = "Exfiltration threshold must be a number ≥ 10 (MB per 10 minutes).";
            return;
        }

        _monitor.ExfilThresholdMb = mb;
        _settings.ExfilMbPer10Min = mb;
        _settings.Save();
        SettingsMessage = $"Exfiltration alert threshold: {mb} MB / 10 min";
    }

    // ── Remote access (web console HTTPS + DuckDNS) ────────────────────────────

    partial void OnHttpsEnabledChanged(bool value)
    {
        if (value && string.IsNullOrWhiteSpace(TlsCertPath))
        {
            SettingsMessage = @"Choose a certificate first — run scripts\issue-duckdns-cert.ps1 to get one.";
            HttpsEnabled = false;
            return;
        }

        _settings.WebHttpsEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? $"Web console HTTPS enabled on port {_settings.WebHttpsPort} — restart the web console to apply."
            : "Web console HTTPS disabled — restart the web console to apply.";
        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnHttpsPortTextChanged(string value)
    {
        if (!int.TryParse(value?.Trim(), out var port) || port is < 1 or > 65535)
        {
            SettingsMessage = "HTTPS port must be a number between 1 and 65535.";
            return;
        }

        _settings.WebHttpsPort = port;
        _settings.Save();
        SettingsMessage = $"Web console HTTPS port set to {port} — restart the web console to apply.";
        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnTlsCertPathChanged(string value) => ApplyTlsPath(certChanged: true, value);

    partial void OnTlsKeyPathChanged(string value) => ApplyTlsPath(certChanged: false, value);

    private void ApplyTlsPath(bool certChanged, string value)
    {
        var path = value?.Trim() ?? "";
        if (path.Length > 0 && !File.Exists(path))
        {
            SettingsMessage = $"File not found: {path}";
            return;
        }

        if (certChanged) _settings.WebTlsCertPath = path;
        else _settings.WebTlsKeyPath = path;
        _settings.Save();

        if (_settings.WebTlsCertPath.Length == 0)
        {
            SettingsMessage = "Certificate cleared — the web console cannot serve HTTPS without one.";
            RefreshRemoteAccessStatus(reloadCertificate: true);
            return;
        }

        // Validate now rather than at the next console start, where a bad path
        // means no console at all.
        if (TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
                _settings.WebTlsPfxPassword, out var cert, out var error))
        {
            SettingsMessage = $"Certificate OK — expires {cert!.NotAfter:yyyy-MM-dd}. " +
                              "Restart the web console to apply.";
            cert.Dispose();
        }
        else
        {
            SettingsMessage = $"Saved, but the certificate cannot be loaded yet: {error}";
        }

        RefreshRemoteAccessStatus(reloadCertificate: true);
    }

    partial void OnHttpsRedirectChanged(bool value)
    {
        _settings.WebHttpsRedirect = value;
        _settings.Save();
        SettingsMessage = value
            ? "Plain-HTTP requests that arrive by hostname will redirect to HTTPS."
            : "HTTP requests are served as-is (no HTTPS redirect).";
    }

    partial void OnDuckDnsEnabledChanged(bool value)
    {
        if (value && (DuckDnsDomain.Trim().Length == 0 || DuckDnsToken.Trim().Length == 0))
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token first.";
            DuckDnsEnabled = false;
            return;
        }

        SettingsMessage = ApplyDuckDns();
    }

    partial void OnAcmeEmailChanged(string value)
    {
        _settings.AcmeAccountEmail = value.Trim();
        _settings.Save();
    }

    partial void OnDuckDnsDomainChanged(string value) => SettingsMessage = ApplyDuckDns();

    partial void OnDuckDnsTokenChanged(string value) => SettingsMessage = ApplyDuckDns();

    private string ApplyDuckDns()
    {
        var status = _duckDns.Apply(new DuckDnsConfig
        {
            Enabled = DuckDnsEnabled,
            Domain = DuckDnsUpdater.NormalizeDomain(DuckDnsDomain),
            Token = DuckDnsToken.Trim(),
            IntervalMinutes = _duckDns.Config.IntervalMinutes
        });

        RefreshRemoteAccessStatus();
        return status;
    }

    /// <summary>Refresh the DuckDNS record immediately instead of waiting for the next cycle.</summary>
    [RelayCommand]
    private async Task UpdateDuckDnsNowAsync()
    {
        if (!_duckDns.Config.IsUsable)
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token, then switch DuckDNS on.";
            return;
        }

        SettingsMessage = "Updating DuckDNS…";
        await _duckDns.UpdateOnceAsync();
        SettingsMessage = _duckDns.Status;
        RefreshRemoteAccessStatus();
    }

    /// <summary>
    /// Issue a Let's Encrypt certificate for the saved DuckDNS name by running
    /// scripts\issue-duckdns-cert.ps1, then point the console at what it produced.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIssueCertificate))]
    private async Task IssueCertificateAsync()
    {
        var domain = DuckDnsUpdater.NormalizeDomain(DuckDnsDomain);
        if (domain.Length == 0 || DuckDnsToken.Trim().Length == 0)
        {
            SettingsMessage = "Enter the DuckDNS subdomain and token first — issuance proves control through them.";
            return;
        }

        // The token is masked in the UI; the real one lives in duckdns.json.
        var token = _duckDns.Config.Token;
        if (token.Length == 0)
        {
            SettingsMessage = "No DuckDNS token saved yet — enter one first.";
            return;
        }

        IsIssuingCertificate = true;
        IssueCertificateCommand.NotifyCanExecuteChanged();
        SettingsMessage = $"Issuing a certificate for {domain}.duckdns.org — this waits on DNS propagation and can take a few minutes…";

        try
        {
            var result = await CertIssuanceService.IssueAsync(domain, token, AcmeEmail);
            _lastIssuanceOutput = result.Output;

            if (result.Success)
            {
                // Fill the paths in for the user; both fields stay editable.
                TlsCertPath = result.CertPath;
                if (result.KeyPath.Length > 0)
                    TlsKeyPath = result.KeyPath;

                SettingsMessage = $"{result.Message} Paths filled in below — switch HTTPS on, then restart the web console.";
            }
            else
            {
                SettingsMessage = result.Message;
            }
        }
        finally
        {
            IsIssuingCertificate = false;
            IssueCertificateCommand.NotifyCanExecuteChanged();
            RefreshRemoteAccessStatus(reloadCertificate: true);
        }
    }

    private bool CanIssueCertificate() => !IsIssuingCertificate;

    /// <summary>Full output of the last issuance, so a failure can be inspected.</summary>
    private string _lastIssuanceOutput = "";

    /// <summary>
    /// Cached HTTPS half of the remote-access status. Reading and parsing the certificate
    /// is far too expensive to redo on the one-second clock tick, and it only changes when
    /// one of these settings does.
    /// </summary>
    private string _httpsStatusPart = "";

    private void RefreshRemoteAccessStatus(bool reloadCertificate = false)
    {
        if (reloadCertificate || _httpsStatusPart.Length == 0)
            _httpsStatusPart = BuildHttpsStatusPart();

        var parts = new List<string> { _httpsStatusPart, _duckDns.Status };
        if (_duckDns.Config.IsUsable && _settings.WebHttpsEnabled)
            parts.Add($"Console URL: https://{_duckDns.Hostname}:{_settings.WebHttpsPort}/");

        var text = string.Join("  ·  ", parts);
        if (text != RemoteAccessStatus)
            RemoteAccessStatus = text;
    }

    private string BuildHttpsStatusPart()
    {
        if (!_settings.WebHttpsEnabled)
            return "HTTPS off — the web console serves plain HTTP only.";

        if (TlsCertificateProvider.TryLoad(_settings.WebTlsCertPath, _settings.WebTlsKeyPath,
                _settings.WebTlsPfxPassword, out var cert, out var error))
        {
            var text = $"HTTPS ready on port {_settings.WebHttpsPort} — certificate expires {cert!.NotAfter:yyyy-MM-dd}.";
            cert.Dispose();
            return text;
        }

        return $"HTTPS enabled but the certificate cannot be loaded: {error}";
    }

    private string BuildRemoteAccessStatus()
    {
        _httpsStatusPart = BuildHttpsStatusPart();
        var parts = new List<string> { _httpsStatusPart, _duckDns.Status };
        if (_duckDns.Config.IsUsable && _settings.WebHttpsEnabled)
            parts.Add($"Console URL: https://{_duckDns.Hostname}:{_settings.WebHttpsPort}/");
        return string.Join("  ·  ", parts);
    }

    partial void OnHoneypotEnabledChanged(bool value)
    {
        _monitor.HoneypotPorts = HoneypotService.ParsePorts(HoneypotPortsText);
        _monitor.HoneypotEnabled = value;
        _settings.HoneypotEnabled = value;
        _settings.Save();
        SettingsMessage = value ? _monitor.HoneypotStatus : "Honeypot: off";
    }

    partial void OnHoneypotPortsTextChanged(string value)
    {
        var ports = HoneypotService.ParsePorts(value);
        if (ports.Count == 0)
        {
            SettingsMessage = "Enter decoy ports as a comma-separated list, e.g. 2323,3389,5900.";
            return;
        }

        _settings.HoneypotPorts = string.Join(",", ports);
        _settings.Save();
        _monitor.HoneypotPorts = ports;
        SettingsMessage = HoneypotEnabled
            ? _monitor.HoneypotStatus
            : $"Decoy ports saved ({_settings.HoneypotPorts}) — enable the honeypot to arm them.";
    }

    partial void OnWebhookUrlChanged(string value)
    {
        var url = value?.Trim() ?? "";
        _monitor.WebhookUrl = url;
        _settings.WebhookUrl = url;
        _settings.Save();
        SettingsMessage = string.IsNullOrEmpty(url)
            ? "Webhook alerts: off"
            : $"Webhook alerts: Critical threats will POST to {url}";
    }

    partial void OnSelectedAutoBlockExpiryChanged(string value)
    {
        var minutes = ExpiryLabelToMinutes(value);
        _settings.AutoBlockExpiryMinutes = minutes;
        _settings.Save();
        _firewall.AutoBlockExpiry = ExpiryMinutesToSpan(minutes);
        SettingsMessage = minutes == 0
            ? "Auto-block rules are permanent until removed."
            : $"New auto-block rules expire after {value}.";
    }

    private static int ExpiryLabelToMinutes(string? label) => label switch
    {
        "1 hour" => 60,
        "6 hours" => 360,
        "24 hours" => 1440,
        "7 days" => 10_080,
        _ => 0
    };

    private static string ExpiryMinutesToLabel(int minutes) => minutes switch
    {
        60 => "1 hour",
        360 => "6 hours",
        1440 => "24 hours",
        10_080 => "7 days",
        _ => "Never (permanent)"
    };

    private static TimeSpan? ExpiryMinutesToSpan(int minutes)
        => minutes > 0 ? TimeSpan.FromMinutes(minutes) : null;

    private void RefreshMonitorStatusText()
    {
        AuthLogStatusText = string.IsNullOrWhiteSpace(_monitor.AuthLogStatus)
            ? (AuthLogMonitorEnabled ? "Starting…" : "Disabled.")
            : _monitor.AuthLogStatus;
        ProbeLogStatusText = string.IsNullOrWhiteSpace(_monitor.ProbeLogStatus)
            ? (ProbeLogEnabled ? "Starting…" : "Disabled — firewall dropped-packet logging is off.")
            : _monitor.ProbeLogStatus;

        ArpWatchStatusText = ArpWatchEnabled ? _monitor.ArpWatchStatus : "Disabled.";
        PersistenceWatchStatusText = PersistenceWatchEnabled ? _monitor.PersistenceWatchStatus : "Disabled.";
        ExfilStatusText = ExfilMonitorEnabled ? _monitor.ExfilStatus : "Disabled.";
        HoneypotStatusText = HoneypotEnabled ? _monitor.HoneypotStatus : "Disabled — no decoy ports are bound.";
        // Only meaningful once a URL is configured; otherwise it always reads "idle".
        WebhookStatusText = string.IsNullOrWhiteSpace(WebhookUrl) ? "" : _monitor.WebhookStatus;

        if (ProbeLogEnabled)
            VerifyProbeLoggingInBackground();
    }

    /// <summary>
    /// The watcher can be happily tailing a log the firewall is no longer writing to —
    /// logging can be turned off by policy or another admin after we enabled it. Confirm
    /// with the firewall itself, off the UI thread (it shells out to netsh).
    /// </summary>
    private void VerifyProbeLoggingInBackground()
    {
        _ = Task.Run(() =>
        {
            bool installed;
            try { installed = _firewall.IsProbeLoggingInstalled(); }
            catch { return; }
            if (installed) return;

            var dispatcher = Application.Current?.Dispatcher;
            dispatcher?.BeginInvoke(() =>
            {
                if (!ProbeLogEnabled) return;
                ProbeLogStatusText =
                    "Windows Firewall dropped-packet logging is not enabled on any profile — " +
                    "no probes will be seen. Re-toggle this setting while running as Administrator.";
            });
        });
    }

    private static int PollLabelToMs(string? label) => label switch
    {
        "0.5 seconds" => 500,
        "2.5 seconds" => 2500,
        "5 seconds" => 5000,
        "10 seconds" => 10_000,
        _ => NetworkMonitorService.DefaultPollIntervalMs
    };

    private static string PollMsToLabel(int ms) => ms switch
    {
        500 => "0.5 seconds",
        2500 => "2.5 seconds",
        5000 => "5 seconds",
        10_000 => "10 seconds",
        _ => "1.2 seconds (default)"
    };

    [RelayCommand]
    private void ToggleMonitoring()
    {
        if (Stats.IsMonitoring)
            _monitor.Stop();
        else
            _monitor.Start();
    }

    [RelayCommand]
    private void ToggleAutoBlock()
    {
        AutoBlockEnabled = !AutoBlockEnabled;
    }

    [RelayCommand]
    private void ClearThreats() => _monitor.ClearThreats();

    [RelayCommand]
    private void RefreshNow()
    {
        RefreshCollections();
        if (ShowFirewall) RefreshFirewallRules();
    }

    [RelayCommand]
    private void RefreshFirewallRules()
    {
        IsAdmin = _firewall.IsAdministrator;
        FirewallStatusText = _firewall.PrivilegeText;
        try
        {
            _blockedIps = _firewall.GetBlockedIps();
            _blockedIpsRefreshedAt = DateTime.UtcNow;
            var rules = _firewall.GetManagedRules();
            FirewallRules.Clear();
            foreach (var rule in rules)
                FirewallRules.Add(rule);
        }
        catch (Exception ex)
        {
            FirewallMessage = $"Could not read firewall rules: {ex.Message}";
        }

        foreach (var host in RemoteHosts)
            host.IsBlocked = _blockedIps.Contains(host.IpAddress);
        foreach (var host in _monitor.RemoteHosts)
            host.IsBlocked = _blockedIps.Contains(host.IpAddress);
    }

    [RelayCommand]
    private void RunAsAdmin()
    {
        if (IsAdmin)
        {
            FirewallMessage = "Already running elevated.";
            return;
        }

        var answer = MessageBox.Show(
            "Network Sentinel will restart with Administrator rights so Windows Firewall rules can be created and removed.\n\nContinue?",
            "Run as Administrator",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (answer != MessageBoxResult.Yes) return;

        try
        {
            _firewall.RestartAsAdministrator();
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Could not elevate:\n{ex.Message}\n\nYou can also right-click the app and choose “Run as administrator”.",
                "Elevation failed",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    [RelayCommand]
    private void BlockHost(RemoteHost? host)
    {
        if (host == null) return;
        BlockIpInternal(host.IpAddress, $"Remote host block · {host.GeoSummary}");
    }

    [RelayCommand]
    private void UnblockHost(RemoteHost? host)
    {
        if (host == null) return;
        UnblockIpInternal(host.IpAddress);
    }

    [RelayCommand]
    private void BlockThreatIp(ThreatEvent? threat)
    {
        if (threat == null) return;
        BlockIpInternal(threat.SourceIp, $"Threat block · {threat.TypeText}: {threat.Title}");
    }

    [RelayCommand]
    private void BlockConnectionIp(NetworkConnection? connection)
    {
        if (connection == null) return;
        if (string.IsNullOrWhiteSpace(connection.RemoteAddress) ||
            connection.RemoteAddress is "0.0.0.0" or "::")
        {
            FirewallMessage = "This connection has no remote peer to block.";
            return;
        }

        BlockIpInternal(connection.RemoteAddress, $"Session block · {connection.ProcessName} {connection.DisplayRemote}");
    }

    [RelayCommand]
    private void BlockSelectedPort(ListeningPort? port)
    {
        if (port == null) return;

        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var answer = MessageBox.Show(
            $"Block inbound traffic to local {port.Protocol} port {port.Port}?\n\n" +
            $"Service: {port.ServiceHint}\nProcess: {port.ProcessName}\n\n" +
            "This creates a Windows Firewall block rule for that port on this PC.",
            "Block local port",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (answer != MessageBoxResult.Yes) return;

        var result = _firewall.BlockPort(
            port.Port,
            port.Protocol,
            FirewallDirection.Inbound,
            $"Port block · {port.ServiceHint} · {port.ProcessName}");

        FirewallMessage = result.Message;
        if (!result.Success)
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Information);

        RefreshFirewallRules();
    }

    [RelayCommand]
    private void BlockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to block.";
            return;
        }

        if (BlockIpInternal(ManualBlockIp.Trim(), "Manual block from Firewall tab"))
            ManualBlockIp = "";
    }

    [RelayCommand]
    private void UnblockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to unblock.";
            return;
        }

        UnblockIpInternal(ManualBlockIp.Trim());
    }

    [RelayCommand]
    private void BlockManualPort()
    {
        if (!int.TryParse(ManualBlockPort, out var port))
        {
            FirewallMessage = "Enter a valid port number (1–65535).";
            return;
        }

        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var direction = ResolveDirection();
        var result = _firewall.BlockPort(port, ManualBlockProtocol, direction, "Manual port block from Firewall tab");
        FirewallMessage = result.Message;
        if (!result.Success)
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        RefreshFirewallRules();
    }

    [RelayCommand]
    private void RemoveSelectedRule(FirewallRuleInfo? rule = null)
    {
        rule ??= SelectedFirewallRule;
        if (rule == null)
        {
            FirewallMessage = "Select a rule to remove.";
            return;
        }

        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var name = rule.Name;
        var answer = MessageBox.Show(
            $"Remove firewall rule?\n\n{name}",
            "Remove rule",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        var result = _firewall.RemoveRule(name);
        FirewallMessage = result.Message;
        if (result.Success)
        {
            var remote = rule.RemoteAddresses;
            if (FirewallService.TryExtractIpFromManagedRule(name, remote, out var removedIp))
                SuppressAutoBlock(removedIp);
        }
        SelectedFirewallRule = null;
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private void RemoveAllManagedRules()
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var answer = MessageBox.Show(
            "Remove ALL Network Sentinel firewall rules from Windows Defender Firewall?\n\nThis cannot be undone (you can re-block later).",
            "Remove all managed rules",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        var result = _firewall.RemoveAllManagedRules();
        FirewallMessage = result.Message;
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task RefreshAllowlistAsync()
    {
        AllowlistStatusText = "Refreshing allowlist (DNS + optional remote feed)…";
        try
        {
            await _allowlist.RefreshAsync();
            SyncAllowlistUi();
            if (IsAdmin)
            {
                var restored = _firewall.UnblockAllowlistedAddresses();
                FirewallMessage = restored.Message;
                RefreshFirewallRules();
                RefreshCollections();
            }
        }
        catch (Exception ex)
        {
            AllowlistStatusText = $"Refresh failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void AddAllowlistEntry()
    {
        var input = AllowlistInput.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            FirewallMessage = "Enter a domain (github.com) or IP to protect.";
            return;
        }

        bool ok;
        string message;
        if (System.Net.IPAddress.TryParse(input, out _))
            ok = _allowlist.TryAddIp(input, out message);
        else
            ok = _allowlist.TryAddDomain(input, out message);

        FirewallMessage = message;
        AllowlistStatusText = message;
        if (ok)
        {
            AllowlistInput = "";
            SyncAllowlistUi();
            if (IsAdmin)
            {
                var restored = _firewall.UnblockAllowlistedAddresses();
                if (restored.Success)
                    FirewallMessage = message + " · " + restored.Message;
                RefreshFirewallRules();
            }
        }
        else
        {
            MessageBox.Show(message, "Allowlist", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    [RelayCommand]
    private void RemoveAllowlistEntry()
    {
        if (SelectedAllowlistEntry == null)
        {
            FirewallMessage = "Select an allowlist entry to remove.";
            return;
        }

        if (SelectedAllowlistEntry.Kind == "Resolved")
        {
            MessageBox.Show(
                "Resolved IPs come from domain DNS. Remove the Domain entry instead, or wait for the next refresh.",
                "Allowlist",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        if (!_allowlist.TryRemove(SelectedAllowlistEntry.Value, SelectedAllowlistEntry.Kind, out var message))
        {
            MessageBox.Show(message, "Allowlist", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        FirewallMessage = message;
        SelectedAllowlistEntry = null;
        SyncAllowlistUi();
    }

    [RelayCommand]
    private void RestoreAllowlisted()
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var result = _firewall.UnblockAllowlistedAddresses();
        FirewallMessage = result.Message;
        MessageBox.Show(result.Message, "Restore allowlisted", MessageBoxButton.OK,
            result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private void OpenAllowlistFolder()
    {
        try
        {
            _allowlist.EnsureUserDatabaseExists();
            var dir = System.IO.Path.GetDirectoryName(_allowlist.LocalDatabasePath)!;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Open allowlist folder", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private bool BlockIpInternal(string ip, string reason)
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return false;
        }

        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            FirewallMessage = error;
            MessageBox.Show(error, "Block IP", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        if (FirewallService.IsPrivateOrLocal(normalized))
        {
            FirewallMessage = "Private/local addresses are not blocked by default (would break LAN).";
            MessageBox.Show(FirewallMessage, "Block IP", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        // Allowlisted IPs get a confirmed manual override instead of a hard
        // refusal — shared cloud IPs can host hostile traffic too.
        bool overrideAllowlist = false;
        if (_allowlist.IsAllowed(normalized, out var allowReason))
        {
            var overrideAnswer = MessageBox.Show(
                $"{normalized} is protected by the allowlist ({allowReason}).\n\n" +
                "Blocking it may break trusted services (GitHub, Microsoft, DNS, …).\n\nBlock it anyway?",
                "Allowlist protection",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (overrideAnswer != MessageBoxResult.Yes)
            {
                FirewallMessage = $"Protected by allowlist — not blocked: {normalized} ({allowReason}).";
                return false;
            }

            overrideAllowlist = true;
        }

        var direction = ResolveDirection();
        var answer = MessageBox.Show(
            $"Create Windows Firewall BLOCK rules for:\n\n{normalized}\nDirection: {direction}\n\n{reason}\n\nInbound blocks stop them reaching you; outbound stops this PC talking back.",
            "Block IP in Windows Firewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (answer != MessageBoxResult.Yes) return false;

        var result = _firewall.BlockIp(normalized, direction, reason, overrideAllowlist);
        FirewallMessage = result.Message;
        if (!result.Success)
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
        {
            ClearAutoBlockSuppress(normalized);
            lock (_autoBlockGate) _blockedIps.Add(normalized);
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        RefreshFirewallRules();
        RefreshCollections();
        return result.Success;
    }

    private void SuppressAutoBlock(string ip)
    {
        var until = DateTime.UtcNow.Add(ManualUnblockSuppressFor);
        lock (_autoBlockGate)
        {
            _blockedIps.Remove(ip);
            _autoBlockAttempted[ip] = DateTime.UtcNow;
            _autoBlockSuppressedUntil[ip] = until;
        }

        _settings.AutoBlockSuppressedUntil[ip] = until;
        PruneExpiredSuppressions(_settings.AutoBlockSuppressedUntil);
        _settings.Save();
    }

    private void ClearAutoBlockSuppress(string ip)
    {
        lock (_autoBlockGate)
            _autoBlockSuppressedUntil.Remove(ip);

        if (_settings.AutoBlockSuppressedUntil.Remove(ip))
            _settings.Save();
    }

    private void LoadPersistedAutoBlockSuppressions()
    {
        lock (_autoBlockGate)
        {
            _autoBlockSuppressedUntil.Clear();
            foreach (var kv in _settings.AutoBlockSuppressedUntil)
            {
                if (kv.Value > DateTime.UtcNow)
                    _autoBlockSuppressedUntil[kv.Key] = kv.Value;
            }
        }
    }

    private static void PruneExpiredSuppressions(Dictionary<string, DateTime> map)
    {
        var now = DateTime.UtcNow;
        foreach (var key in map.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
            map.Remove(key);
    }

    private void UnblockIpInternal(string ip)
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var result = _firewall.UnblockIp(ip);
        if (result.Success && FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            SuppressAutoBlock(normalized);
        FirewallMessage = result.Message;
        if (!result.Success)
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Information);

        RefreshFirewallRules();
        RefreshCollections();
    }

    private FirewallDirection ResolveDirection()
    {
        if (BlockInbound && BlockOutbound) return FirewallDirection.Both;
        if (BlockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Inbound;
    }

    private void PromptElevation()
    {
        FirewallMessage = "Administrator rights required for firewall changes.";
        var answer = MessageBox.Show(
            "Changing Windows Firewall rules requires Administrator rights.\n\nRestart Network Sentinel elevated now?",
            "Elevation required",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information);
        if (answer == MessageBoxResult.Yes)
            RunAsAdmin();
    }

    private static string FormatAppVersion()
    {
        var asm = Assembly.GetExecutingAssembly();
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var plus = info.IndexOf('+');
            if (plus >= 0)
                info = info[..plus];
            return info.StartsWith("v", StringComparison.OrdinalIgnoreCase) ? info : $"v{info}";
        }

        var version = asm.GetName().Version;
        return version is null ? "v0.1.0" : $"v{version.Major}.{version.Minor}.{version.Build}";
    }

    public void Dispose()
    {
        _clockTimer.Stop();
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        PersistSettings();
        _duckDns.Dispose();
        _allowlist.Dispose();
        _monitor.Dispose();
    }
}
