using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using Avalonia.Threading;
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
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _clockTimer;
    private readonly object _autoBlockGate = new();
    private readonly Dictionary<string, DateTime> _autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan AutoBlockRetryAfter = TimeSpan.FromMinutes(10);
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

    /// <summary>Availability of the desktop notification channel (fixed at startup).</summary>
    public string CriticalAlertStatusText => _notifier.StatusText;

    // ── Activity chart legend (mirrors the web chart's legend row) ─────────────
    [ObservableProperty] private string _activityConnectionsText = "connections";
    [ObservableProperty] private string _activityThreatText = "threat detected (none in window)";
    [ObservableProperty] private string _activityFromText = "";
    [ObservableProperty] private string _activityToText = "";
    [ObservableProperty] private string _activityWindowText = "collecting…";

    /// <summary>Live window title shown in the taskbar / top bar when minimized.</summary>
    [ObservableProperty] private string _windowTitle = "Network Sentinel";

    /// <summary>Multi-line tooltip / tray summary for the system indicator.</summary>
    [ObservableProperty] private string _trayToolTip = "Network Sentinel — starting…";

    /// <summary>Short one-line status for tray menu header.</summary>
    [ObservableProperty] private string _trayStatusLine = "Network Sentinel";

    public string AppVersion { get; } = FormatAppVersion();

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

        _firewall.Allowlist = _allowlist;
        _monitor.GeoLookupsEnabled = _settings.GeoLookupEnabled;
        _monitor.AuthMonitoringEnabled = _settings.AuthLogMonitorEnabled;
        _monitor.ProbeMonitoringEnabled = _settings.ProbeLogEnabled;
        _monitor.PollIntervalMs = _settings.MonitorPollMs;
        if (_settings.ProbeLogEnabled && _firewall.IsRoot)
            _ = Task.Run(() => _firewall.EnableProbeLogging());
        _allowlist.UseRemoteFeed = _settings.AllowlistUseRemoteFeed;
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
            // Keep chrome fresh even between monitor polls (clock second tick).
            if (DateTime.Now.Second % 2 == 0)
                UpdateStatusChrome();
        };
        _clockTimer.Start();
        UpdateStatusChrome();
        RefreshMonitorStatusText();
    }

    private async Task InitializeAllowlistAsync()
    {
        try
        {
            await _allowlist.InitializeAsync();
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                SyncAllowlistUi();
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
            await Dispatcher.UIThread.InvokeAsync(() =>
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
        if (Dispatcher.UIThread.CheckAccess())
        {
            RefreshCollections();
            return;
        }

        if (Interlocked.CompareExchange(ref _monitorRefreshQueued, 1, 0) != 0)
            return;

        Dispatcher.UIThread.Post(() =>
        {
            Interlocked.Exchange(ref _monitorRefreshQueued, 0);
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

        _ = Task.Run(() =>
        {
            try
            {
                ProcessAutoBlocks(threats);
            }
            catch (Exception ex)
            {
                Dispatcher.UIThread.Post(() =>
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
            Dispatcher.UIThread.Post(() =>
            {
                AutoBlockStatusText = "Auto-block is ON, but firewall elevation is unavailable — install pkexec or click Authorize firewall.";
                FirewallMessage = "Auto-block skipped: cannot elevate nft/iptables.";
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
            if (threat.Type == ThreatType.NewRemoteHost)
                continue;
            if (!FirewallService.TryNormalizeIp(threat.SourceIp, out var ip, out _))
                continue;
            if (FirewallService.IsPrivateOrLocal(ip))
                continue;
            if (_allowlist.IsAllowed(ip, out _))
                continue;

            lock (_autoBlockGate)
            {
                if (_blockedIps.Contains(ip))
                    continue;
                if (_autoBlockAttempted.TryGetValue(ip, out var lastAttempt) &&
                    DateTime.UtcNow - lastAttempt < AutoBlockRetryAfter)
                    continue;
                _autoBlockAttempted[ip] = DateTime.UtcNow;
            }

            var reason = $"Auto-block · {threat.LevelText} · {threat.TypeText}: {threat.Title}";
            var result = _firewall.BlockIp(ip, direction, reason);
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

        Dispatcher.UIThread.Post(() =>
        {
            FirewallMessage = string.Join(" · ", messages);
            UpdateAutoBlockStatusText();
            RefreshFirewallRules();
            RefreshCollections();
        });
    }

    private void RefreshCollections()
    {
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

        UpdateStatusChrome();
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

    /// <summary>
    /// Refresh window title + tray text so the top bar / task list still show
    /// live stats when the main window is minimized.
    /// </summary>
    public void UpdateStatusChrome()
    {
        var sessions = Stats.ActiveConnections;
        var ports = Stats.ListeningPorts;
        var hosts = Stats.RemoteHosts;
        var threats = Stats.ThreatsToday;
        var high = Stats.HighThreats;
        var blocked = _blockedIps.Count;
        var mon = Stats.IsMonitoring ? "Live" : "Paused";
        var auto = AutoBlockEnabled ? $"auto≥{AutoBlockMinLevel}" : "auto off";

        // Compact title for taskbar / window list (GNOME top bar / dock).
        WindowTitle = high > 0
            ? $"NS ⚠{high} · {sessions} sess · {hosts} hosts · {threats} evt"
            : $"NS · {sessions} sess · {ports} ports · {hosts} hosts · {threats} evt";

        TrayStatusLine = high > 0
            ? $"Network Sentinel · ⚠ {high} high · {sessions} sessions ({mon})"
            : $"Network Sentinel · {sessions} sessions · {hosts} remotes ({mon})";

        TrayToolTip =
            $"Network Sentinel  ·  {AppVersion}  ·  {mon}\n" +
            $"TCP sessions: {sessions}\n" +
            $"Listening ports: {ports}\n" +
            $"Remote hosts: {hosts}\n" +
            $"Threat events today: {threats}\n" +
            $"High / critical: {high}\n" +
            $"Blocked IPs: {blocked}  ·  {auto}";
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

            Dispatcher.UIThread.Post(() =>
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
            AutoBlockStatusText = $"Auto-block is ON (≥ {AutoBlockMinLevel}), but no elevation helper (pkexec/sudo) was found.";
            return;
        }

        AutoBlockStatusText =
            $"Auto-block is ON — public IPs at {AutoBlockMinLevel}+ severity are blocked in the host firewall " +
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
            FirewallMessage = "Auto-block enabled, but no elevation helper found (install policykit-1 / pkexec).";
        else if (value)
            FirewallMessage = $"Auto-block enabled for {AutoBlockMinLevel}+ threats (password dialog may appear).";
        else
            FirewallMessage = "Auto-block disabled.";
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
            ? $"Auth-log monitoring: on ({_monitor.AuthLogStatus})"
            : "Auth-log monitoring: off";
    }

    partial void OnProbeLogEnabledChanged(bool value)
    {
        // Set while reverting the toggle after a failed rule install, so the revert
        // doesn't re-enter this handler and try to undo itself.
        if (_suppressProbeLogHandler) return;

        _settings.ProbeLogEnabled = value;
        _settings.Save();
        SettingsMessage = value
            ? "Installing probe-log firewall rule…"
            : "Removing probe-log firewall rule…";

        // Installing/removing the SYN-log rule shells out to nft/iptables and may
        // prompt for elevation, so keep it off the UI thread.
        _ = Task.Run(() =>
        {
            var result = value ? _firewall.EnableProbeLogging() : _firewall.DisableProbeLogging();
            Dispatcher.UIThread.Post(() =>
            {
                _monitor.ProbeMonitoringEnabled = value && result.Success;
                if (value && !result.Success)
                {
                    // Rule install failed (usually no elevation) — don't leave the
                    // toggle claiming a detection that isn't running.
                    _settings.ProbeLogEnabled = false;
                    _settings.Save();
                    _suppressProbeLogHandler = true;
                    try { ProbeLogEnabled = false; }
                    finally { _suppressProbeLogHandler = false; }
                    SettingsMessage = $"Closed-port scan detection: could not install firewall rule — {result.Message}";
                }
                else
                {
                    SettingsMessage = value
                        ? "Closed-port scan detection: on (probe-log firewall rule installed)"
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

    private void RefreshMonitorStatusText()
    {
        AuthLogStatusText = string.IsNullOrWhiteSpace(_monitor.AuthLogStatus)
            ? (AuthLogMonitorEnabled ? "Starting…" : "Disabled.")
            : _monitor.AuthLogStatus;
        ProbeLogStatusText = string.IsNullOrWhiteSpace(_monitor.ProbeLogStatus)
            ? (ProbeLogEnabled ? "Starting…" : "Disabled — no firewall rule installed.")
            : _monitor.ProbeLogStatus;
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
    private void ToggleAutoBlock() => AutoBlockEnabled = !AutoBlockEnabled;

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
    private async Task RunAsAdmin()
    {
        // Never relaunch the GUI as root — that breaks Wayland/X11 (XOpenDisplay).
        // Instead, pre-authorize pkexec/sudo for firewall tools only.
        if (_firewall.IsRoot)
        {
            FirewallMessage = "Already running as root (prefer running as your user on Wayland).";
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            "Network Sentinel will request admin rights only for firewall tools (nft/iptables) via a password dialog.\n\n" +
            "The app itself stays running as your user — do not use “sudo NetworkSentinel” on Wayland.\n\nContinue?",
            "Authorize firewall");

        if (!answer) return;

        try
        {
            var result = await Task.Run(() => _firewall.AuthorizeElevation());
            if (result.Success && _settings.ProbeLogEnabled)
                await Task.Run(() => _firewall.EnableProbeLogging());
            FirewallMessage = result.Message;
            IsAdmin = _firewall.IsAdministrator;
            FirewallStatusText = _firewall.PrivilegeText;
            if (result.Success)
                await DialogService.ShowInfoAsync(result.Message, "Firewall authorization");
            else
                await DialogService.ShowWarningAsync(result.Message, "Authorization failed");
        }
        catch (Exception ex)
        {
            await DialogService.ShowWarningAsync(
                $"Could not authorize:\n{ex.Message}",
                "Authorization failed");
        }
    }

    [RelayCommand]
    private async Task BlockHost(RemoteHost? host)
    {
        if (host == null) return;
        await BlockIpInternal(host.IpAddress, $"Remote host block · {host.GeoSummary}");
    }

    [RelayCommand]
    private async Task UnblockHost(RemoteHost? host)
    {
        if (host == null) return;
        await UnblockIpInternal(host.IpAddress);
    }

    [RelayCommand]
    private async Task BlockThreatIp(ThreatEvent? threat)
    {
        if (threat == null) return;
        await BlockIpInternal(threat.SourceIp, $"Threat block · {threat.TypeText}: {threat.Title}");
    }

    [RelayCommand]
    private async Task BlockConnectionIp(NetworkConnection? connection)
    {
        if (connection == null) return;
        if (string.IsNullOrWhiteSpace(connection.RemoteAddress) ||
            connection.RemoteAddress is "0.0.0.0" or "::")
        {
            FirewallMessage = "This connection has no remote peer to block.";
            return;
        }

        await BlockIpInternal(connection.RemoteAddress, $"Session block · {connection.ProcessName} {connection.DisplayRemote}");
    }

    [RelayCommand]
    private async Task BlockSelectedPort(ListeningPort? port)
    {
        if (port == null) return;

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            $"Block inbound traffic to local {port.Protocol} port {port.Port}?\n\n" +
            $"Service: {port.ServiceHint}\nProcess: {port.ProcessName}\n\n" +
            "This creates a host firewall drop rule for that port on this PC.",
            "Block local port");

        if (!answer) return;

        var result = _firewall.BlockPort(
            port.Port,
            port.Protocol,
            FirewallDirection.Inbound,
            $"Port block · {port.ServiceHint} · {port.ProcessName}");

        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");
        RefreshFirewallRules();
    }

    [RelayCommand]
    private async Task BlockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to block.";
            return;
        }

        if (await BlockIpInternal(ManualBlockIp.Trim(), "Manual block from Firewall tab"))
            ManualBlockIp = "";
    }

    [RelayCommand]
    private async Task UnblockManualIp()
    {
        if (string.IsNullOrWhiteSpace(ManualBlockIp))
        {
            FirewallMessage = "Enter an IP address to unblock.";
            return;
        }

        await UnblockIpInternal(ManualBlockIp.Trim());
    }

    [RelayCommand]
    private async Task BlockManualPort()
    {
        if (!int.TryParse(ManualBlockPort, out var port))
        {
            FirewallMessage = "Enter a valid port number (1–65535).";
            return;
        }

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var direction = ResolveDirection();
        var result = _firewall.BlockPort(port, ManualBlockProtocol, direction, "Manual port block from Firewall tab");
        FirewallMessage = result.Message;
        if (!result.Success)
            await DialogService.ShowWarningAsync(result.Message, "Firewall");
        RefreshFirewallRules();
    }

    [RelayCommand]
    private async Task RemoveSelectedRule(FirewallRuleInfo? rule = null)
    {
        rule ??= SelectedFirewallRule;
        if (rule == null)
        {
            FirewallMessage = "Select a rule to remove.";
            return;
        }

        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var name = rule.Name;
        var answer = await DialogService.ConfirmAsync($"Remove firewall rule?\n\n{name}", "Remove rule");
        if (!answer) return;

        var result = _firewall.RemoveRule(name);
        FirewallMessage = result.Message;
        SelectedFirewallRule = null;
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task RemoveAllManagedRules()
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var answer = await DialogService.ConfirmAsync(
            "Remove ALL Network Sentinel firewall rules from the host firewall?\n\nThis cannot be undone (you can re-block later).",
            "Remove all managed rules");
        if (!answer) return;

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
    private async Task AddAllowlistEntry()
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
            await DialogService.ShowInfoAsync(message, "Allowlist");
        }
    }

    [RelayCommand]
    private async Task RemoveAllowlistEntry()
    {
        if (SelectedAllowlistEntry == null)
        {
            FirewallMessage = "Select an allowlist entry to remove.";
            return;
        }

        if (SelectedAllowlistEntry.Kind == "Resolved")
        {
            await DialogService.ShowInfoAsync(
                "Resolved IPs come from domain DNS. Remove the Domain entry instead, or wait for the next refresh.",
                "Allowlist");
            return;
        }

        if (!_allowlist.TryRemove(SelectedAllowlistEntry.Value, SelectedAllowlistEntry.Kind, out var message))
        {
            await DialogService.ShowInfoAsync(message, "Allowlist");
            return;
        }

        FirewallMessage = message;
        SelectedAllowlistEntry = null;
        SyncAllowlistUi();
    }

    [RelayCommand]
    private async Task RestoreAllowlisted()
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var result = _firewall.UnblockAllowlistedAddresses();
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Restore allowlisted");
        RefreshFirewallRules();
        RefreshCollections();
    }

    [RelayCommand]
    private async Task OpenAllowlistFolder()
    {
        try
        {
            _allowlist.EnsureUserDatabaseExists();
            var dir = Path.GetDirectoryName(_allowlist.LocalDatabasePath)!;
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            await DialogService.ShowWarningAsync(ex.Message, "Open allowlist folder");
        }
    }

    private async Task<bool> BlockIpInternal(string ip, string reason)
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return false;
        }

        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            FirewallMessage = error;
            await DialogService.ShowWarningAsync(error, "Block IP");
            return false;
        }

        if (FirewallService.IsPrivateOrLocal(normalized))
        {
            FirewallMessage = "Private/local addresses are not blocked by default (would break LAN).";
            await DialogService.ShowInfoAsync(FirewallMessage, "Block IP");
            return false;
        }

        bool overrideAllowlist = false;
        if (_allowlist.IsAllowed(normalized, out var allowReason))
        {
            var overrideAnswer = await DialogService.ConfirmAsync(
                $"{normalized} is protected by the allowlist ({allowReason}).\n\n" +
                "Blocking it may break trusted services (GitHub, Microsoft, DNS, …).\n\nBlock it anyway?",
                "Allowlist protection");

            if (!overrideAnswer)
            {
                FirewallMessage = $"Protected by allowlist — not blocked: {normalized} ({allowReason}).";
                return false;
            }

            overrideAllowlist = true;
        }

        var direction = ResolveDirection();
        var answer = await DialogService.ConfirmAsync(
            $"Create host firewall DROP rules for:\n\n{normalized}\nDirection: {direction}\n\n{reason}\n\nInbound blocks stop them reaching you; outbound stops this PC talking back.",
            "Block IP in host firewall");

        if (!answer) return false;

        var result = _firewall.BlockIp(normalized, direction, reason, overrideAllowlist);
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");

        RefreshFirewallRules();
        RefreshCollections();
        return result.Success;
    }

    private async Task UnblockIpInternal(string ip)
    {
        if (!IsAdmin)
        {
            await PromptElevation();
            return;
        }

        var result = _firewall.UnblockIp(ip);
        if (result.Success && FirewallService.TryNormalizeIp(ip, out var normalized, out _))
        {
            lock (_autoBlockGate)
            {
                _blockedIps.Remove(normalized);
                _autoBlockAttempted.Remove(normalized);
            }
        }
        FirewallMessage = result.Message;
        await DialogService.ShowInfoAsync(result.Message, "Firewall");

        RefreshFirewallRules();
        RefreshCollections();
    }

    private FirewallDirection ResolveDirection()
    {
        if (BlockInbound && BlockOutbound) return FirewallDirection.Both;
        if (BlockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Inbound;
    }

    private async Task PromptElevation()
    {
        FirewallMessage = "Admin rights required for firewall changes (pkexec password dialog).";
        var answer = await DialogService.ConfirmAsync(
            "Changing host firewall rules needs admin rights.\n\n" +
            "The app will ask for your password via pkexec — it will NOT restart as root.\n\nAuthorize now?",
            "Elevation required");
        if (answer)
            await RunAsAdmin();
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
        return version is null ? "v0.2.0" : $"v{version.Major}.{version.Minor}.{version.Build}";
    }

    public void Dispose()
    {
        _clockTimer.Stop();
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        PersistSettings();
        _allowlist.Dispose();
        _monitor.Dispose();
    }
}
