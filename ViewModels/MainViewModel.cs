using System.Collections.ObjectModel;
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
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _clockTimer;
    private readonly object _autoBlockGate = new();
    private readonly HashSet<string> _autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);

    [ObservableProperty] private string _clockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
    [ObservableProperty] private string _selectedNav = "Dashboard";
    [ObservableProperty] private bool _showDashboard = true;
    [ObservableProperty] private bool _showConnections;
    [ObservableProperty] private bool _showHosts;
    [ObservableProperty] private bool _showThreats;
    [ObservableProperty] private bool _showPorts;
    [ObservableProperty] private bool _showFirewall;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private string _heroSubtitle = "Watching local ports, remote peers, and break-in patterns in real time.";
    [ObservableProperty] private string _firewallStatusText = "";
    [ObservableProperty] private string _firewallMessage = "";
    [ObservableProperty] private string _autoBlockStatusText = "Auto-block is off.";
    [ObservableProperty] private bool _isAdmin;
    [ObservableProperty] private bool _autoBlockEnabled;
    [ObservableProperty] private string _autoBlockMinLevel = nameof(ThreatLevel.High);
    [ObservableProperty] private string _manualBlockIp = "";
    [ObservableProperty] private string _manualBlockPort = "";
    [ObservableProperty] private string _manualBlockProtocol = "TCP";
    [ObservableProperty] private bool _blockInbound = true;
    [ObservableProperty] private bool _blockOutbound = true;
    [ObservableProperty] private FirewallRuleInfo? _selectedFirewallRule;
    [ObservableProperty] private RemoteHost? _selectedHost;
    [ObservableProperty] private ThreatEvent? _selectedThreat;
    [ObservableProperty] private NetworkConnection? _selectedConnection;
    [ObservableProperty] private ListeningPort? _selectedPort;

    public DashboardStats Stats => _monitor.Stats;
    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    public ObservableCollection<ListeningPort> ListeningPorts { get; } = new();
    public ObservableCollection<RemoteHost> RemoteHosts { get; } = new();
    public ObservableCollection<ThreatEvent> Threats { get; } = new();
    public ObservableCollection<FirewallRuleInfo> FirewallRules { get; } = new();
    public ObservableCollection<double> ActivitySeries { get; } = new();
    public ObservableCollection<double> ThreatSeries { get; } = new();
    public ObservableCollection<string> ProtocolOptions { get; } = new() { "TCP", "UDP" };
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

        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
        _monitor.Start();

        IsAdmin = _firewall.IsAdministrator;
        FirewallStatusText = _firewall.PrivilegeText;
        UpdateAutoBlockStatusText();
        RefreshFirewallRules();

        _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clockTimer.Tick += (_, _) => ClockText = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss");
        _clockTimer.Start();
    }

    private void OnMonitorUpdated()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher == null) return;

        if (dispatcher.CheckAccess())
            RefreshCollections();
        else
            dispatcher.Invoke(RefreshCollections, DispatcherPriority.Background);
    }

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (!AutoBlockEnabled || threats.Count == 0)
            return;

        // Run auto-block off the UI thread; marshal status updates back.
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

            lock (_autoBlockGate)
            {
                if (_autoBlockAttempted.Contains(ip) || _blockedIps.Contains(ip))
                    continue;
                _autoBlockAttempted.Add(ip);
            }

            if (_firewall.IsIpBlocked(ip))
            {
                lock (_autoBlockGate) _blockedIps.Add(ip);
                continue;
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
        // Refresh blocked set periodically with monitor ticks (cheap when few rules)
        try { _blockedIps = _firewall.GetBlockedIps(); }
        catch { /* ignore */ }

        foreach (var host in _monitor.RemoteHosts)
            host.IsBlocked = _blockedIps.Contains(host.IpAddress);

        Sync(Connections, FilterConnections(_monitor.Connections));
        Sync(ListeningPorts, _monitor.ListeningPorts);
        Sync(RemoteHosts, FilterHosts(_monitor.RemoteHosts));
        Sync(Threats, FilterThreats(_monitor.Threats));

        ActivitySeries.Clear();
        ThreatSeries.Clear();
        foreach (var sample in _monitor.Activity)
        {
            ActivitySeries.Add(sample.ConnectionCount);
            ThreatSeries.Add(sample.ThreatCount * 4.0);
        }

        var high = Stats.HighThreats;
        var blocked = _blockedIps.Count;
        var auto = AutoBlockEnabled ? $"Auto-block ON (≥{AutoBlockMinLevel})" : "Auto-block OFF";
        HeroSubtitle = high > 0
            ? $"{high} high/critical · {blocked} blocked · {auto}"
            : $"{blocked} IPs blocked · {auto}";
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

    private static void Sync<T>(ObservableCollection<T> target, IEnumerable<T> source)
    {
        var list = source.ToList();
        target.Clear();
        foreach (var item in list)
            target.Add(item);
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

        if (ShowFirewall)
            RefreshFirewallRules();
    }

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

        BlockIpInternal(ManualBlockIp.Trim(), "Manual block from Firewall tab");
        if (_blockedIps.Contains(ManualBlockIp.Trim()) || FirewallMessage.Contains("Blocked", StringComparison.OrdinalIgnoreCase))
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

    private void BlockIpInternal(string ip, string reason)
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            FirewallMessage = error;
            MessageBox.Show(error, "Block IP", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (FirewallService.IsPrivateOrLocal(normalized))
        {
            FirewallMessage = "Private/local addresses are not blocked by default (would break LAN).";
            MessageBox.Show(FirewallMessage, "Block IP", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var direction = ResolveDirection();
        var answer = MessageBox.Show(
            $"Create Windows Firewall BLOCK rules for:\n\n{normalized}\nDirection: {direction}\n\n{reason}\n\nInbound blocks stop them reaching you; outbound stops this PC talking back.",
            "Block IP in Windows Firewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (answer != MessageBoxResult.Yes) return;

        var result = _firewall.BlockIp(normalized, direction, reason);
        FirewallMessage = result.Message;
        if (!result.Success)
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(result.Message, "Firewall", MessageBoxButton.OK, MessageBoxImage.Information);

        RefreshFirewallRules();
        RefreshCollections();
    }

    private void UnblockIpInternal(string ip)
    {
        if (!IsAdmin)
        {
            PromptElevation();
            return;
        }

        var result = _firewall.UnblockIp(ip);
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

    public void Dispose()
    {
        _clockTimer.Stop();
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        PersistSettings();
        _monitor.Dispose();
    }
}
