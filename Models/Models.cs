using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NetworkSentinel.Models;

public enum ThreatLevel
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum ThreatType
{
    PortScan,
    BruteForcePattern,
    SensitivePortProbe,
    RapidReconnect,
    ManyShortConnections,
    NewRemoteHost,
    SuspiciousOutbound,
    FailedLogonBurst,
    NewListener,
    SuspiciousProcess,
    KnownBadAddress,
    HoneypotHit,
    ArpSpoof,
    PersistenceChange,
    DataExfiltration
}

public enum TcpConnectionState
{
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12
}

public sealed class NetworkConnection : INotifyPropertyChanged
{
    private string _processName = "—";
    private string _remoteHostName = "";
    private string _geoSummary = "Looking up…";

    public string Protocol { get; init; } = "TCP";
    public string LocalAddress { get; init; } = "";
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    public TcpConnectionState State { get; init; }
    public int ProcessId { get; init; }
    public DateTime FirstSeen { get; init; } = DateTime.Now;
    public DateTime LastSeen { get; set; } = DateTime.Now;
    public string Key => $"{Protocol}|{LocalAddress}:{LocalPort}|{RemoteAddress}:{RemotePort}|{ProcessId}";

    public string ProcessName
    {
        get => _processName;
        set { if (_processName != value) { _processName = value; OnPropertyChanged(); } }
    }

    public string RemoteHostName
    {
        get => _remoteHostName;
        set { if (_remoteHostName != value) { _remoteHostName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayRemote)); } }
    }

    public string GeoSummary
    {
        get => _geoSummary;
        set { if (_geoSummary != value) { _geoSummary = value; OnPropertyChanged(); } }
    }

    public string StateText => State.ToString();
    public string DisplayLocal => $"{LocalAddress}:{LocalPort}";
    public string DisplayRemote => string.IsNullOrWhiteSpace(RemoteHostName)
        ? $"{RemoteAddress}:{RemotePort}"
        : $"{RemoteHostName} ({RemoteAddress}:{RemotePort})";

    public bool IsInboundEstablished =>
        State == TcpConnectionState.Established &&
        !string.IsNullOrEmpty(RemoteAddress) &&
        RemoteAddress is not ("0.0.0.0" or "::" or "127.0.0.1" or "::1");

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ListeningPort : INotifyPropertyChanged
{
    private string _processName = "—";

    public string Protocol { get; init; } = "TCP";
    public string Address { get; init; } = "";
    public int Port { get; init; }
    public int ProcessId { get; init; }
    public string ServiceHint { get; init; } = "";
    public string Key => $"{Protocol}|{Address}:{Port}|{ProcessId}";

    public string ProcessName
    {
        get => _processName;
        set { if (_processName != value) { _processName = value; OnPropertyChanged(); } }
    }

    public string DisplayEndpoint => $"{Address}:{Port}";

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RemoteHost : INotifyPropertyChanged
{
    private string _hostName = "";
    private string _country = "";
    private string _city = "";
    private string _isp = "";
    private string _geoSummary = "Resolving…";
    private int _activeConnections;
    private int _totalConnections;
    private int _portsTouched;
    private ThreatLevel _threatLevel = ThreatLevel.Info;
    private string _status = "Observed";
    private DateTime _lastSeen = DateTime.Now;
    private bool _isBlocked;

    public string IpAddress { get; init; } = "";
    public DateTime FirstSeen { get; init; } = DateTime.Now;
    public HashSet<int> LocalPortsContacted { get; } = new();
    public HashSet<int> RemotePortsUsed { get; } = new();
    public List<string> Notes { get; } = new();

    public string HostName
    {
        get => _hostName;
        set { if (_hostName != value) { _hostName = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayName)); } }
    }

    public string Country
    {
        get => _country;
        set { if (_country != value) { _country = value; OnPropertyChanged(); RefreshGeo(); } }
    }

    public string City
    {
        get => _city;
        set { if (_city != value) { _city = value; OnPropertyChanged(); RefreshGeo(); } }
    }

    public string Isp
    {
        get => _isp;
        set { if (_isp != value) { _isp = value; OnPropertyChanged(); RefreshGeo(); } }
    }

    public string GeoSummary
    {
        get => _geoSummary;
        set { if (_geoSummary != value) { _geoSummary = value; OnPropertyChanged(); } }
    }

    public int ActiveConnections
    {
        get => _activeConnections;
        set { if (_activeConnections != value) { _activeConnections = value; OnPropertyChanged(); } }
    }

    public int TotalConnections
    {
        get => _totalConnections;
        set { if (_totalConnections != value) { _totalConnections = value; OnPropertyChanged(); } }
    }

    public int PortsTouched
    {
        get => _portsTouched;
        set { if (_portsTouched != value) { _portsTouched = value; OnPropertyChanged(); } }
    }

    public ThreatLevel ThreatLevel
    {
        get => _threatLevel;
        set { if (_threatLevel != value) { _threatLevel = value; OnPropertyChanged(); OnPropertyChanged(nameof(ThreatText)); } }
    }

    public string Status
    {
        get => _status;
        set { if (_status != value) { _status = value; OnPropertyChanged(); } }
    }

    public DateTime LastSeen
    {
        get => _lastSeen;
        set { if (_lastSeen != value) { _lastSeen = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastSeenText)); } }
    }

    public bool IsBlocked
    {
        get => _isBlocked;
        set
        {
            if (_isBlocked != value)
            {
                _isBlocked = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(BlockStatusText));
            }
        }
    }

    public string DisplayName => string.IsNullOrWhiteSpace(HostName) ? IpAddress : $"{HostName} · {IpAddress}";
    public string ThreatText => ThreatLevel.ToString();
    public string LastSeenText => LastSeen.ToString("HH:mm:ss");
    public string FirstSeenText => FirstSeen.ToString("HH:mm:ss");
    public string BlockStatusText => IsBlocked ? "Blocked" : "Allowed";


    private void RefreshGeo()
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(City)) parts.Add(City);
        if (!string.IsNullOrWhiteSpace(Country)) parts.Add(Country);
        if (!string.IsNullOrWhiteSpace(Isp)) parts.Add(Isp);
        GeoSummary = parts.Count > 0 ? string.Join(" · ", parts) : "Location unknown";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class ThreatEvent : INotifyPropertyChanged
{
    private string _origin = "";

    public DateTime Timestamp { get; init; } = DateTime.Now;
    public ThreatType Type { get; init; }
    public ThreatLevel Level { get; init; }
    public string SourceIp { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Method { get; init; } = "";

    /// <summary>Mutable so async geo lookups can patch it in place after creation.</summary>
    public string Origin
    {
        get => _origin;
        set { if (_origin != value) { _origin = value; OnPropertyChanged(); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public string TimeText => Timestamp.ToString("HH:mm:ss");
    public string LevelText => Level.ToString();
    public string TypeText => Type switch
    {
        ThreatType.PortScan => "Port Scan",
        ThreatType.BruteForcePattern => "Brute-Force Pattern",
        ThreatType.SensitivePortProbe => "Sensitive Port Probe",
        ThreatType.RapidReconnect => "Rapid Reconnect",
        ThreatType.ManyShortConnections => "Short-Lived Burst",
        ThreatType.NewRemoteHost => "New Remote Host",
        ThreatType.SuspiciousOutbound => "Suspicious Outbound",
        ThreatType.FailedLogonBurst => "Failed Logon Burst",
        ThreatType.NewListener => "New Listener",
        ThreatType.SuspiciousProcess => "Suspicious Process",
        ThreatType.KnownBadAddress => "Known-Bad Address",
        ThreatType.HoneypotHit => "Honeypot Hit",
        ThreatType.ArpSpoof => "ARP Spoofing",
        ThreatType.PersistenceChange => "Persistence Change",
        ThreatType.DataExfiltration => "Data Exfiltration",
        _ => Type.ToString()
    };
}

public sealed class ActivitySample
{
    public DateTime Time { get; init; }
    public int ConnectionCount { get; init; }
    public int ThreatCount { get; init; }
    public int RemoteHostCount { get; init; }
}

public sealed class DashboardStats : INotifyPropertyChanged
{
    private int _listeningPorts;
    private int _activeConnections;
    private int _remoteHosts;
    private int _threatsToday;
    private int _highThreats;
    private string _statusText = "Initializing…";
    private bool _isMonitoring;

    public int ListeningPorts
    {
        get => _listeningPorts;
        set { if (_listeningPorts != value) { _listeningPorts = value; OnPropertyChanged(); } }
    }

    public int ActiveConnections
    {
        get => _activeConnections;
        set { if (_activeConnections != value) { _activeConnections = value; OnPropertyChanged(); } }
    }

    public int RemoteHosts
    {
        get => _remoteHosts;
        set { if (_remoteHosts != value) { _remoteHosts = value; OnPropertyChanged(); } }
    }

    public int ThreatsToday
    {
        get => _threatsToday;
        set { if (_threatsToday != value) { _threatsToday = value; OnPropertyChanged(); } }
    }

    public int HighThreats
    {
        get => _highThreats;
        set { if (_highThreats != value) { _highThreats = value; OnPropertyChanged(); } }
    }

    public string StatusText
    {
        get => _statusText;
        set { if (_statusText != value) { _statusText = value; OnPropertyChanged(); } }
    }

    public bool IsMonitoring
    {
        get => _isMonitoring;
        set { if (_isMonitoring != value) { _isMonitoring = value; OnPropertyChanged(); } }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
