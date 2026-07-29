using System.Reflection;
using System.Text;
using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace NetworkSentinel.Tui;

/// <summary>
/// Terminal UI for Network Sentinel — same monitoring / firewall services as the Avalonia GUI.
/// Launch with <c>--tui</c> or when no graphical display is available.
/// </summary>
public sealed class TuiApp : IDisposable
{
    private enum View
    {
        Dashboard = 0,
        Connections = 1,
        Hosts = 2,
        Threats = 3,
        Ports = 4,
        Firewall = 5,
        Allowlist = 6,
        Help = 7
    }

    private static readonly string[] ViewNames =
    [
        "Dashboard", "Connections", "Hosts", "Threats", "Ports", "Firewall", "Allowlist", "Help"
    ];

    /// <summary>
    /// Spectre.Console forbids Ask/Confirm/Status while Live is running.
    /// Keys only schedule a prompt; Live exits, we run the prompt, then Live restarts.
    /// </summary>
    private enum PromptKind
    {
        None,
        Filter,
        Authorize,
        Block,
        Unblock,
        AddAllowlist,
        RemoveAllowlist,
        RefreshAllowlist,
        RestoreAllowlisted
    }

    private readonly NetworkMonitorService _monitor = new();
    private readonly FirewallService _firewall = new();
    private readonly AllowlistService _allowlist = new();
    private readonly AppSettings _settings;
    private readonly object _autoBlockGate = new();
    private readonly Dictionary<string, DateTime> _autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan AutoBlockRetryAfter = TimeSpan.FromMinutes(10);

    private View _view = View.Dashboard;
    private string _filter = "";
    private string _statusMessage = "TUI ready — monitoring started.";
    private int _selectedIndex;
    private int _scrollOffset;
    private bool _running = true;
    private bool _autoBlockEnabled;
    private string _autoBlockMinLevel;
    private bool _blockInbound;
    private bool _blockOutbound;
    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _blockedIpsRefreshedAt = DateTime.MinValue;
    private bool _blockedIpsRefreshInFlight;
    private PromptKind _pendingPrompt = PromptKind.None;
    private string _appVersion = FormatAppVersion();

    public TuiApp()
    {
        _settings = AppSettings.Load();
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (_autoBlockMinLevel is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;

        _firewall.Allowlist = _allowlist;
        _monitor.GeoLookupsEnabled = _settings.GeoLookupEnabled;
        _monitor.AuthMonitoringEnabled = _settings.AuthLogMonitorEnabled;
        _allowlist.UseRemoteFeed = _settings.AllowlistUseRemoteFeed;
        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
    }

    public async Task RunAsync()
    {
        if (!AnsiConsole.Profile.Capabilities.Interactive)
        {
            AnsiConsole.MarkupLine("[red]Interactive terminal required for TUI mode.[/]");
            AnsiConsole.MarkupLine("Run from a real TTY, or use the Avalonia GUI without [cyan]--tui[/].");
            return;
        }

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _running = false;
        };

        AnsiConsole.Clear();
        AnsiConsole.MarkupLine("[bold cyan]Network Sentinel[/] [grey]TUI[/] — loading…");

        try
        {
            await _allowlist.InitializeAsync();
            _statusMessage = _allowlist.StatusText;
        }
        catch (Exception ex)
        {
            _statusMessage = $"Allowlist load error: {ex.Message}";
        }

        RefreshBlockedIps(force: true);
        _monitor.Start();

        try
        {
            // Live display and interactive prompts cannot run at the same time in Spectre.Console.
            // Loop: draw until a key requests a prompt → exit Live → prompt on plain console → redraw.
            while (_running)
            {
                await AnsiConsole.Live(BuildRoot())
                    .AutoClear(true)
                    .Overflow(VerticalOverflow.Ellipsis)
                    .Cropping(VerticalOverflowCropping.Bottom)
                    .StartAsync(async ctx =>
                    {
                        while (_running && _pendingPrompt == PromptKind.None)
                        {
                            HandleInput();
                            if (!_running || _pendingPrompt != PromptKind.None)
                                break;

                            ctx.UpdateTarget(BuildRoot());
                            ctx.Refresh();
                            await Task.Delay(200);
                        }
                    });

                if (!_running)
                    break;

                if (_pendingPrompt != PromptKind.None)
                {
                    var kind = _pendingPrompt;
                    _pendingPrompt = PromptKind.None;
                    // Leave alternate/live screen so stdin prompts are stable.
                    AnsiConsole.Clear();
                    AnsiConsole.Cursor.Show();
                    try
                    {
                        await RunPromptAsync(kind);
                    }
                    finally
                    {
                        try { AnsiConsole.Cursor.Hide(); } catch { /* ignore */ }
                    }
                }
            }
        }
        finally
        {
            _monitor.Stop();
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[grey]Network Sentinel TUI stopped.[/]");
        }
    }

    private void OnMonitorUpdated()
    {
        // Live loop redraws on its own cadence; nothing to marshal to UI thread.
        RefreshBlockedIps(force: false);
    }

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled || threats.Count == 0)
            return;

        _ = Task.Run(() =>
        {
            try
            {
                ProcessAutoBlocks(threats);
            }
            catch (Exception ex)
            {
                _statusMessage = $"Auto-block error: {ex.Message}";
            }
        });
    }

    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled)
            return;

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Auto-block ON, but no elevation helper (install pkexec).";
            return;
        }

        var minLevel = Enum.TryParse<ThreatLevel>(_autoBlockMinLevel, true, out var level)
            ? level
            : ThreatLevel.High;
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
                messages.Add($"Auto-blocked {ip}");
            }
            else
            {
                messages.Add($"Auto-block failed {ip}: {result.Message}");
                lock (_autoBlockGate) _autoBlockAttempted.Remove(ip);
            }
        }

        if (messages.Count > 0)
        {
            _statusMessage = string.Join(" · ", messages);
            RefreshBlockedIps(force: true);
        }
    }

    private FirewallDirection ResolveDirection()
    {
        if (_blockInbound && _blockOutbound) return FirewallDirection.Both;
        if (_blockInbound) return FirewallDirection.Inbound;
        if (_blockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Both;
    }

    private void RefreshBlockedIps(bool force)
    {
        if (_blockedIpsRefreshInFlight)
            return;
        if (!force && DateTime.UtcNow - _blockedIpsRefreshedAt < TimeSpan.FromSeconds(15))
            return;

        _blockedIpsRefreshInFlight = true;
        _ = Task.Run(() =>
        {
            try
            {
                var set = _firewall.GetBlockedIps();
                _blockedIps = set;
                _blockedIpsRefreshedAt = DateTime.UtcNow;
                foreach (var host in _monitor.RemoteHosts)
                    host.IsBlocked = _blockedIps.Contains(host.IpAddress);
            }
            catch
            {
                // keep previous set
            }
            finally
            {
                _blockedIpsRefreshInFlight = false;
            }
        });
    }

    private void HandleInput()
    {
        if (_pendingPrompt != PromptKind.None || !Console.KeyAvailable)
            return;

        var key = Console.ReadKey(true);
        switch (key.Key)
        {
            case ConsoleKey.Q when key.Modifiers == ConsoleModifiers.None:
                _running = false;
                return;

            case ConsoleKey.D1:
            case ConsoleKey.NumPad1:
                SwitchView(View.Dashboard);
                break;
            case ConsoleKey.D2:
            case ConsoleKey.NumPad2:
                SwitchView(View.Connections);
                break;
            case ConsoleKey.D3:
            case ConsoleKey.NumPad3:
                SwitchView(View.Hosts);
                break;
            case ConsoleKey.D4:
            case ConsoleKey.NumPad4:
                SwitchView(View.Threats);
                break;
            case ConsoleKey.D5:
            case ConsoleKey.NumPad5:
                SwitchView(View.Ports);
                break;
            case ConsoleKey.D6:
            case ConsoleKey.NumPad6:
                SwitchView(View.Firewall);
                break;
            case ConsoleKey.D7:
            case ConsoleKey.NumPad7:
                SwitchView(View.Allowlist);
                break;
            case ConsoleKey.D8:
            case ConsoleKey.NumPad8:
            case ConsoleKey.H:
            case ConsoleKey.F1:
            case ConsoleKey.Oem2 when key.Modifiers == ConsoleModifiers.Shift: // ?
                SwitchView(View.Help);
                break;

            case ConsoleKey.Tab:
                SwitchView((View)(((int)_view + 1) % ViewNames.Length));
                break;

            case ConsoleKey.UpArrow:
            case ConsoleKey.K:
                MoveSelection(-1);
                break;
            case ConsoleKey.DownArrow:
            case ConsoleKey.J:
                MoveSelection(1);
                break;
            case ConsoleKey.PageUp:
                MoveSelection(-10);
                break;
            case ConsoleKey.PageDown:
                MoveSelection(10);
                break;
            case ConsoleKey.Home:
                _selectedIndex = 0;
                _scrollOffset = 0;
                break;
            case ConsoleKey.End:
                MoveSelection(10_000);
                break;

            case ConsoleKey.P:
                ToggleMonitoring();
                break;
            case ConsoleKey.A:
                ToggleAutoBlock();
                break;
            case ConsoleKey.C:
                _monitor.ClearThreats();
                _statusMessage = "Threat alerts cleared.";
                break;
            case ConsoleKey.R:
                if (_view == View.Allowlist)
                    _pendingPrompt = PromptKind.RefreshAllowlist;
                else
                {
                    RefreshBlockedIps(force: true);
                    _statusMessage = "Firewall / block list refreshed.";
                }
                break;
            case ConsoleKey.U:
                _pendingPrompt = PromptKind.Authorize;
                break;
            case ConsoleKey.B:
                _pendingPrompt = PromptKind.Block;
                break;
            case ConsoleKey.X:
                _pendingPrompt = PromptKind.Unblock;
                break;
            case ConsoleKey.M:
                CycleMinLevel();
                break;
            case ConsoleKey.N:
            case ConsoleKey.Insert:
            case ConsoleKey.OemPlus:
            case ConsoleKey.Add:
                _pendingPrompt = PromptKind.AddAllowlist;
                break;
            case ConsoleKey.D when key.Modifiers == ConsoleModifiers.None:
            case ConsoleKey.Delete:
                // Immediate validation (no console prompt needed for some cases)
                if (_view != View.Allowlist)
                {
                    _statusMessage = "Switch to Allowlist (7), select a Domain/IP row, then press d.";
                    break;
                }
                _pendingPrompt = PromptKind.RemoveAllowlist;
                break;
            case ConsoleKey.G:
                _pendingPrompt = PromptKind.RestoreAllowlisted;
                break;
            case ConsoleKey.Oem2: // /
            case ConsoleKey.F:
                _pendingPrompt = PromptKind.Filter;
                break;
            case ConsoleKey.Escape:
                if (!string.IsNullOrEmpty(_filter))
                {
                    _filter = "";
                    _selectedIndex = 0;
                    _scrollOffset = 0;
                    _statusMessage = "Filter cleared.";
                }
                else
                {
                    _running = false;
                }
                break;

            case ConsoleKey.L when key.Modifiers == ConsoleModifiers.Control:
                _filter = "";
                _selectedIndex = 0;
                _scrollOffset = 0;
                _statusMessage = "Filter cleared.";
                break;
        }
    }

    private async Task RunPromptAsync(PromptKind kind)
    {
        try
        {
            switch (kind)
            {
                case PromptKind.Filter:
                    RunPromptFilter();
                    break;
                case PromptKind.Authorize:
                    RunPromptAuthorize();
                    break;
                case PromptKind.Block:
                    RunPromptBlock();
                    break;
                case PromptKind.Unblock:
                    RunPromptUnblock();
                    break;
                case PromptKind.AddAllowlist:
                    RunPromptAddAllowlist();
                    break;
                case PromptKind.RemoveAllowlist:
                    RunPromptRemoveAllowlist();
                    break;
                case PromptKind.RefreshAllowlist:
                    await RunPromptRefreshAllowlistAsync();
                    break;
                case PromptKind.RestoreAllowlisted:
                    RunPromptRestoreAllowlisted();
                    break;
            }
        }
        catch (Exception ex)
        {
            _statusMessage = $"Prompt failed: {ex.Message}";
        }

        // Drain any leftover keypresses from the prompt (e.g. Enter echo).
        while (Console.KeyAvailable)
            Console.ReadKey(true);
    }

    /// <summary>Plain stdin prompt — safe after Live display has exited.</summary>
    private static string ReadLine(string label, string defaultValue = "")
    {
        if (!string.IsNullOrEmpty(defaultValue))
            Console.Write($"{label} [{defaultValue}]: ");
        else
            Console.Write($"{label}: ");

        var line = Console.ReadLine();
        if (line == null)
            return defaultValue;
        line = line.Trim();
        return line.Length == 0 ? defaultValue : line;
    }

    private static bool Confirm(string message, bool defaultYes = false)
    {
        var hint = defaultYes ? "Y/n" : "y/N";
        Console.Write($"{message} [{hint}] ");
        var line = Console.ReadLine()?.Trim() ?? "";
        if (line.Length == 0)
            return defaultYes;
        return line is "y" or "Y" or "yes" or "YES";
    }

    private void SwitchView(View view)
    {
        _view = view;
        _selectedIndex = 0;
        _scrollOffset = 0;
    }

    private void MoveSelection(int delta)
    {
        var count = GetRowCount();
        if (count <= 0)
        {
            _selectedIndex = 0;
            return;
        }

        _selectedIndex = Math.Clamp(_selectedIndex + delta, 0, count - 1);
        var visible = Math.Max(5, Console.WindowHeight - 16);
        if (_selectedIndex < _scrollOffset)
            _scrollOffset = _selectedIndex;
        else if (_selectedIndex >= _scrollOffset + visible)
            _scrollOffset = _selectedIndex - visible + 1;
    }

    private int GetRowCount() => _view switch
    {
        View.Connections => FilterConnections().Count,
        View.Hosts => FilterHosts().Count,
        View.Threats => FilterThreats().Count,
        View.Ports => _monitor.ListeningPorts.Count,
        View.Firewall => _firewall.GetManagedRules().Count,
        View.Allowlist => FilterAllowlist().Count,
        View.Dashboard => Math.Max(FilterThreats().Count, FilterHosts().Count),
        _ => 0
    };

    private void ToggleMonitoring()
    {
        if (_monitor.Stats.IsMonitoring)
        {
            _monitor.Stop();
            _statusMessage = "Monitoring paused.";
        }
        else
        {
            _monitor.Start();
            _statusMessage = "Monitoring resumed.";
        }
    }

    private void ToggleAutoBlock()
    {
        _autoBlockEnabled = !_autoBlockEnabled;
        _settings.AutoBlockEnabled = _autoBlockEnabled;
        _settings.Save();
        _statusMessage = _autoBlockEnabled
            ? $"Auto-block ON (≥ {_autoBlockMinLevel})" +
              (_firewall.IsAdministrator ? "" : " — need pkexec for firewall changes")
            : "Auto-block OFF";
    }

    private void CycleMinLevel()
    {
        _autoBlockMinLevel = _autoBlockMinLevel switch
        {
            nameof(ThreatLevel.Medium) => nameof(ThreatLevel.High),
            nameof(ThreatLevel.High) => nameof(ThreatLevel.Critical),
            _ => nameof(ThreatLevel.Medium)
        };
        _settings.AutoBlockMinLevel = _autoBlockMinLevel;
        _settings.Save();
        _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
    }

    private void RunPromptFilter()
    {
        Console.WriteLine();
        Console.WriteLine("Filter (empty clears)");
        // Empty default so blank Enter clears; show current as hint only.
        Console.Write(string.IsNullOrEmpty(_filter)
            ? "Filter: "
            : $"Filter (current: {_filter}, Enter clears if blank): ");
        var line = Console.ReadLine()?.Trim() ?? "";
        // If user pressed Enter with empty and we want to keep filter, they'd retype it.
        // Spec: empty clears (same as GUI watermark behavior for filter reset via /).
        _filter = line;
        _selectedIndex = 0;
        _scrollOffset = 0;
        _statusMessage = string.IsNullOrEmpty(_filter) ? "Filter cleared." : $"Filter: {_filter}";
    }

    private void RunPromptAuthorize()
    {
        Console.WriteLine();
        if (_firewall.IsRoot)
        {
            _statusMessage = "Already root — firewall rules apply directly.";
            return;
        }

        if (!Confirm("Authorize firewall elevation (pkexec/sudo password may be required)?"))
        {
            _statusMessage = "Authorization cancelled.";
            return;
        }

        var result = _firewall.AuthorizeElevation();
        _statusMessage = result.Message;
    }

    private void RunPromptBlock()
    {
        Console.WriteLine();
        var ip = TryGetSelectedIp();
        if (string.IsNullOrWhiteSpace(ip))
            ip = ReadLine("IP to block");
        else
            Console.WriteLine($"Selected: {ip}");

        if (string.IsNullOrWhiteSpace(ip))
        {
            _statusMessage = "Block cancelled (no IP).";
            return;
        }

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot block — install pkexec/sudo or run Authorize (u).";
            return;
        }

        if (!Confirm($"Block {ip.Trim()} (inbound+outbound)?"))
        {
            _statusMessage = "Block cancelled.";
            return;
        }

        var result = _firewall.BlockIp(ip.Trim(), ResolveDirection(), "TUI block");
        _statusMessage = result.Message;
        if (result.Success)
        {
            _blockedIps.Add(ip.Trim());
            RefreshBlockedIps(force: true);
        }
    }

    private void RunPromptUnblock()
    {
        Console.WriteLine();
        var ip = TryGetSelectedIp();
        if (string.IsNullOrWhiteSpace(ip))
            ip = ReadLine("IP to unblock");
        else
            Console.WriteLine($"Selected: {ip}");

        if (string.IsNullOrWhiteSpace(ip))
        {
            _statusMessage = "Unblock cancelled (no IP).";
            return;
        }

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot unblock — install pkexec/sudo or run Authorize (u).";
            return;
        }

        var result = _firewall.UnblockIp(ip.Trim());
        _statusMessage = result.Message;
        RefreshBlockedIps(force: true);
    }

    private string? TryGetSelectedIp()
    {
        try
        {
            return _view switch
            {
                View.Connections => FilterConnections().ElementAtOrDefault(_selectedIndex)?.RemoteAddress,
                View.Hosts => FilterHosts().ElementAtOrDefault(_selectedIndex)?.IpAddress,
                View.Threats => FilterThreats().ElementAtOrDefault(_selectedIndex)?.SourceIp,
                View.Firewall => ExtractIpFromRule(_firewall.GetManagedRules().ElementAtOrDefault(_selectedIndex)),
                View.Dashboard => FilterThreats().ElementAtOrDefault(_selectedIndex)?.SourceIp
                                  ?? FilterHosts().ElementAtOrDefault(_selectedIndex)?.IpAddress,
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractIpFromRule(FirewallRuleInfo? rule)
    {
        if (rule == null || string.IsNullOrWhiteSpace(rule.RemoteAddresses))
            return null;
        var first = rule.RemoteAddresses.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault();
        return first;
    }

    private IReadOnlyList<NetworkConnection> FilterConnections()
    {
        var source = _monitor.Connections;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(c =>
            c.DisplayLocal.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.DisplayRemote.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            c.StateText.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<RemoteHost> FilterHosts()
    {
        var source = _monitor.RemoteHosts;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(h =>
            h.IpAddress.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.HostName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.GeoSummary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            h.Status.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<ThreatEvent> FilterThreats()
    {
        var source = _monitor.Threats;
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(t =>
            t.SourceIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Detail.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Origin.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            t.Method.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private IReadOnlyList<AllowlistEntryView> FilterAllowlist()
    {
        var source = _allowlist.GetEntries();
        if (string.IsNullOrWhiteSpace(_filter)) return source;
        var q = _filter.Trim();
        return source.Where(e =>
            e.Kind.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            e.Value.Contains(q, StringComparison.OrdinalIgnoreCase) ||
            e.Detail.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void RunPromptAddAllowlist()
    {
        Console.WriteLine();
        Console.WriteLine("Add to allowlist — domain (github.com) or IP (1.2.3.4). Never blocked.");
        var input = ReadLine("Domain or IP");
        if (string.IsNullOrWhiteSpace(input))
        {
            _statusMessage = "Allowlist add cancelled.";
            return;
        }

        bool ok;
        string message;
        if (System.Net.IPAddress.TryParse(input, out _))
            ok = _allowlist.TryAddIp(input, out message);
        else
            ok = _allowlist.TryAddDomain(input, out message);

        _statusMessage = message;
        if (!ok)
            return;

        // Domains resolve in the background; optionally restore any blocks on allowlisted IPs.
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(800);
                if (_firewall.IsAdministrator)
                {
                    var restored = _firewall.UnblockAllowlistedAddresses();
                    if (restored.Success &&
                        !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                        _statusMessage = message + " · " + restored.Message;
                }
            }
            catch { /* best-effort */ }
        });

        if (_view != View.Allowlist)
            SwitchView(View.Allowlist);
        else
        {
            _selectedIndex = 0;
            _scrollOffset = 0;
        }
    }

    private void RunPromptRemoveAllowlist()
    {
        var rows = FilterAllowlist();
        var entry = rows.ElementAtOrDefault(_selectedIndex);
        if (entry == null)
        {
            _statusMessage = "No allowlist entry selected.";
            return;
        }

        if (entry.Kind.Equals("Resolved", StringComparison.OrdinalIgnoreCase))
        {
            _statusMessage = "Resolved IPs come from DNS of a Domain — remove the Domain entry instead.";
            return;
        }

        Console.WriteLine();
        if (!Confirm($"Remove allowlist entry {entry.Kind}: {entry.Value}?"))
        {
            _statusMessage = "Remove cancelled.";
            return;
        }

        if (!_allowlist.TryRemove(entry.Value, entry.Kind, out var message))
        {
            _statusMessage = message;
            return;
        }

        _statusMessage = message;
        var count = FilterAllowlist().Count;
        _selectedIndex = count == 0 ? 0 : Math.Clamp(_selectedIndex, 0, count - 1);
    }

    private async Task RunPromptRefreshAllowlistAsync()
    {
        Console.WriteLine();
        Console.WriteLine("Refreshing allowlist (DNS + optional remote feed)…");
        await _allowlist.RefreshAsync();
        _statusMessage = _allowlist.StatusText;
        if (_firewall.IsAdministrator)
        {
            var restored = _firewall.UnblockAllowlistedAddresses();
            if (restored.Success &&
                !restored.Message.Contains("No allowlisted", StringComparison.OrdinalIgnoreCase))
                _statusMessage += " · " + restored.Message;
        }
        RefreshBlockedIps(force: true);
        Console.WriteLine(_statusMessage);
    }

    private void RunPromptRestoreAllowlisted()
    {
        Console.WriteLine();
        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Cannot restore — install pkexec/sudo or press u to authorize.";
            return;
        }

        if (!Confirm("Unblock any Network Sentinel rules that hit allowlisted IPs?"))
        {
            _statusMessage = "Restore cancelled.";
            return;
        }

        var result = _firewall.UnblockAllowlistedAddresses();
        _statusMessage = result.Message;
        RefreshBlockedIps(force: true);
    }

    private IRenderable BuildRoot()
    {
        var layout = new Layout("root")
            .SplitRows(
                new Layout("header").Size(4),
                new Layout("nav").Size(3),
                new Layout("body"),
                new Layout("footer").Size(4));

        layout["header"].Update(BuildHeader());
        layout["nav"].Update(BuildNav());
        layout["body"].Update(BuildBody());
        layout["footer"].Update(BuildFooter());
        return layout;
    }

    private IRenderable BuildHeader()
    {
        var stats = _monitor.Stats;
        var mon = stats.IsMonitoring ? "[green]LIVE[/]" : "[yellow]PAUSED[/]";
        var auto = _autoBlockEnabled
            ? $"[red]AUTO ≥ {_autoBlockMinLevel}[/]"
            : "[grey]auto off[/]";
        var blocked = _blockedIps.Count;

        var grid = new Grid().AddColumns(5);
        grid.AddRow(
            new Markup($"[bold]Ports[/]\n[cyan bold]{stats.ListeningPorts}[/]"),
            new Markup($"[bold]Sessions[/]\n[blue bold]{stats.ActiveConnections}[/]"),
            new Markup($"[bold]Hosts[/]\n[purple bold]{stats.RemoteHosts}[/]"),
            new Markup($"[bold]Threats[/]\n[yellow bold]{stats.ThreatsToday}[/]"),
            new Markup($"[bold]High[/]\n[red bold]{stats.HighThreats}[/]"));

        return new Panel(grid)
        {
            Header = new PanelHeader(
                $"[bold cyan] Network Sentinel [/][grey]{_appVersion}[/]  {mon}  {auto}  [grey]blocked {blocked}[/]  [dim]{DateTime.Now:HH:mm:ss}[/]"),
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Grey)
        };
    }

    private IRenderable BuildNav()
    {
        var parts = new List<string>();
        for (var i = 0; i < ViewNames.Length; i++)
        {
            var label = $"{i + 1}:{ViewNames[i]}";
            if ((View)i == _view)
                parts.Add($"[black on cyan] {label} [/]");
            else
                parts.Add($"[grey]{label}[/]");
        }

        var filterHint = string.IsNullOrEmpty(_filter)
            ? "[dim]/ filter[/]"
            : $"[yellow]filter:[/] {_filter.EscapeMarkup()}";

        return new Panel(new Markup(string.Join("  ", parts) + "   " + filterHint))
        {
            Border = BoxBorder.None,
            Padding = new Padding(1, 0)
        };
    }

    private IRenderable BuildBody() => _view switch
    {
        View.Dashboard => BuildDashboard(),
        View.Connections => BuildConnectionsTable(),
        View.Hosts => BuildHostsTable(),
        View.Threats => BuildThreatsTable(),
        View.Ports => BuildPortsTable(),
        View.Firewall => BuildFirewallPanel(),
        View.Allowlist => BuildAllowlistPanel(),
        View.Help => BuildHelp(),
        _ => new Markup("Unknown view")
    };

    private IRenderable BuildDashboard()
    {
        var activity = BuildSparkline(_monitor.Activity.Select(a => (double)a.ConnectionCount).ToList(), "Activity");
        var threats = FilterThreats().Take(8).ToList();
        var hosts = FilterHosts().Take(8).ToList();

        var threatTable = new Table().Expand().Border(TableBorder.Simple);
        threatTable.AddColumns("Time", "Lvl", "IP", "Title");
        if (threats.Count == 0)
            threatTable.AddRow("-", "-", "-", "[dim]No threats yet[/]");
        else
        {
            for (var i = 0; i < threats.Count; i++)
            {
                var t = threats[i];
                var mark = i == _selectedIndex ? "[cyan]>[/] " : "  ";
                threatTable.AddRow(
                    mark + t.TimeText,
                    ColorLevel(t.Level),
                    Markup.Escape(t.SourceIp),
                    Markup.Escape(Truncate(t.Title, 40)));
            }
        }

        var hostTable = new Table().Expand().Border(TableBorder.Simple);
        // IP first (never cut for hostname length); host name is secondary.
        hostTable.AddColumns("IP", "Host", "Geo", "Threat", "Blk");
        if (hosts.Count == 0)
            hostTable.AddRow("[dim]No peers yet[/]", "-", "-", "-", "-");
        else
        {
            var hostW = Math.Max(12, (TermWidth / 2) - 28);
            var geoW = Math.Max(10, TermWidth / 8);
            foreach (var h in hosts)
            {
                h.IsBlocked = _blockedIps.Contains(h.IpAddress);
                hostTable.AddRow(
                    Markup.Escape(h.IpAddress),
                    Markup.Escape(Truncate(h.HostName, hostW)),
                    Markup.Escape(Truncate(h.GeoSummary, geoW)),
                    ColorLevel(h.ThreatLevel),
                    h.IsBlocked ? "[red]Y[/]" : "[dim]·[/]");
            }
        }

        var split = new Layout()
            .SplitRows(
                new Layout("spark").Size(5),
                new Layout("bottom").SplitColumns(
                    new Layout("threats"),
                    new Layout("hosts")));

        split["spark"].Update(new Panel(activity) { Header = new PanelHeader("[bold]Live activity[/]"), Border = BoxBorder.Rounded });
        split["bottom"]["threats"].Update(new Panel(threatTable) { Header = new PanelHeader("[bold]Recent threats[/]"), Border = BoxBorder.Rounded });
        split["bottom"]["hosts"].Update(new Panel(hostTable) { Header = new PanelHeader("[bold]Remote hosts[/]"), Border = BoxBorder.Rounded });
        return split;
    }

    private static string BuildSparkline(IReadOnlyList<double> values, string label)
    {
        if (values.Count == 0)
            return $"[dim]{label}: waiting for samples…[/]";

        const string blocks = " ▁▂▃▄▅▆▇█";
        var max = values.Max();
        if (max <= 0) max = 1;
        var sb = new StringBuilder();
        sb.Append($"[cyan]{label}[/]  ");
        foreach (var v in values.TakeLast(48))
        {
            var idx = (int)Math.Round(v / max * (blocks.Length - 1));
            idx = Math.Clamp(idx, 0, blocks.Length - 1);
            sb.Append(blocks[idx]);
        }

        sb.Append($"  [dim]now {values[^1]:0}  peak {max:0}[/]");
        return sb.ToString();
    }

    private IRenderable BuildConnectionsTable()
    {
        var rows = FilterConnections();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Live connections[/] ({rows.Count})");
        // Local/Remote show full endpoint (IP:port). Reverse-DNS is its own column so
        // long hostnames cannot truncate the address.
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Process"),
            new TableColumn("Local"),
            new TableColumn("Remote"),
            new TableColumn("Host"),
            new TableColumn("State"),
            new TableColumn("Geo"));

        var w = TermWidth;
        var procW = Math.Clamp(w / 10, 10, 18);
        var hostW = Math.Clamp(w / 5, 16, 40);
        var geoW = Math.Clamp(w / 6, 12, 28);
        // Endpoints: IPv6 + port can approach ~50 chars; keep room on wide terminals.
        var epW = Math.Clamp((w - 50) / 2, 22, 55);

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No matching connections[/]", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var c = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                var local = $"{c.LocalAddress}:{c.LocalPort}";
                var remote = string.IsNullOrWhiteSpace(c.RemoteAddress) || c.RemoteAddress is "0.0.0.0" or "::"
                    ? "—"
                    : $"{c.RemoteAddress}:{c.RemotePort}";
                table.AddRow(
                    sel,
                    Markup.Escape(Truncate(c.ProcessName, procW)),
                    Markup.Escape(Truncate(local, epW)),
                    Markup.Escape(Truncate(remote, epW)),
                    Markup.Escape(Truncate(c.RemoteHostName, hostW)),
                    Markup.Escape(c.StateText),
                    Markup.Escape(Truncate(c.GeoSummary, geoW)));
            }
        }

        return table;
    }

    private IRenderable BuildHostsTable()
    {
        var rows = FilterHosts();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Remote computers[/] ({rows.Count})");
        // IP column is untruncated (IPv6 ≤ 45). Hostname is separate so long DNS
        // names no longer clip the address off the right edge.
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("IP"),
            new TableColumn("Host"),
            new TableColumn("Origin"),
            new TableColumn("Act").Width(4),
            new TableColumn("Threat"),
            new TableColumn("Status"),
            new TableColumn("Block"));

        var w = TermWidth;
        var hostW = Math.Clamp(w / 4, 18, 48);
        var geoW = Math.Clamp(w / 5, 14, 36);
        // IPv6 max textual length is 45; always allow full IP.
        const int ipW = 45;

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No remote hosts yet[/]", "", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var h = rows[i];
                h.IsBlocked = _blockedIps.Contains(h.IpAddress);
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    Markup.Escape(Truncate(h.IpAddress, ipW)),
                    Markup.Escape(Truncate(h.HostName, hostW)),
                    Markup.Escape(Truncate(h.GeoSummary, geoW)),
                    h.ActiveConnections.ToString(),
                    ColorLevel(h.ThreatLevel),
                    Markup.Escape(Truncate(h.Status, 14)),
                    h.IsBlocked ? "[red]Blocked[/]" : "[green]Allowed[/]");
            }
        }

        return table;
    }

    private IRenderable BuildThreatsTable()
    {
        var rows = FilterThreats();
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Break-in attempts[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Time"),
            new TableColumn("Level"),
            new TableColumn("Type"),
            new TableColumn("Source IP"),
            new TableColumn("Title"),
            new TableColumn("Origin"));

        var w = TermWidth;
        var titleW = Math.Clamp(w / 4, 20, 48);
        var originW = Math.Clamp(w / 5, 16, 40);
        const int ipW = 45;

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No threat events[/]", "", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var t = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    t.TimeText,
                    ColorLevel(t.Level),
                    Markup.Escape(Truncate(t.TypeText, 18)),
                    Markup.Escape(Truncate(t.SourceIp, ipW)),
                    Markup.Escape(Truncate(t.Title, titleW)),
                    Markup.Escape(Truncate(t.Origin, originW)));
            }
        }

        return table;
    }

    private IRenderable BuildPortsTable()
    {
        var rows = _monitor.ListeningPorts;
        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Open ports[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Proto"),
            new TableColumn("Endpoint"),
            new TableColumn("PID"),
            new TableColumn("Process"),
            new TableColumn("Service"));

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
            table.AddRow(" ", "[dim]No listeners[/]", "", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var p = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    p.Protocol,
                    Markup.Escape(p.DisplayEndpoint),
                    p.ProcessId.ToString(),
                    Markup.Escape(Truncate(p.ProcessName, 20)),
                    Markup.Escape(Truncate(p.ServiceHint, 24)));
            }
        }

        return table;
    }

    private IRenderable BuildFirewallPanel()
    {
        IReadOnlyList<FirewallRuleInfo> rules;
        try
        {
            rules = _firewall.GetManagedRules();
        }
        catch (Exception ex)
        {
            return new Panel($"[red]Could not read firewall rules:[/] {Markup.Escape(ex.Message)}")
            {
                Header = new PanelHeader("[bold]Firewall[/]"),
                Border = BoxBorder.Rounded
            };
        }

        var info = new Markup(
            $"[bold]Privilege[/]: {Markup.Escape(_firewall.PrivilegeText)}\n" +
            $"[bold]Auto-block[/]: {(_autoBlockEnabled ? $"[red]ON ≥ {_autoBlockMinLevel}[/]" : "[grey]off[/]")}  " +
            $"in={_blockInbound} out={_blockOutbound}\n" +
            $"[bold]Allowlist[/]: {Markup.Escape(Truncate(_allowlist.StatusText, 70))}  [dim](view 7 · n add)[/]\n" +
            $"[bold]Blocked IPs (managed)[/]: {_blockedIps.Count}");

        var table = new Table().Expand().Border(TableBorder.Simple);
        table.AddColumns("", "Kind", "Dir", "Target", "Name");
        var visible = VisibleWindow(rules.Count);
        if (rules.Count == 0)
            table.AddRow(" ", "[dim]No Network Sentinel rules[/]", "", "", "");
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var r = rules[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                table.AddRow(
                    sel,
                    Markup.Escape(r.KindText),
                    Markup.Escape(r.DirectionText),
                    Markup.Escape(Truncate(r.TargetText, 28)),
                    Markup.Escape(Truncate(r.Name, 36)));
            }
        }

        var layout = new Layout().SplitRows(
            new Layout("info").Size(6),
            new Layout("rules"));
        layout["info"].Update(new Panel(info) { Header = new PanelHeader("[bold]Firewall & block[/]"), Border = BoxBorder.Rounded });
        layout["rules"].Update(new Panel(table) { Header = new PanelHeader($"[bold]Managed rules[/] ({rules.Count})"), Border = BoxBorder.Rounded });
        return layout;
    }

    private IRenderable BuildAllowlistPanel()
    {
        var rows = FilterAllowlist();
        var info = new Markup(
            $"[bold]Known-good allowlist[/] — these domains/IPs are [green]never blocked[/] by auto-block or manual block.\n" +
            $"{Markup.Escape(Truncate(_allowlist.StatusText, 100))}\n" +
            $"[dim]File:[/] {Markup.Escape(Truncate(_allowlist.LocalDatabasePath, 70))}\n" +
            "[dim]Keys:[/] [cyan]n[/]/[cyan]+[/] add domain or IP · [cyan]d[/] remove · [cyan]r[/] refresh · [cyan]g[/] restore good sites · [cyan]/[/] filter");

        var table = new Table().Expand().Border(TableBorder.Rounded);
        table.Title = new TableTitle($"[bold]Allowlist entries[/] ({rows.Count})");
        table.AddColumns(
            new TableColumn("").Width(2),
            new TableColumn("Kind").Width(12),
            new TableColumn("Value"),
            new TableColumn("Detail"));

        var visible = VisibleWindow(rows.Count);
        if (rows.Count == 0)
        {
            table.AddRow(" ", "[dim]Empty — press n to add a domain or IP[/]", "", "");
        }
        else
        {
            for (var i = visible.start; i < visible.end; i++)
            {
                var e = rows[i];
                var sel = i == _selectedIndex ? "[cyan]▶[/]" : " ";
                var kindColor = e.Kind.Equals("Domain", StringComparison.OrdinalIgnoreCase) ? "green"
                    : e.Kind.Equals("IP", StringComparison.OrdinalIgnoreCase) ? "cyan"
                    : e.Kind.Equals("Resolved", StringComparison.OrdinalIgnoreCase) ? "grey"
                    : "yellow";
                table.AddRow(
                    sel,
                    $"[{kindColor}]{Markup.Escape(e.Kind)}[/]",
                    Markup.Escape(Truncate(e.Value, Math.Clamp(TermWidth / 3, 32, 64))),
                    Markup.Escape(Truncate(e.Detail, Math.Clamp(TermWidth / 3, 24, 56))));
            }
        }

        var layout = new Layout().SplitRows(
            new Layout("info").Size(7),
            new Layout("list"));
        layout["info"].Update(new Panel(info)
        {
            Header = new PanelHeader("[bold]Allowlist (never block)[/]"),
            Border = BoxBorder.Rounded
        });
        layout["list"].Update(table);
        return layout;
    }

    private static IRenderable BuildHelp()
    {
        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold]Keyboard shortcuts[/]");
        table.AddColumns("Key", "Action");
        table.AddRow("1–7 / Tab", "Switch view (Dashboard…Allowlist)");
        table.AddRow("8 / h / F1", "Help");
        table.AddRow("↑↓ / j k", "Move selection");
        table.AddRow("PgUp/PgDn", "Scroll selection faster");
        table.AddRow("/ or f", "Set text filter");
        table.AddRow("Ctrl+L", "Clear filter");
        table.AddRow("p", "Pause / resume monitoring");
        table.AddRow("a", "Toggle auto-block");
        table.AddRow("m", "Cycle auto-block min severity");
        table.AddRow("b", "Block selected IP (or prompt)");
        table.AddRow("x", "Unblock selected IP (or prompt)");
        table.AddRow("u", "Authorize firewall elevation (pkexec)");
        table.AddRow("n / + / Ins", "Add domain or IP to allowlist");
        table.AddRow("d / Del", "Remove selected allowlist Domain/IP");
        table.AddRow("g", "Restore good sites (unblock allowlisted)");
        table.AddRow("c", "Clear threat alerts");
        table.AddRow("r", "Refresh firewall cache · on Allowlist: refresh DNS/feed");
        table.AddRow("q / Esc", "Quit");
        table.AddRow("", "[dim]Allowlist data: ~/.local/share/NetworkSentinel/allowlist.json[/]");
        return table;
    }

    private IRenderable BuildFooter()
    {
        var stats = _monitor.Stats;
        var keys = _view == View.Allowlist
            ? "[dim]7 allowlist · n/+ add domain or IP · d remove · r refresh · g restore · / filter · q quit[/]"
            : "[dim]1-7 views · p pause · a auto · b block · n allowlist-add · u auth · / filter · h help · q quit[/]";

        // Full address of the selected row so nothing is lost if a column is still tight.
        var selection = GetSelectedSummary();
        var msg = Markup.Escape(Truncate(_statusMessage, Math.Max(40, TermWidth - 4)));
        var status = string.IsNullOrEmpty(selection)
            ? $"[grey]{Markup.Escape(Truncate(stats.StatusText, 40))}[/]  {msg}"
            : $"[grey]{Markup.Escape(Truncate(stats.StatusText, 24))}[/]  [cyan]{Markup.Escape(Truncate(selection, TermWidth - 30))}[/]  {msg}";
        return new Panel(new Markup(keys + "\n" + status))
        {
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Grey)
        };
    }

    /// <summary>Full selected address/detail for the footer (avoids hidden truncation).</summary>
    private string GetSelectedSummary()
    {
        try
        {
            return _view switch
            {
                View.Hosts => FilterHosts().ElementAtOrDefault(_selectedIndex) is { } h
                    ? (string.IsNullOrWhiteSpace(h.HostName) ? h.IpAddress : $"{h.IpAddress}  {h.HostName}")
                    : "",
                View.Connections => FilterConnections().ElementAtOrDefault(_selectedIndex) is { } c
                    ? $"{c.RemoteAddress}:{c.RemotePort}" +
                      (string.IsNullOrWhiteSpace(c.RemoteHostName) ? "" : $"  {c.RemoteHostName}")
                    : "",
                View.Threats => FilterThreats().ElementAtOrDefault(_selectedIndex) is { } t
                    ? $"{t.SourceIp}  {t.Title}"
                    : "",
                View.Allowlist => FilterAllowlist().ElementAtOrDefault(_selectedIndex) is { } e
                    ? $"{e.Kind}: {e.Value}"
                    : "",
                _ => ""
            };
        }
        catch
        {
            return "";
        }
    }

    private (int start, int end) VisibleWindow(int count)
    {
        if (count <= 0) return (0, 0);
        var height = Math.Max(5, Console.WindowHeight - 16);
        var start = Math.Clamp(_scrollOffset, 0, Math.Max(0, count - 1));
        if (_selectedIndex < start) start = _selectedIndex;
        if (_selectedIndex >= start + height) start = _selectedIndex - height + 1;
        start = Math.Clamp(start, 0, Math.Max(0, count - height));
        _scrollOffset = start;
        var end = Math.Min(count, start + height);
        return (start, end);
    }

    private static string ColorLevel(ThreatLevel level) => level switch
    {
        ThreatLevel.Critical => "[red bold]Critical[/]",
        ThreatLevel.High => "[red]High[/]",
        ThreatLevel.Medium => "[yellow]Medium[/]",
        ThreatLevel.Low => "[blue]Low[/]",
        _ => "[grey]Info[/]"
    };

    private static int TermWidth
    {
        get
        {
            try { return Math.Max(60, Console.WindowWidth); }
            catch { return 120; }
        }
    }

    private static string Truncate(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (max <= 1) return s.Length <= 1 ? s : "…";
        return s.Length <= max ? s : s[..(max - 1)] + "…";
    }

    private static string FormatAppVersion()
    {
        try
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version;
            return v == null ? "v?" : $"v{v.Major}.{v.Minor}.{v.Build}";
        }
        catch
        {
            return "v?";
        }
    }

    public void Dispose()
    {
        _monitor.Updated -= OnMonitorUpdated;
        _monitor.ThreatsDetected -= OnThreatsDetected;
        _monitor.Dispose();
    }
}
