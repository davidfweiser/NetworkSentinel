using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Models;
using NetworkSentinel.Services;

namespace NetworkSentinel.Web;

/// <summary>
/// Headless web UI for Network Sentinel — same monitoring / firewall services as the TUI/GUI.
/// Launch with <c>-w</c> / <c>--web</c>. Serves a browser dashboard on an uncommon free port.
/// </summary>
public sealed class WebApp : IDisposable
{
    /// <summary>
    /// High ports that common servers (HTTP, DBs, game/dev stacks) almost never claim.
    /// First free candidate wins; falls back to an OS-assigned ephemeral port.
    /// </summary>
    private static readonly int[] PreferredPorts =
    [
        18765, 18766, 18767, 27654, 31415, 41927, 47293, 52891, 58347, 61903
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private readonly NetworkMonitorService _monitor = new();
    private readonly FirewallService _firewall = new();
    private readonly AllowlistService _allowlist = new();
    private readonly WebAuthStore _auth = new();
    private readonly AppSettings _settings;
    private readonly object _autoBlockGate = new();
    private readonly Dictionary<string, DateTime> _autoBlockAttempted = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// IPs the user explicitly unblocked/removed. Auto-block must not recreate rules for these
    /// until the user manually blocks again (or the suppress window expires).
    /// </summary>
    private readonly Dictionary<string, DateTime> _autoBlockSuppressedUntil = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan AutoBlockRetryAfter = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ManualUnblockSuppressFor = TimeSpan.FromHours(24);

    private readonly int _port;
    private readonly bool _bindAll;
    private bool _listeningLocalOnly;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private string _statusMessage = "Web UI ready — monitoring started.";
    private bool _autoBlockEnabled;
    private string _autoBlockMinLevel;
    private bool _blockInbound;
    private bool _blockOutbound;
    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _blockedIpsRefreshedAt = DateTime.MinValue;
    private bool _blockedIpsRefreshInFlight;
    private readonly string _appVersion = FormatAppVersion();

    public int Port => _port;

    public WebApp(int? requestedPort = null, bool bindAll = true)
    {
        _bindAll = bindAll;
        _port = ResolvePort(requestedPort);
        _settings = AppSettings.Load();
        _autoBlockEnabled = _settings.AutoBlockEnabled;
        _autoBlockMinLevel = _settings.AutoBlockMinLevel;
        if (_autoBlockMinLevel is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
            _autoBlockMinLevel = nameof(ThreatLevel.High);
        _blockInbound = _settings.AutoBlockInbound;
        _blockOutbound = _settings.AutoBlockOutbound;

        _firewall.Allowlist = _allowlist;
        _monitor.GeoLookupsEnabled = _settings.GeoLookupEnabled;
        _allowlist.UseRemoteFeed = _settings.AllowlistUseRemoteFeed;
        _monitor.Updated += OnMonitorUpdated;
        _monitor.ThreatsDetected += OnThreatsDetected;
    }

    public async Task RunAsync()
    {
        _cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _cts.Cancel();
        };

        Console.WriteLine("Network Sentinel — headless web UI");
        Console.WriteLine("Loading allowlist…");

        try
        {
            await _allowlist.InitializeAsync(_cts.Token);
            _statusMessage = _allowlist.StatusText;
        }
        catch (Exception ex)
        {
            _statusMessage = $"Allowlist load error: {ex.Message}";
            Console.Error.WriteLine(_statusMessage);
        }

        LoadPersistedAutoBlockSuppressions();
        RefreshBlockedIps(force: true);
        _monitor.Start();

        _listener = new HttpListener();
        // HttpListener prefixes must end with '/'.
        // Windows: "+" (all interfaces) needs URL ACL or admin; fall back to localhost.
        // Linux: "*" binds all interfaces.
        var candidates = _bindAll
            ? (OperatingSystem.IsWindows()
                ? new[] { $"http://+:{_port}/", $"http://*:{_port}/", $"http://127.0.0.1:{_port}/" }
                : new[] { $"http://*:{_port}/", $"http://127.0.0.1:{_port}/" })
            : new[] { $"http://127.0.0.1:{_port}/" };

        Exception? lastBindError = null;
        string? boundPrefix = null;
        foreach (var prefix in candidates)
        {
            try
            {
                _listener.Prefixes.Clear();
                _listener.Prefixes.Add(prefix);
                _listener.Start();
                boundPrefix = prefix;
                break;
            }
            catch (Exception ex)
            {
                lastBindError = ex;
                try { _listener.Close(); } catch { /* ignore */ }
                _listener = new HttpListener();
            }
        }

        if (boundPrefix == null)
        {
            throw new InvalidOperationException(
                "Failed to bind web UI. Try another port with -w PORT, run as Administrator, " +
                "or reserve a URL ACL, e.g.:\n" +
                $"  netsh http add urlacl url=http://+:{_port}/ user=Everyone\n" +
                $"Detail: {lastBindError?.Message}", lastBindError);
        }

        _listeningLocalOnly = boundPrefix.Contains("127.0.0.1", StringComparison.Ordinal);
        if (_listeningLocalOnly && _bindAll)
        {
            Console.WriteLine(
                "Note: bound to localhost only (URL ACL / elevation required for all-interfaces). " +
                "Use SSH tunnel or add a URL ACL to expose the LAN.");
        }

        PrintListenBanner();

        try
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().WaitAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // A reset/aborted connection can surface here as HttpListenerException.
                    // That must never end the accept loop — Program.RunWeb treats an escape
                    // as fatal and exits the whole server process.
                    if (_cts.IsCancellationRequested)
                        break;
                    Console.Error.WriteLine($"Accept error (continuing): {ex.Message}");
                    await Task.Delay(100, CancellationToken.None);
                    continue;
                }

                // Handle each request without blocking the accept loop for long polls.
                _ = Task.Run(() => HandleRequestSafe(ctx));
            }
        }
        finally
        {
            _monitor.Stop();
            try { _listener.Stop(); } catch { /* ignore */ }
            Console.WriteLine("Network Sentinel web UI stopped.");
        }
    }

    private void PrintListenBanner()
    {
        Console.WriteLine();
        var scope = _listeningLocalOnly ? "localhost only" : (_bindAll ? "all interfaces" : "localhost only");
        Console.WriteLine($"  Listening on port {_port}  ({scope})");
        Console.WriteLine($"  Local:   http://127.0.0.1:{_port}/");
        if (_bindAll && !_listeningLocalOnly)
        {
            foreach (var ip in GetLanIpv4Addresses().Take(4))
                Console.WriteLine($"  Network: http://{ip}:{_port}/");
        }

        Console.WriteLine();
        Console.WriteLine("  Open the URL above in your browser.");
        if (_auth.IsConfigured)
            Console.WriteLine("  Master password required on every login.");
        else
            Console.WriteLine("  First visit: create a master password in the browser.");
        Console.WriteLine("  Press Ctrl+C to stop.");
        Console.WriteLine();
    }

    private static IEnumerable<string> GetLanIpv4Addresses()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback)
                    continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add(ua.Address.ToString());
                }
            }
        }
        catch
        {
            // best-effort only
        }
        return list;
    }

    private void HandleRequestSafe(HttpListenerContext ctx)
    {
        try
        {
            HandleRequest(ctx);
        }
        catch (Exception ex)
        {
            try
            {
                WriteJson(ctx.Response, 500, new { ok = false, message = ex.Message });
            }
            catch
            {
                try { ctx.Response.Abort(); } catch { /* ignore */ }
            }
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var res = ctx.Response;
        res.Headers["Cache-Control"] = "no-store";
        res.Headers["X-Content-Type-Options"] = "nosniff";

        var path = req.Url?.AbsolutePath?.TrimEnd('/') ?? "";
        if (path.Length == 0)
            path = "/";

        if (req.HttpMethod == "GET" && (path is "/" or "/index.html"))
        {
            WriteHtml(res, IndexHtml);
            return;
        }

        // --- Auth endpoints (public) ---
        if (req.HttpMethod == "GET" && path == "/api/auth/status")
        {
            var authed = _auth.IsSessionValid(GetSessionToken(req));
            WriteJson(res, 200, new
            {
                ok = true,
                configured = _auth.IsConfigured,
                authenticated = authed,
                minPasswordLength = WebAuthStore.MinPasswordLength
            });
            return;
        }

        if (req.HttpMethod == "POST" && path == "/api/auth/setup")
        {
            var body = ReadBody(req);
            var authReq = DeserializeAuth(body);
            if (authReq == null)
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (!_auth.TrySetup(authReq.Password ?? "", authReq.Confirm ?? authReq.Password ?? "", out var setupMsg))
            {
                // Slow down scripted setup attempts.
                Thread.Sleep(400);
                WriteJson(res, 400, new { ok = false, message = setupMsg });
                return;
            }

            var token = _auth.CreateSession();
            SetSessionCookie(res, token);
            WriteJson(res, 200, new { ok = true, message = setupMsg, authenticated = true });
            return;
        }

        if (req.HttpMethod == "POST" && path == "/api/auth/login")
        {
            var body = ReadBody(req);
            var authReq = DeserializeAuth(body);
            if (authReq == null)
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (!_auth.IsConfigured)
            {
                WriteJson(res, 400, new { ok = false, message = "Master password not set yet. Use setup." });
                return;
            }

            // Constant-ish delay on failure to blunt brute force.
            if (!_auth.VerifyPassword(authReq.Password ?? ""))
            {
                Thread.Sleep(600);
                WriteJson(res, 401, new { ok = false, message = "Incorrect master password." });
                return;
            }

            var token = _auth.CreateSession();
            SetSessionCookie(res, token);
            WriteJson(res, 200, new { ok = true, message = "Signed in.", authenticated = true });
            return;
        }

        if (req.HttpMethod == "POST" && path == "/api/auth/logout")
        {
            _auth.RevokeSession(GetSessionToken(req));
            ClearSessionCookie(res);
            WriteJson(res, 200, new { ok = true, message = "Signed out." });
            return;
        }

        // --- Protected API ---
        if (!_auth.IsSessionValid(GetSessionToken(req)))
        {
            WriteJson(res, 401, new
            {
                ok = false,
                message = "Authentication required.",
                configured = _auth.IsConfigured,
                authenticated = false
            });
            return;
        }

        if (req.HttpMethod == "GET" && path == "/api/state")
        {
            WriteJson(res, 200, BuildState());
            return;
        }

        if (req.HttpMethod == "POST" && path == "/api/action")
        {
            var body = ReadBody(req);
            ActionRequest? actionReq = null;
            try
            {
                actionReq = JsonSerializer.Deserialize<ActionRequest>(body, JsonOptions);
            }
            catch
            {
                WriteJson(res, 400, new { ok = false, message = "Invalid JSON body." });
                return;
            }

            if (actionReq == null || string.IsNullOrWhiteSpace(actionReq.Action))
            {
                WriteJson(res, 400, new { ok = false, message = "Missing action." });
                return;
            }

            var result = RunAction(actionReq);
            WriteJson(res, result.Ok ? 200 : 400, result);
            return;
        }

        WriteJson(res, 404, new { ok = false, message = "Not found." });
    }

    private static string ReadBody(HttpListenerRequest req)
    {
        using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
        return reader.ReadToEnd();
    }

    private AuthBody? DeserializeAuth(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<AuthBody>(body, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string? GetSessionToken(HttpListenerRequest req)
    {
        try
        {
            var cookie = req.Cookies[WebAuthStore.CookieName];
            if (cookie != null && !string.IsNullOrEmpty(cookie.Value))
                return cookie.Value;
        }
        catch
        {
            // ignore
        }

        // Also accept Authorization: Bearer <token> for non-browser clients.
        var authHeader = req.Headers["Authorization"];
        if (!string.IsNullOrEmpty(authHeader) &&
            authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authHeader["Bearer ".Length..].Trim();

        return null;
    }

    private static void SetSessionCookie(HttpListenerResponse res, string token)
    {
        // Session cookie (no Max-Age): browser discards on close → login again next visit.
        // HttpOnly so JS cannot read it; SameSite=Strict for CSRF-ish protection on POST.
        res.Headers.Add("Set-Cookie",
            $"{WebAuthStore.CookieName}={token}; Path=/; HttpOnly; SameSite=Strict");
    }

    private static void ClearSessionCookie(HttpListenerResponse res)
    {
        res.Headers.Add("Set-Cookie",
            $"{WebAuthStore.CookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    }

    private ActionResultDto RunAction(ActionRequest req)
    {
        try
        {
            switch (req.Action.Trim().ToLowerInvariant())
            {
                case "pause":
                    _monitor.Stop();
                    _statusMessage = "Monitoring paused.";
                    return ActionResultDto.Success(_statusMessage);

                case "resume":
                    _monitor.Start();
                    _statusMessage = "Monitoring resumed.";
                    return ActionResultDto.Success(_statusMessage);

                case "toggle_monitor":
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
                    return ActionResultDto.Success(_statusMessage);

                case "toggle_autoblock":
                    _autoBlockEnabled = !_autoBlockEnabled;
                    _settings.AutoBlockEnabled = _autoBlockEnabled;
                    _settings.Save();
                    _statusMessage = _autoBlockEnabled
                        ? $"Auto-block ON (≥ {_autoBlockMinLevel})" +
                          (_firewall.IsAdministrator ? "" : " — need Administrator for firewall changes")
                        : "Auto-block OFF";
                    return ActionResultDto.Success(_statusMessage);

                case "cycle_min_level":
                    _autoBlockMinLevel = _autoBlockMinLevel switch
                    {
                        nameof(ThreatLevel.Medium) => nameof(ThreatLevel.High),
                        nameof(ThreatLevel.High) => nameof(ThreatLevel.Critical),
                        _ => nameof(ThreatLevel.Medium)
                    };
                    _settings.AutoBlockMinLevel = _autoBlockMinLevel;
                    _settings.Save();
                    _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
                    return ActionResultDto.Success(_statusMessage);

                case "set_min_level":
                {
                    var level = (req.Value ?? "").Trim();
                    if (level is not (nameof(ThreatLevel.Medium) or nameof(ThreatLevel.High) or nameof(ThreatLevel.Critical)))
                        return ActionResultDto.Fail("Level must be Medium, High, or Critical.");
                    _autoBlockMinLevel = level;
                    _settings.AutoBlockMinLevel = level;
                    _settings.Save();
                    _statusMessage = $"Auto-block minimum severity: {_autoBlockMinLevel}";
                    return ActionResultDto.Success(_statusMessage);
                }

                case "clear_threats":
                    _monitor.ClearThreats();
                    _statusMessage = "Threat alerts cleared.";
                    return ActionResultDto.Success(_statusMessage);

                case "authorize":
                {
                    var r = _firewall.AuthorizeElevation();
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "block":
                {
                    var ip = (req.Ip ?? req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(ip))
                        return ActionResultDto.Fail("IP required.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot block — run as Administrator or use authorize first.");
                    var r = _firewall.BlockIp(ip, ResolveDirection(), $"Web UI block · {ip}");
                    if (r.Success)
                    {
                        var key = FirewallService.TryNormalizeIp(ip, out var normalized, out _) ? normalized : ip;
                        ClearAutoBlockSuppress(key);
                        lock (_autoBlockGate) _blockedIps.Add(key);
                        RefreshBlockedIps(force: true);
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "unblock":
                {
                    var ip = (req.Ip ?? req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(ip))
                        return ActionResultDto.Fail("IP required.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot unblock — run as Administrator or use authorize first.");
                    var r = _firewall.UnblockIp(ip);
                    if (r.Success)
                    {
                        if (FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                        {
                            SuppressAutoBlock(normalized);
                            lock (_autoBlockGate) _blockedIps.Remove(normalized);
                        }
                        RefreshBlockedIps(force: true);
                    }
                    _statusMessage = r.Message;
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "add_allowlist":
                {
                    var value = (req.Value ?? "").Trim();
                    if (string.IsNullOrEmpty(value))
                        return ActionResultDto.Fail("Domain or IP required.");
                    bool ok;
                    string message;
                    if (value.Contains('.') && !IPAddress.TryParse(value, out _) &&
                        value.Any(c => char.IsLetter(c)))
                        ok = _allowlist.TryAddDomain(value, out message);
                    else if (IPAddress.TryParse(value, out _))
                        ok = _allowlist.TryAddIp(value, out message);
                    else
                        ok = _allowlist.TryAddDomain(value, out message);
                    _statusMessage = message;
                    return ok ? ActionResultDto.Success(message) : ActionResultDto.Fail(message);
                }

                case "remove_allowlist":
                {
                    var value = (req.Value ?? "").Trim();
                    var kind = (req.Kind ?? "").Trim();
                    if (string.IsNullOrEmpty(value))
                        return ActionResultDto.Fail("Value required.");
                    if (string.IsNullOrEmpty(kind))
                        kind = IPAddress.TryParse(value, out _) ? "IP" : "Domain";
                    var ok = _allowlist.TryRemove(value, kind, out var message);
                    _statusMessage = message;
                    return ok ? ActionResultDto.Success(message) : ActionResultDto.Fail(message);
                }

                case "refresh_allowlist":
                {
                    try
                    {
                        _allowlist.RefreshAsync().GetAwaiter().GetResult();
                        _statusMessage = _allowlist.StatusText;
                        return ActionResultDto.Success(_statusMessage);
                    }
                    catch (Exception ex)
                    {
                        _statusMessage = $"Allowlist refresh failed: {ex.Message}";
                        return ActionResultDto.Fail(_statusMessage);
                    }
                }

                case "restore_allowlisted":
                {
                    var r = _firewall.UnblockAllowlistedAddresses();
                    _statusMessage = r.Message;
                    if (r.Success) RefreshBlockedIps(force: true);
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                case "remove_rule":
                {
                    // Decode HTML entities if the browser sent an attribute-escaped name.
                    var name = System.Net.WebUtility.HtmlDecode((req.Value ?? req.Name ?? "").Trim());
                    if (string.IsNullOrEmpty(name))
                        return ActionResultDto.Fail("Rule name required.");
                    if (IsOwnWebRule(name))
                        return ActionResultDto.Fail(
                            $"\"{name}\" is the allow rule that lets your browser reach this console — " +
                            "removing it from here would instantly cut off this page (it looks like a crash). " +
                            "To remove web access, use the desktop app or run uninstall-web-service.ps1 on the server.");
                    if (!_firewall.IsAdministrator)
                        return ActionResultDto.Fail("Cannot remove rules — run Network Sentinel elevated (Admin / service as SYSTEM).");

                    // netsh-only delete; never HNetCfg COM (MTA AccessViolation kills the host).
                    FirewallOperationResult r;
                    try
                    {
                        r = _firewall.RemoveRule(name);
                    }
                    catch (Exception ex)
                    {
                        _statusMessage = $"Remove failed: {ex.Message}";
                        return ActionResultDto.Fail(_statusMessage);
                    }

                    _statusMessage = r.Message;
                    if (r.Success)
                    {
                        // Keep auto-block from immediately recreating the same IP block.
                        if (FirewallService.TryExtractIpFromManagedRule(name, null, out var removedIp))
                            SuppressAutoBlock(removedIp);

                        try { RefreshBlockedIps(force: true); }
                        catch { /* ignore */ }
                    }
                    return r.Success ? ActionResultDto.Success(r.Message) : ActionResultDto.Fail(r.Message);
                }

                default:
                    return ActionResultDto.Fail($"Unknown action: {req.Action}");
            }
        }
        catch (Exception ex)
        {
            _statusMessage = $"Action failed: {ex.Message}";
            return ActionResultDto.Fail(_statusMessage);
        }
    }

    private object BuildState()
    {
        RefreshBlockedIps(force: false);
        var blocked = _blockedIps;
        var stats = _monitor.Stats;

        return new
        {
            ok = true,
            version = _appVersion,
            clock = DateTime.Now.ToString("dddd, MMM d  ·  HH:mm:ss"),
            statusMessage = _statusMessage,
            firewall = new
            {
                isAdmin = _firewall.IsAdministrator,
                isRoot = _firewall.IsRoot,
                privilegeText = _firewall.PrivilegeText
            },
            settings = new
            {
                autoBlockEnabled = _autoBlockEnabled,
                autoBlockMinLevel = _autoBlockMinLevel,
                blockInbound = _blockInbound,
                blockOutbound = _blockOutbound,
                isMonitoring = stats.IsMonitoring
            },
            stats = new
            {
                listeningPorts = stats.ListeningPorts,
                activeConnections = stats.ActiveConnections,
                remoteHosts = stats.RemoteHosts,
                threatsToday = stats.ThreatsToday,
                highThreats = stats.HighThreats,
                statusText = stats.StatusText,
                isMonitoring = stats.IsMonitoring
            },
            allowlistStatus = _allowlist.StatusText,
            connections = _monitor.Connections.Take(250).Select(c => new
            {
                protocol = c.Protocol,
                local = c.DisplayLocal,
                remote = c.DisplayRemote,
                remoteAddress = c.RemoteAddress,
                remotePort = c.RemotePort,
                state = c.StateText,
                process = c.ProcessName,
                pid = c.ProcessId,
                geo = c.GeoSummary,
                lastSeen = c.LastSeen.ToString("HH:mm:ss")
            }),
            hosts = _monitor.RemoteHosts.Take(250).Select(h => new
            {
                ip = h.IpAddress,
                name = h.DisplayName,
                hostName = h.HostName,
                geo = h.GeoSummary,
                active = h.ActiveConnections,
                total = h.TotalConnections,
                ports = h.PortsTouched,
                threat = h.ThreatText,
                threatLevel = (int)h.ThreatLevel,
                status = h.Status,
                blocked = blocked.Contains(h.IpAddress) || h.IsBlocked,
                lastSeen = h.LastSeenText
            }),
            threats = _monitor.Threats.Take(200).Select(t => new
            {
                time = t.TimeText,
                level = t.LevelText,
                levelNum = (int)t.Level,
                type = t.TypeText,
                sourceIp = t.SourceIp,
                title = t.Title,
                detail = t.Detail,
                origin = t.Origin,
                method = t.Method
            }),
            ports = _monitor.ListeningPorts.Select(p => new
            {
                protocol = p.Protocol,
                endpoint = p.DisplayEndpoint,
                port = p.Port,
                process = p.ProcessName,
                pid = p.ProcessId,
                hint = p.ServiceHint
            }),
            firewallRules = _firewall.GetManagedRules().Select(r => new
            {
                name = r.Name,
                isProtected = IsOwnWebRule(r.Name),
                kind = r.KindText,
                // Explicit address field so the UI always has an IP column even if target is a port.
                address = string.IsNullOrWhiteSpace(r.AddressText) ? r.TargetText : r.AddressText,
                target = r.TargetText,
                ports = r.LocalPorts,
                direction = r.DirectionText,
                protocol = r.Protocol,
                enabled = r.Enabled,
                action = r.ActionText,
                description = r.Description
            }),
            allowlist = _allowlist.GetEntries().Select(e => new
            {
                kind = e.Kind,
                value = e.Value,
                detail = e.Detail
            }),
            activity = _monitor.Activity.TakeLast(60).Select(a => new
            {
                time = a.Time.ToString("HH:mm:ss"),
                connections = a.ConnectionCount,
                threats = a.ThreatCount,
                hosts = a.RemoteHostCount
            })
        };
    }

    /// <summary>
    /// The inbound allow rule for THIS console's port. Removing it over the web kills the
    /// user's own browser connection mid-request — indistinguishable from a server crash.
    /// </summary>
    private bool IsOwnWebRule(string name)
        => string.Equals(name, $"{FirewallService.RulePrefix}-Web-{_port}", StringComparison.OrdinalIgnoreCase);

    private FirewallDirection ResolveDirection()
    {
        if (_blockInbound && _blockOutbound) return FirewallDirection.Both;
        if (_blockInbound) return FirewallDirection.Inbound;
        if (_blockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Both;
    }

    private void OnMonitorUpdated() => RefreshBlockedIps(force: false);

    private void OnThreatsDetected(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled || threats.Count == 0)
            return;

        _ = Task.Run(() =>
        {
            try { ProcessAutoBlocks(threats); }
            catch (Exception ex) { _statusMessage = $"Auto-block error: {ex.Message}"; }
        });
    }

    private void ProcessAutoBlocks(IReadOnlyList<ThreatEvent> threats)
    {
        if (!_autoBlockEnabled)
            return;

        if (!_firewall.IsAdministrator)
        {
            _statusMessage = "Auto-block ON, but not elevated — run as Administrator.";
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
                if (_autoBlockSuppressedUntil.TryGetValue(ip, out var until) && DateTime.UtcNow < until)
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
                    host.IsBlocked = set.Contains(host.IpAddress);
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

    private void SuppressAutoBlock(string ip)
    {
        var until = DateTime.UtcNow.Add(ManualUnblockSuppressFor);
        lock (_autoBlockGate)
        {
            _blockedIps.Remove(ip);
            // Leave a long cooldown marker so concurrent threat handlers also skip briefly.
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

    /// <summary>
    /// Picks a free port from preferred uncommon high ports, or an OS ephemeral port.
    /// If <paramref name="requested"/> is set, that port is required (throws if taken).
    /// </summary>
    public static int ResolvePort(int? requested)
    {
        if (requested is int p)
        {
            if (p is < 1 or > 65535)
                throw new ArgumentOutOfRangeException(nameof(requested), "Port must be 1–65535.");
            if (!IsPortAvailable(p))
                throw new InvalidOperationException($"Port {p} is already in use. Choose another with -w PORT.");
            return p;
        }

        foreach (var candidate in PreferredPorts)
        {
            if (IsPortAvailable(candidate))
                return candidate;
        }

        // Last resort: let the OS assign any free port.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static bool IsPortAvailable(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void WriteHtml(HttpListenerResponse res, string html)
    {
        var bytes = Encoding.UTF8.GetBytes(html);
        res.StatusCode = 200;
        res.ContentType = "text/html; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        res.OutputStream.Write(bytes, 0, bytes.Length);
        res.OutputStream.Close();
    }

    private static void WriteJson(HttpListenerResponse res, int status, object payload)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        res.StatusCode = status;
        res.ContentType = "application/json; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        res.OutputStream.Write(bytes, 0, bytes.Length);
        res.OutputStream.Close();
    }

    private static string FormatAppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "0.0.0" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { /* ignore */ }
        _listener?.Close();
        _monitor.Dispose();
        _allowlist.Dispose();
        _cts?.Dispose();
    }

    private sealed class ActionRequest
    {
        public string Action { get; set; } = "";
        public string? Ip { get; set; }
        public string? Value { get; set; }
        public string? Name { get; set; }
        public string? Kind { get; set; }
    }

    private sealed class AuthBody
    {
        public string? Password { get; set; }
        public string? Confirm { get; set; }
    }

    private sealed class ActionResultDto
    {
        public bool Ok { get; init; }
        public string Message { get; init; } = "";

        public static ActionResultDto Success(string message) => new() { Ok = true, Message = message };
        public static ActionResultDto Fail(string message) => new() { Ok = false, Message = message };
    }

    private const string IndexHtml =
"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Network Sentinel</title>
<style>
  :root {
    --bg-deep: #070b16;
    --bg-panel: #0e1628;
    --bg-card: #121c31;
    --bg-hover: #18243f;
    --stroke: rgba(168,197,255,.2);
    --stroke-strong: rgba(124,249,255,.34);
    --text: #f2f7ff;
    --text2: #93a4c3;
    --muted: #667794;
    --cyan: #3de7c8;
    --blue: #4c8dff;
    --violet: #9b7bff;
    --amber: #ffb020;
    --danger: #ff4d6d;
    --success: #3ddc97;
    --font: "Segoe UI", system-ui, -apple-system, sans-serif;
    --mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    font-family: var(--font); color: var(--text);
    background:
      radial-gradient(1200px 600px at 10% -10%, rgba(61,231,200,.08), transparent 50%),
      radial-gradient(900px 500px at 90% 0%, rgba(76,141,255,.1), transparent 45%),
      var(--bg-deep);
  }
  header {
    display: flex; flex-wrap: wrap; align-items: center; gap: 12px 20px;
    padding: 16px 22px; border-bottom: 1px solid var(--stroke);
    background: linear-gradient(180deg, #101b33, #0e1628);
    position: sticky; top: 0; z-index: 10;
  }
  .brand { display: flex; flex-direction: column; gap: 2px; min-width: 180px; }
  .brand h1 {
    margin: 0; font-size: 1.15rem; letter-spacing: .02em;
    background: linear-gradient(90deg, var(--cyan), var(--blue), var(--violet));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .brand .sub { color: var(--text2); font-size: .78rem; }
  .clock { color: var(--muted); font-size: .85rem; font-family: var(--mono); }
  nav { display: flex; flex-wrap: wrap; gap: 6px; flex: 1; }
  nav button, .actions button, .row-actions button {
    appearance: none; border: 1px solid var(--stroke); background: var(--bg-card);
    color: var(--text2); border-radius: 8px; padding: 7px 12px; cursor: pointer;
    font: inherit; font-size: .82rem; transition: .15s ease;
  }
  nav button:hover, .actions button:hover, .row-actions button:hover {
    background: var(--bg-hover); color: var(--text); border-color: var(--stroke-strong);
  }
  nav button.active {
    color: var(--text); border-color: transparent;
    background: linear-gradient(135deg, rgba(61,231,200,.25), rgba(76,141,255,.3));
  }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .actions button.primary {
    color: var(--bg-deep); font-weight: 600;
    background: linear-gradient(135deg, var(--cyan), var(--blue));
    border: none;
  }
  .actions button.danger { border-color: rgba(255,77,109,.4); color: #ffb0bd; }
  main { padding: 18px 22px 40px; max-width: 1400px; margin: 0 auto; }
  .status {
    margin-bottom: 14px; padding: 10px 14px; border-radius: 10px;
    background: var(--bg-panel); border: 1px solid var(--stroke);
    color: var(--text2); font-size: .88rem;
  }
  .status.err { border-color: rgba(255,77,109,.45); color: #ffb0bd; }
  .status.good { border-color: rgba(61,220,151,.4); color: #9fe8c8; }
  .cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px; margin-bottom: 16px;
  }
  .card {
    background: var(--bg-card); border: 1px solid var(--stroke);
    border-radius: 12px; padding: 14px 16px;
  }
  .card .label { color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; }
  .card .value { font-size: 1.55rem; font-weight: 650; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .card .value.cyan { color: var(--cyan); }
  .card .value.amber { color: var(--amber); }
  .card .value.danger { color: var(--danger); }
  .toolbar {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
    margin-bottom: 12px;
  }
  .toolbar input, .toolbar select, .modal input {
    background: var(--bg-deep); border: 1px solid var(--stroke); color: var(--text);
    border-radius: 8px; padding: 8px 12px; font: inherit; font-size: .88rem;
    min-width: 180px;
  }
  .toolbar input:focus, .modal input:focus { outline: 1px solid var(--blue); }
  table {
    width: 100%; border-collapse: collapse; font-size: .84rem;
    background: var(--bg-panel); border: 1px solid var(--stroke); border-radius: 12px;
    overflow: hidden;
  }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--stroke); vertical-align: top; }
  th {
    color: var(--muted); font-weight: 600; font-size: .72rem;
    text-transform: uppercase; letter-spacing: .05em; background: #0c1426;
    position: sticky; top: 0;
  }
  tbody tr:nth-child(even) td { background: rgba(255,255,255,.02); }
  tr:hover td { background: rgba(24,36,63,.55); }
  tr:last-child td { border-bottom: none; }
  [data-scroll] { scrollbar-width: thin; scrollbar-color: rgba(124,249,255,.25) transparent; }
  [data-scroll]::-webkit-scrollbar { width: 9px; height: 9px; }
  [data-scroll]::-webkit-scrollbar-thumb { background: rgba(124,249,255,.2); border-radius: 6px; }
  [data-scroll]::-webkit-scrollbar-thumb:hover { background: rgba(124,249,255,.35); }
  [data-scroll]::-webkit-scrollbar-track { background: transparent; }
  .chip {
    display: inline-block; padding: 1px 8px; border-radius: 999px; margin-right: 4px;
    font-size: .72rem; font-weight: 600;
    background: rgba(76,141,255,.16); color: #9ec0ff; border: 1px solid rgba(76,141,255,.25);
  }
  .row-actions button.rm { border-color: rgba(255,77,109,.4); color: #ffb0bd; }
  .row-actions button.rm:hover { background: rgba(255,77,109,.12); border-color: rgba(255,77,109,.65); color: #ffd3db; }
  .row-actions button:disabled { opacity: .55; cursor: wait; }
  .mono { font-family: var(--mono); font-size: .8rem; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: .72rem; font-weight: 600; letter-spacing: .02em;
  }
  .lvl-info, .lvl-low { background: rgba(76,141,255,.18); color: #9ec0ff; }
  .lvl-medium { background: rgba(255,176,32,.18); color: var(--amber); }
  .lvl-high { background: rgba(255,77,109,.18); color: #ff8da3; }
  .lvl-critical { background: rgba(255,77,109,.35); color: #fff; }
  .blocked { color: var(--danger); font-weight: 600; }
  .ok { color: var(--success); }
  .muted { color: var(--muted); }
  .empty { padding: 28px; text-align: center; color: var(--muted); }
  .pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 999px; font-size: .78rem;
    background: var(--bg-card); border: 1px solid var(--stroke); color: var(--text2);
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--success); box-shadow: 0 0 8px rgba(61,220,151,.6); }
  .dot.off { background: var(--amber); }
  .help { color: var(--text2); line-height: 1.55; max-width: 720px; }
  .help code {
    font-family: var(--mono); background: var(--bg-card); padding: 1px 6px;
    border-radius: 4px; font-size: .85em; border: 1px solid var(--stroke);
  }
  .modal-backdrop {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,.55);
    z-index: 50; align-items: center; justify-content: center; padding: 16px;
  }
  .modal-backdrop.show { display: flex; }
  .modal {
    background: var(--bg-panel); border: 1px solid var(--stroke-strong);
    border-radius: 14px; padding: 20px; width: min(420px, 100%);
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
  }
  .modal h3 { margin: 0 0 8px; font-size: 1rem; }
  .modal p { margin: 0 0 14px; color: var(--text2); font-size: .88rem; }
  .modal .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .hidden { display: none !important; }
  #authGate {
    position: fixed; inset: 0; z-index: 100;
    display: flex; align-items: center; justify-content: center;
    padding: 20px;
    background:
      radial-gradient(900px 500px at 20% 0%, rgba(61,231,200,.1), transparent 50%),
      radial-gradient(800px 400px at 90% 20%, rgba(76,141,255,.12), transparent 45%),
      rgba(7,11,22,.96);
  }
  #authGate.hidden { display: none !important; }
  .auth-card {
    width: min(420px, 100%);
    background: var(--bg-panel);
    border: 1px solid var(--stroke-strong);
    border-radius: 16px;
    padding: 28px 26px 24px;
    box-shadow: 0 24px 70px rgba(0,0,0,.5);
  }
  .auth-card h1 {
    margin: 0 0 6px; font-size: 1.25rem;
    background: linear-gradient(90deg, var(--cyan), var(--blue), var(--violet));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .auth-card .lead { color: var(--text2); font-size: .9rem; margin: 0 0 18px; line-height: 1.45; }
  .auth-card label {
    display: block; color: var(--muted); font-size: .75rem;
    text-transform: uppercase; letter-spacing: .05em; margin: 0 0 6px;
  }
  .auth-card input {
    width: 100%; background: var(--bg-deep); border: 1px solid var(--stroke);
    color: var(--text); border-radius: 8px; padding: 10px 12px;
    font: inherit; font-size: .95rem; margin-bottom: 14px;
  }
  .auth-card input:focus { outline: 1px solid var(--blue); border-color: var(--blue); }
  .auth-card .auth-error {
    color: #ffb0bd; font-size: .85rem; min-height: 1.2em; margin: 0 0 12px;
  }
  .auth-card button.submit {
    width: 100%; appearance: none; border: none; border-radius: 10px;
    padding: 11px 14px; font: inherit; font-weight: 650; font-size: .95rem;
    cursor: pointer; color: var(--bg-deep);
    background: linear-gradient(135deg, var(--cyan), var(--blue));
  }
  .auth-card button.submit:disabled { opacity: .55; cursor: wait; }
  .auth-card .hint { color: var(--muted); font-size: .78rem; margin: 14px 0 0; line-height: 1.4; }
  #appShell.hidden { display: none !important; }
  @media (max-width: 720px) {
    header { padding: 12px 14px; }
    main { padding: 12px 14px 32px; }
    th, td { padding: 8px; }
  }
</style>
</head>
<body>

<div id="authGate">
  <div class="auth-card">
    <h1>Network Sentinel</h1>
    <p class="lead" id="authLead">Checking session…</p>
    <form id="authForm" autocomplete="on">
      <div id="setupFields" class="hidden">
        <label for="pwConfirm">Confirm master password</label>
        <input id="pwConfirm" type="password" name="confirm" autocomplete="new-password" minlength="8" />
      </div>
      <label for="pw" id="pwLabel">Master password</label>
      <input id="pw" type="password" name="password" autocomplete="current-password" required minlength="8" autofocus />
      <p class="auth-error" id="authError"></p>
      <button type="submit" class="submit" id="authSubmit">Continue</button>
    </form>
    <p class="hint" id="authHint"></p>
  </div>
</div>

<div id="appShell" class="hidden">
<header>
  <div class="brand">
    <h1>Network Sentinel</h1>
    <div class="sub">Web console · <span id="ver">—</span></div>
  </div>
  <div class="clock" id="clock">—</div>
  <nav id="nav">
    <button data-tab="dashboard" class="active">Dashboard</button>
    <button data-tab="connections">Connections</button>
    <button data-tab="hosts">Hosts</button>
    <button data-tab="threats">Threats</button>
    <button data-tab="ports">Ports</button>
    <button data-tab="firewall">Firewall</button>
    <button data-tab="allowlist">Allowlist</button>
    <button data-tab="help">Help</button>
  </nav>
  <div class="actions">
    <button id="btnMonitor" class="primary">Pause</button>
    <button id="btnAuto">Auto-block</button>
    <button id="btnLevel">Min: High</button>
    <button id="btnAuth">Authorize</button>
    <button id="btnClear" class="danger">Clear alerts</button>
    <button id="btnLogout">Sign out</button>
  </div>
</header>
<main>
  <div class="status" id="status">Connecting…</div>

  <section id="tab-dashboard">
    <div class="cards" id="cards"></div>
    <div class="toolbar">
      <span class="pill"><span class="dot" id="monDot"></span> <span id="monLabel">—</span></span>
      <span class="pill" id="fwPill">—</span>
      <span class="pill" id="abPill">—</span>
    </div>
    <h3 style="margin:18px 0 8px;font-size:.95rem;color:var(--text2)">Recent threats</h3>
    <div id="dash-threats"></div>
  </section>

  <section id="tab-connections" class="hidden">
    <div class="toolbar">
      <input id="filterConn" placeholder="Filter connections…" />
    </div>
    <div id="tbl-connections"></div>
  </section>

  <section id="tab-hosts" class="hidden">
    <div class="toolbar">
      <input id="filterHosts" placeholder="Filter hosts…" />
      <input id="blockIp" placeholder="IP to block/unblock" class="mono" />
      <button id="btnBlock">Block IP</button>
      <button id="btnUnblock">Unblock IP</button>
    </div>
    <div id="tbl-hosts"></div>
  </section>

  <section id="tab-threats" class="hidden">
    <div class="toolbar">
      <input id="filterThreats" placeholder="Filter threats…" />
    </div>
    <div id="tbl-threats"></div>
  </section>

  <section id="tab-ports" class="hidden">
    <div id="tbl-ports"></div>
  </section>

  <section id="tab-firewall" class="hidden">
    <div class="toolbar">
      <button id="btnRestore">Restore allowlisted</button>
      <button id="btnRefreshFw">Refresh list</button>
    </div>
    <p class="muted" id="fwHint" style="margin:0 0 10px;font-size:.85rem">Each row is one block — Remove deletes its inbound and outbound rules together and keeps auto-block from re-adding it for 24h. Live refresh is off on this tab; click Refresh list to update. Requires Administrator.</p>
    <div id="tbl-firewall"></div>
  </section>

  <section id="tab-allowlist" class="hidden">
    <div class="toolbar">
      <input id="allowInput" placeholder="Domain or IP to allowlist" autocomplete="off" />
      <button id="btnAddAllow">Add</button>
      <button id="btnRefreshAllow">Refresh feed + list</button>
    </div>
    <p class="muted" id="allowStatus" style="margin:0 0 10px;font-size:.85rem"></p>
    <p class="muted" id="allowHint" style="margin:0 0 10px;font-size:.85rem">Live UI refresh is off on this tab so you can scroll the full list. Click Refresh feed + list to update.</p>
    <div id="tbl-allowlist"></div>
  </section>

  <section id="tab-help" class="hidden">
    <div class="help">
      <p><strong>Network Sentinel</strong> headless web UI — same monitoring and firewall stack as the desktop and TUI apps.</p>
      <p>Start with <code>NetworkSentinel -w</code> (optional port: <code>-w 18765</code>). The process picks a free high port when you omit one.</p>
      <ul>
        <li><strong>Dashboard</strong> — live counters and recent threats</li>
        <li><strong>Hosts</strong> — remote peers; block/unblock IPs</li>
        <li><strong>Auto-block</strong> — automatically block new threats at the chosen minimum severity</li>
        <li><strong>Authorize</strong> — prepare Administrator / UAC elevation for firewall changes</li>
        <li><strong>Allowlist</strong> — domains/IPs that are never blocked</li>
      </ul>
      <p class="muted">Firewall actions need Administrator. Prefer running the service elevated once rather than elevating per action.</p>
      <p class="muted">Web access is gated by a master password (set on first visit). Sign out or close the browser to require it again.</p>
    </div>
  </section>
</main>
</div>

<script>
(() => {
  let state = null;
  let tab = 'dashboard';
  let lastError = '';
  let authMode = 'check'; // check | setup | login | ok
  let pollTimer = null;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
    { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]
  ));

  function setStatus(msg, err, good) {
    const el = $('status');
    el.textContent = msg || '';
    el.classList.toggle('err', !!err);
    el.classList.toggle('good', !err && !!good);
  }

  function showAuth(mode, message) {
    authMode = mode;
    const gate = $('authGate');
    const shell = $('appShell');
    if (mode === 'ok') {
      gate.classList.add('hidden');
      shell.classList.remove('hidden');
      return;
    }
    gate.classList.remove('hidden');
    shell.classList.add('hidden');
    const setup = mode === 'setup';
    $('setupFields').classList.toggle('hidden', !setup);
    $('authLead').textContent = setup
      ? 'Create a master password to protect this console. You will need it every time you open the web UI.'
      : 'Enter the master password to continue.';
    $('pwLabel').textContent = setup ? 'New master password' : 'Master password';
    $('pw').autocomplete = setup ? 'new-password' : 'current-password';
    $('authSubmit').textContent = setup ? 'Create password & sign in' : 'Sign in';
    $('authHint').textContent = setup
      ? 'Minimum 8 characters. Stored only as a one-way hash on this machine.'
      : 'Session ends when you sign out, close the browser, or after 12 hours idle.';
    $('authError').textContent = message || '';
    $('pw').value = '';
    $('pwConfirm').value = '';
    setTimeout(() => $('pw').focus(), 50);
  }

  function lvlClass(level) {
    const l = String(level || '').toLowerCase();
    if (l === 'critical') return 'lvl-critical';
    if (l === 'high') return 'lvl-high';
    if (l === 'medium') return 'lvl-medium';
    return 'lvl-info';
  }

  function badge(level) {
    return `<span class="badge ${lvlClass(level)}">${esc(level)}</span>`;
  }

  function matchFilter(q, ...parts) {
    if (!q) return true;
    const s = parts.join(' ').toLowerCase();
    return s.includes(q.toLowerCase());
  }

  function table(headers, rowsHtml) {
    if (!rowsHtml) return `<div class="empty">No rows.</div>`;
    return `<div data-scroll style="overflow:auto;max-height:calc(100vh - 220px)"><table>
      <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table></div>`;
  }

  async function ensureAuth() {
    try {
      const res = await fetch('/api/auth/status', { cache: 'no-store', credentials: 'same-origin' });
      const data = await res.json();
      if (!data.configured) {
        showAuth('setup');
        return false;
      }
      if (!data.authenticated) {
        showAuth('login');
        return false;
      }
      showAuth('ok');
      return true;
    } catch (e) {
      showAuth('login', 'Cannot reach server: ' + (e.message || e));
      return false;
    }
  }

  let statusHoldUntil = 0;
  // Allowlist + Firewall tabs freeze live redraw so you can scroll and act on rows.
  // Dashboard/connections/etc. keep the 2s poll.
  function isFrozenTab() {
    return tab === 'allowlist' || tab === 'firewall';
  }

  async function fetchState() {
    const res = await fetch('/api/state', { cache: 'no-store', credentials: 'same-origin' });
    if (res.status === 401) {
      stopPolling();
      const body = await res.json().catch(() => ({}));
      showAuth(body.configured === false ? 'setup' : 'login', 'Sign in required.');
      return false;
    }
    if (!res.ok) throw new Error('HTTP ' + res.status);
    state = await res.json();
    lastError = '';
    return true;
  }

  async function apiAction(action, extra = {}) {
    const res = await fetch('/api/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ action, ...extra })
    });
    if (res.status === 401) {
      stopPolling();
      showAuth('login', 'Session expired. Sign in again.');
      return { ok: false, message: 'Authentication required.' };
    }
    const data = await res.json().catch(() => ({ ok: false, message: 'Bad response' }));
    if (data.message) {
      statusHoldUntil = Date.now() + 12000;
      setStatus(data.message, !data.ok, data.ok);
    }
    // Always pull once after an action so Add/Remove show up even on frozen tabs.
    try {
      if (await fetchState()) render({ forceLists: true });
    } catch { /* ignore */ }
    return data;
  }

  async function refresh() {
    // Frozen tabs: do not auto-redraw (scroll position + readability).
    if (isFrozenTab()) return;
    try {
      if (await fetchState()) render({ forceLists: true });
    } catch (e) {
      lastError = e.message || String(e);
      setStatus('Lost connection to Network Sentinel: ' + lastError, true);
    }
  }

  async function refreshFrozenTab() {
    try {
      if (await fetchState()) render({ forceLists: true });
      setStatus('List updated.', false);
      statusHoldUntil = Date.now() + 4000;
    } catch (e) {
      setStatus('Refresh failed: ' + (e.message || e), true);
    }
  }

  function startPolling() {
    stopPolling();
    if (!isFrozenTab()) {
      refresh();
      pollTimer = setInterval(refresh, 2500);
    } else {
      refreshFrozenTab();
    }
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function saveScroll(id) {
    const el = document.getElementById(id);
    if (!el) return 0;
    const sc = el.querySelector('[data-scroll]');
    return sc ? sc.scrollTop : 0;
  }
  function restoreScroll(id, top) {
    const el = document.getElementById(id);
    if (!el) return;
    const sc = el.querySelector('[data-scroll]');
    if (sc) sc.scrollTop = top || 0;
  }

  function render(opts) {
    opts = opts || {};
    if (!state) return;
    const forceLists = !!opts.forceLists;
    $('ver').textContent = 'v' + (state.version || '?');
    $('clock').textContent = state.clock || '';
    // Don't overwrite a recent action result (add/remove/block) with the generic status.
    if (state.statusMessage && Date.now() > statusHoldUntil)
      setStatus(state.statusMessage, false);

    const mon = !!(state.settings && state.settings.isMonitoring);
    $('btnMonitor').textContent = mon ? 'Pause' : 'Resume';
    $('monDot').className = 'dot ' + (mon ? 'on' : 'off');
    $('monLabel').textContent = mon ? 'Monitoring' : 'Paused';
    $('fwPill').textContent = state.firewall?.isAdmin ? 'Firewall: ready' : 'Firewall: needs elevation';
    const ab = state.settings?.autoBlockEnabled;
    $('abPill').textContent = ab
      ? `Auto-block ≥ ${state.settings.autoBlockMinLevel}`
      : 'Auto-block off';
    $('btnAuto').textContent = ab ? 'Auto-block ON' : 'Auto-block OFF';
    $('btnLevel').textContent = 'Min: ' + (state.settings?.autoBlockMinLevel || 'High');

    const s = state.stats || {};
    $('cards').innerHTML = [
      ['Listening', s.listeningPorts, 'cyan'],
      ['Connections', s.activeConnections, 'cyan'],
      ['Remote hosts', s.remoteHosts, ''],
      ['Threats today', s.threatsToday, 'amber'],
      ['High / critical', s.highThreats, 'danger']
    ].map(([label, val, cls]) => `
      <div class="card">
        <div class="label">${esc(label)}</div>
        <div class="value ${cls}">${esc(val ?? 0)}</div>
      </div>`).join('');

    const threats = state.threats || [];
    $('dash-threats').innerHTML = table(
      ['Time', 'Level', 'Type', 'Source', 'Title', 'Origin'],
      threats.slice(0, 12).map(t => `<tr>
        <td class="mono">${esc(t.time)}</td>
        <td>${badge(t.level)}</td>
        <td>${esc(t.type)}</td>
        <td class="mono">${esc(t.sourceIp)}</td>
        <td>${esc(t.title)}</td>
        <td class="muted">${esc(t.origin)}</td>
      </tr>`).join('')
    );

    const fq = $('filterConn').value.trim();
    $('tbl-connections').innerHTML = table(
      ['Proto', 'Local', 'Remote', 'State', 'Process', 'Geo', 'Last'],
      (state.connections || []).filter(c => matchFilter(fq, c.protocol, c.local, c.remote, c.state, c.process, c.geo))
        .map(c => `<tr>
          <td>${esc(c.protocol)}</td>
          <td class="mono">${esc(c.local)}</td>
          <td class="mono">${esc(c.remote)}</td>
          <td>${esc(c.state)}</td>
          <td>${esc(c.process)} <span class="muted">#${esc(c.pid)}</span></td>
          <td class="muted">${esc(c.geo)}</td>
          <td class="mono">${esc(c.lastSeen)}</td>
        </tr>`).join('')
    );

    const hq = $('filterHosts').value.trim();
    $('tbl-hosts').innerHTML = table(
      ['Host', 'Geo', 'Active', 'Total', 'Ports', 'Threat', 'Status', ''],
      (state.hosts || []).filter(h => matchFilter(hq, h.name, h.ip, h.geo, h.threat, h.status))
        .map(h => `<tr>
          <td class="mono">${esc(h.name)}</td>
          <td class="muted">${esc(h.geo)}</td>
          <td>${esc(h.active)}</td>
          <td>${esc(h.total)}</td>
          <td>${esc(h.ports)}</td>
          <td>${badge(h.threat)}</td>
          <td class="${h.blocked ? 'blocked' : 'ok'}">${h.blocked ? 'Blocked' : esc(h.status)}</td>
          <td class="row-actions">
            ${h.blocked
              ? `<button data-unblock="${esc(h.ip)}">Unblock</button>`
              : `<button data-block="${esc(h.ip)}">Block</button>`}
          </td>
        </tr>`).join('')
    );

    const tq = $('filterThreats').value.trim();
    $('tbl-threats').innerHTML = table(
      ['Time', 'Level', 'Type', 'Source', 'Title', 'Detail', 'Origin'],
      (state.threats || []).filter(t => matchFilter(tq, t.level, t.type, t.sourceIp, t.title, t.detail, t.origin))
        .map(t => `<tr>
          <td class="mono">${esc(t.time)}</td>
          <td>${badge(t.level)}</td>
          <td>${esc(t.type)}</td>
          <td class="mono">${esc(t.sourceIp)}</td>
          <td>${esc(t.title)}</td>
          <td class="muted">${esc(t.detail)}</td>
          <td class="muted">${esc(t.origin)}</td>
        </tr>`).join('')
    );

    $('tbl-ports').innerHTML = table(
      ['Proto', 'Endpoint', 'Process', 'Hint'],
      (state.ports || []).map(p => `<tr>
        <td>${esc(p.protocol)}</td>
        <td class="mono">${esc(p.endpoint)}</td>
        <td>${esc(p.process)} <span class="muted">#${esc(p.pid)}</span></td>
        <td class="muted">${esc(p.hint)}</td>
      </tr>`).join('')
    );

    // Heavy lists: only redraw when forced (tab open, action, manual refresh).
    // Auto-poll never redraws allowlist/firewall — that was resetting scroll every 2s.
    if (forceLists || !isFrozenTab()) {
      const fwScroll = saveScroll('tbl-firewall');
      const alScroll = saveScroll('tbl-allowlist');

      // One row per block: -In/-Out siblings are grouped, and Remove deletes the pair.
      const rules = state.firewallRules || [];
      const groups = new Map();
      rules.forEach((r, i) => {
        const m = /^(.*)-(In|Out)$/i.exec(r.name || '');
        const key = m ? m[1] : (r.name || 'rule-' + i);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(r);
      });
      $('tbl-firewall').innerHTML = table(
        ['Address / target', 'Kind', 'Directions', 'Proto', 'Action', 'Enabled', 'Rule', ''],
        [...groups.values()].map(pair => {
          const r = pair[0];
          const addr = r.address || r.target || '';
          const dirs = pair.map(x => `<span class="chip">${esc(x.direction || '?')}</span>`).join('');
          const baseName = (r.name || '').replace(/-(In|Out)$/i, '');
          const action = pair.some(x => x.isProtected)
            ? `<span class="chip" title="This rule lets your browser reach this console. Removing it would cut off this page. Use the desktop app or uninstall-web-service.ps1 instead.">this console</span>`
            : `<button type="button" class="rm" data-rm-rule="${esc(r.name || '')}">Remove</button>`;
          return `<tr>
            <td class="mono"><strong>${esc(addr)}</strong></td>
            <td>${esc(r.kind || '')}</td>
            <td>${dirs}</td>
            <td>${esc(r.protocol || '')}</td>
            <td>${esc(r.action || '')}</td>
            <td>${pair.some(x => x.enabled) ? 'On' : 'Off'}</td>
            <td class="mono muted" style="font-size:.8rem">${esc(baseName)}</td>
            <td class="row-actions">${action}</td>
          </tr>`;
        }).join('') || '<tr><td colspan="8" class="muted">No managed IP/port rules yet.</td></tr>'
      );

      $('allowStatus').textContent = state.allowlistStatus || '';
      const allowRows = (state.allowlist || []).slice().sort((a, b) => {
        const rank = k => k === 'Domain' || k === 'IP' ? 0 : k === 'CIDR' ? 1 : 2;
        return rank(a.kind) - rank(b.kind) || String(a.value).localeCompare(String(b.value));
      });
      $('tbl-allowlist').innerHTML = table(
        ['Kind', 'Value', 'Detail', ''],
        allowRows.map(e => `<tr>
          <td>${esc(e.kind || '')}</td>
          <td class="mono">${esc(e.value || '')}</td>
          <td class="muted">${esc(e.detail || '')}</td>
          <td class="row-actions">${
            (e.kind === 'Domain' || e.kind === 'IP')
              ? `<button type="button" class="rm" data-rm-allow="${esc(e.value || '')}" data-kind="${esc(e.kind || '')}">Remove</button>`
              : '<span class="muted">built-in</span>'
          }</td>
        </tr>`).join('') || '<tr><td colspan="4" class="muted">No allowlist entries loaded.</td></tr>'
      );

      restoreScroll('tbl-firewall', fwScroll);
      restoreScroll('tbl-allowlist', alScroll);
    }
  }

  document.getElementById('nav').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    tab = btn.dataset.tab;
    document.querySelectorAll('nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('main > section').forEach(sec => {
      sec.classList.toggle('hidden', sec.id !== 'tab-' + tab);
    });
    // Freeze live poll on allowlist/firewall so lists stay readable.
    if (isFrozenTab()) {
      stopPolling();
      refreshFrozenTab();
    } else if (!pollTimer) {
      startPolling();
    }
  });

  $('btnMonitor').onclick = async () => {
    await apiAction('toggle_monitor');
    // Monitor Pause also stops background UI polling (user expectation).
    if (state && state.settings && !state.settings.isMonitoring) {
      stopPolling();
      setStatus('Monitoring and live UI refresh paused. Open a tab or Resume to update.', false);
      statusHoldUntil = Date.now() + 8000;
    } else if (!isFrozenTab()) {
      startPolling();
    }
  };
  $('btnAuto').onclick = () => apiAction('toggle_autoblock');
  $('btnLevel').onclick = () => apiAction('cycle_min_level');
  $('btnAuth').onclick = () => apiAction('authorize');
  $('btnClear').onclick = () => apiAction('clear_threats');
  $('btnLogout').onclick = async () => {
    stopPolling();
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    state = null;
    showAuth('login', 'Signed out.');
  };
  $('btnBlock').onclick = () => {
    const ip = $('blockIp').value.trim();
    if (ip) apiAction('block', { ip });
  };
  $('btnUnblock').onclick = () => {
    const ip = $('blockIp').value.trim();
    if (ip) apiAction('unblock', { ip });
  };
  $('btnAddAllow').onclick = () => {
    const value = $('allowInput').value.trim();
    if (value) apiAction('add_allowlist', { value }).then(r => { if (r.ok) $('allowInput').value = ''; });
  };
  $('btnRefreshAllow').onclick = async () => {
    await apiAction('refresh_allowlist');
  };
  $('btnRefreshFw').onclick = () => refreshFrozenTab();
  $('btnRestore').onclick = () => apiAction('restore_allowlisted');
  $('allowInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $('btnAddAllow').click(); }
  });

  document.body.addEventListener('click', (e) => {
    const b = e.target.closest('[data-block]');
    if (b) { apiAction('block', { ip: b.dataset.block }); return; }
    const u = e.target.closest('[data-unblock]');
    if (u) { apiAction('unblock', { ip: u.dataset.unblock }); return; }
    const r = e.target.closest('[data-rm-allow]');
    if (r) {
      apiAction('remove_allowlist', { value: r.dataset.rmAllow, kind: r.dataset.kind });
      return;
    }
    const fr = e.target.closest('[data-rm-rule]');
    if (fr) {
      // Prefer dataset (decoded) over getAttribute (may still contain entities).
      const name = (fr.dataset.rmRule || fr.getAttribute('data-rm-rule') || '').trim();
      if (!name) {
        setStatus('Could not read rule name from the row.', true);
        return;
      }
      const base = name.replace(/-(In|Out)$/i, '');
      if (confirm('Remove this block (inbound + outbound)?\n\n' + base + '\n\n(Requires Administrator)')) {
        fr.disabled = true;
        fr.textContent = 'Removing…';
        apiAction('remove_rule', { value: name, name: name }).finally(() => {
          // Re-render usually replaced the button; restore it if the row survived (failure).
          if (fr.isConnected) { fr.disabled = false; fr.textContent = 'Remove'; }
        });
      }
    }
  });

  ['filterConn', 'filterHosts', 'filterThreats'].forEach(id => {
    $(id).addEventListener('input', () => {
      if (state && !isFrozenTab()) render({ forceLists: true });
    });
  });

  $('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = $('pw').value;
    const confirm = $('pwConfirm').value;
    const setup = authMode === 'setup';
    $('authError').textContent = '';
    $('authSubmit').disabled = true;
    try {
      const res = await fetch(setup ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(setup ? { password, confirm } : { password })
      });
      const data = await res.json().catch(() => ({ ok: false, message: 'Bad response' }));
      if (!res.ok || !data.ok) {
        $('authError').textContent = data.message || 'Authentication failed.';
        return;
      }
      showAuth('ok');
      startPolling();
    } catch (err) {
      $('authError').textContent = err.message || String(err);
    } finally {
      $('authSubmit').disabled = false;
    }
  });

  (async () => {
    if (await ensureAuth()) startPolling();
  })();
})();
</script>
</body>
</html>
""";
}
