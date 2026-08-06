using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>What happened to one threat that reached the prevention engine.</summary>
public enum PreventionAction
{
    /// <summary>A firewall rule was created.</summary>
    Blocked,
    /// <summary>Dry-run mode: the block was decided but deliberately not written.</summary>
    Simulated,
    /// <summary>The firewall rejected the rule.</summary>
    Failed
}

/// <summary>One acted-on threat. Threats filtered out by the gates never produce a decision.</summary>
public sealed class PreventionDecision
{
    public required string Ip { get; init; }
    public required PreventionAction Action { get; init; }
    public required string Message { get; init; }
    public required ThreatEvent Threat { get; init; }
}

/// <summary>Result of one <see cref="PreventionService.Apply"/> pass.</summary>
public sealed class PreventionResult
{
    public static readonly PreventionResult Empty = new();

    public IReadOnlyList<PreventionDecision> Decisions { get; init; } = Array.Empty<PreventionDecision>();

    /// <summary>Set when prevention could not run at all (no elevation); surfaced as UI status.</summary>
    public string? StatusMessage { get; init; }

    /// <summary>True when at least one real firewall rule was created — frontends should refresh.</summary>
    public bool RulesChanged => Decisions.Any(d => d.Action == PreventionAction.Blocked);

    public bool HasMessages => Decisions.Count > 0 || StatusMessage != null;

    /// <summary>Single-line summary in the format the GUI/TUI/web status bars already use.</summary>
    public string Summary => Decisions.Count > 0
        ? string.Join(" · ", Decisions.Select(d => d.Message))
        : StatusMessage ?? "";
}

/// <summary>
/// The single enforcement engine: every automatic block in Network Sentinel goes
/// through here, whatever raised the threat and whichever frontend is running.
///
/// This used to be three near-identical copies of ProcessAutoBlocks (GUI, TUI, web)
/// that had already drifted apart — only the web copy honoured the manual-unblock
/// suppression list, so the GUI and TUI would happily re-block an address the user
/// had just deliberately released. Detection sources keep multiplying (heuristics,
/// threat intel, honeypot, ARP, Suricata); the decision to drop traffic must not.
///
/// Ordered gates, cheapest first — a threat must clear all of them:
///   severity ≥ MinLevel → not informational-only → routable public IP →
///   not allowlisted → not protected → not already blocked →
///   not suppressed by a manual unblock → not attempted in the last RetryAfter.
///
/// In <see cref="DryRun"/> mode every gate still runs and decisions are still
/// reported, but no rule is written. That is the safe way to promote a noisy new
/// detection source (a fresh Suricata ruleset especially) from alerting to
/// blocking: watch what it *would* have dropped before letting it drop anything.
/// </summary>
public sealed class PreventionService
{
    /// <summary>How long to wait before retrying an IP whose block attempt failed.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(10);

    /// <summary>A manual unblock suppresses auto-block for this address for this long.</summary>
    public static readonly TimeSpan ManualUnblockSuppressFor = TimeSpan.FromHours(24);

    private static readonly TimeSpan BlockedIpsMaxAge = TimeSpan.FromSeconds(15);

    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;
    private readonly AppSettings _settings;

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _attempted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _suppressedUntil = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _protectedUntil = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _blockedIpsRefreshedAt = DateTime.MinValue;
    private bool _refreshInFlight;

    public PreventionService(FirewallService firewall, AllowlistService allowlist, AppSettings settings)
    {
        _firewall = firewall;
        _allowlist = allowlist;
        _settings = settings;

        Enabled = settings.AutoBlockEnabled;
        MinLevel = settings.GetMinLevel();
        BlockInbound = settings.AutoBlockInbound;
        BlockOutbound = settings.AutoBlockOutbound;
        DryRun = settings.PreventionDryRun;

        LoadPersistedSuppressions();
    }

    /// <summary>Master switch. Off means threats are still detected and shown, just never acted on.</summary>
    public bool Enabled { get; set; }

    /// <summary>Minimum severity that justifies dropping traffic.</summary>
    public ThreatLevel MinLevel { get; set; } = ThreatLevel.High;

    public bool BlockInbound { get; set; } = true;
    public bool BlockOutbound { get; set; } = true;

    /// <summary>
    /// Decide and report blocks without writing firewall rules. Inline prevention turns a
    /// false positive from noise into an outage, so a new detection source should run here
    /// first.
    /// </summary>
    public bool DryRun { get; set; }

    /// <summary>Addresses currently blocked by rules this app owns.</summary>
    public IReadOnlySet<string> BlockedIps
    {
        get { lock (_gate) return _blockedIps; }
    }

    public int BlockedCount
    {
        get { lock (_gate) return _blockedIps.Count; }
    }

    public bool IsBlocked(string ip)
    {
        lock (_gate) return _blockedIps.Contains(ip);
    }

    /// <summary>How long an address stays protected after the last sign of active administration.</summary>
    public static readonly TimeSpan ProtectionTtl = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Shields an address from auto-block for <see cref="ProtectionTtl"/>, on top of the
    /// allowlist. The console calls this for whoever is signed in and using it: prevention
    /// that firewalls the operator away from the box it protects has done more damage than
    /// the attack it stopped, and a fresh signature ruleset is exactly when that happens.
    ///
    /// Time-boxed and refreshed by use, so the set can't grow without bound and protection
    /// lapses once an admin stops working. Manual blocking is deliberately unaffected —
    /// this only stops the machine deciding on its own.
    /// </summary>
    public void Protect(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;
        if (FirewallService.IsPrivateOrLocal(normalized))
            return; // never auto-blocked anyway

        lock (_gate)
        {
            _protectedUntil[normalized] = DateTime.UtcNow.Add(ProtectionTtl);
            if (_protectedUntil.Count > 64)
                PruneExpired(_protectedUntil);
        }
    }

    public void Unprotect(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;
        lock (_gate) _protectedUntil.Remove(normalized);
    }

    /// <summary>Addresses currently shielded from auto-block by active administration.</summary>
    public IReadOnlyCollection<string> ProtectedIps
    {
        get
        {
            lock (_gate)
            {
                var now = DateTime.UtcNow;
                return _protectedUntil.Where(kv => kv.Value > now).Select(kv => kv.Key).ToList();
            }
        }
    }

    /// <summary>
    /// Runs the gates over a batch of threats and enforces what survives.
    /// Safe to call from any thread; blocking itself is serialised by the firewall.
    /// </summary>
    public PreventionResult Apply(IReadOnlyList<ThreatEvent> threats)
    {
        if (!Enabled || threats.Count == 0)
            return PreventionResult.Empty;

        if (!_firewall.IsAdministrator)
        {
            return new PreventionResult
            {
                StatusMessage = "Auto-block is ON, but firewall elevation is unavailable — run as root or install pkexec/sudo."
            };
        }

        var direction = ResolveDirection();
        var decisions = new List<PreventionDecision>();

        foreach (var threat in threats)
        {
            if (!ShouldConsider(threat, out var ip))
                continue;

            if (DryRun)
            {
                decisions.Add(new PreventionDecision
                {
                    Ip = ip,
                    Action = PreventionAction.Simulated,
                    Message = $"Would block {ip} ({threat.LevelText}: {threat.Title}) — dry run",
                    Threat = threat
                });
                continue;
            }

            var reason = $"Auto-block · {threat.LevelText} · {threat.TypeText}: {threat.Title}";
            var result = _firewall.BlockIp(ip, direction, reason, expiresAfter: _firewall.AutoBlockExpiry);

            if (result.Success)
            {
                lock (_gate) _blockedIps.Add(ip);
                decisions.Add(new PreventionDecision
                {
                    Ip = ip,
                    Action = PreventionAction.Blocked,
                    Message = $"Auto-blocked {ip} ({threat.LevelText}: {threat.Title})",
                    Threat = threat
                });
            }
            else
            {
                // Clear the attempt marker so the retry window doesn't hide a transient failure.
                lock (_gate) _attempted.Remove(ip);
                decisions.Add(new PreventionDecision
                {
                    Ip = ip,
                    Action = PreventionAction.Failed,
                    Message = $"Auto-block failed for {ip}: {result.Message}",
                    Threat = threat
                });
            }
        }

        return decisions.Count == 0 ? PreventionResult.Empty : new PreventionResult { Decisions = decisions };
    }

    /// <summary>
    /// The gate stack. Claims the attempt slot as a side effect when a threat passes, so two
    /// concurrent batches naming the same IP can't both try to block it.
    /// </summary>
    private bool ShouldConsider(ThreatEvent threat, out string ip)
    {
        ip = "";

        if (threat.Level < MinLevel)
            return false;

        // "New remote host" is informational — first contact is not evidence of anything.
        if (threat.Type == ThreatType.NewRemoteHost)
            return false;

        if (!FirewallService.TryNormalizeIp(threat.SourceIp, out var normalized, out _))
            return false;

        if (FirewallService.IsPrivateOrLocal(normalized))
            return false;

        if (_allowlist.IsAllowed(normalized, out _))
            return false;

        lock (_gate)
        {
            if (_protectedUntil.TryGetValue(normalized, out var protectedUntil) && DateTime.UtcNow < protectedUntil)
                return false;
            if (_blockedIps.Contains(normalized))
                return false;
            if (_suppressedUntil.TryGetValue(normalized, out var until) && DateTime.UtcNow < until)
                return false;
            if (_attempted.TryGetValue(normalized, out var last) && DateTime.UtcNow - last < RetryAfter)
                return false;

            _attempted[normalized] = DateTime.UtcNow;
        }

        ip = normalized;
        return true;
    }

    public FirewallDirection ResolveDirection()
    {
        if (BlockInbound && BlockOutbound) return FirewallDirection.Both;
        if (BlockInbound) return FirewallDirection.Inbound;
        if (BlockOutbound) return FirewallDirection.Outbound;
        return FirewallDirection.Both;
    }

    /// <summary>
    /// Re-reads the live rule set. Rate-limited to <see cref="BlockedIpsMaxAge"/> unless forced,
    /// because listing rules can mean shelling out to nft/iptables.
    /// </summary>
    public void RefreshBlockedIps(bool force, Action<IReadOnlySet<string>>? onRefreshed = null)
    {
        lock (_gate)
        {
            if (_refreshInFlight)
                return;
            if (!force && DateTime.UtcNow - _blockedIpsRefreshedAt < BlockedIpsMaxAge)
                return;
            _refreshInFlight = true;
        }

        _ = Task.Run(() =>
        {
            try
            {
                var set = _firewall.GetBlockedIps();
                lock (_gate)
                {
                    _blockedIps = set;
                    _blockedIpsRefreshedAt = DateTime.UtcNow;
                }
                onRefreshed?.Invoke(set);
            }
            catch
            {
                // Keep the previous snapshot; the next refresh will try again.
            }
            finally
            {
                lock (_gate) _refreshInFlight = false;
            }
        });
    }

    /// <summary>Synchronous refresh for startup paths that need the set before first paint.</summary>
    public IReadOnlySet<string> RefreshBlockedIpsNow()
    {
        var set = _firewall.GetBlockedIps();
        lock (_gate)
        {
            _blockedIps = set;
            _blockedIpsRefreshedAt = DateTime.UtcNow;
        }
        return set;
    }

    /// <summary>Record a block made outside the engine (a manual click) so it isn't retried.</summary>
    public void NoteBlocked(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;
        lock (_gate) _blockedIps.Add(normalized);
    }

    /// <summary>
    /// Record a manual unblock. Suppresses auto-block for that address for 24 h and persists
    /// it, so an address the user deliberately released stays released across restarts.
    /// </summary>
    public void NoteUnblocked(string ip, bool suppress = true)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;

        var until = DateTime.UtcNow.Add(ManualUnblockSuppressFor);
        lock (_gate)
        {
            _blockedIps.Remove(normalized);
            _attempted.Remove(normalized);
            if (!suppress)
                return;
            // Leave a cooldown marker so a concurrent batch also skips this address.
            _attempted[normalized] = DateTime.UtcNow;
            _suppressedUntil[normalized] = until;
        }

        _settings.AutoBlockSuppressedUntil[normalized] = until;
        PruneExpired(_settings.AutoBlockSuppressedUntil);
        _settings.Save();
    }

    /// <summary>Drop the suppression for one address (the user blocked it again on purpose).</summary>
    public void ClearSuppression(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            normalized = ip;

        lock (_gate) _suppressedUntil.Remove(normalized);

        if (_settings.AutoBlockSuppressedUntil.Remove(normalized))
            _settings.Save();
    }

    public bool IsSuppressed(string ip)
    {
        lock (_gate)
            return _suppressedUntil.TryGetValue(ip, out var until) && DateTime.UtcNow < until;
    }

    private void LoadPersistedSuppressions()
    {
        lock (_gate)
        {
            _suppressedUntil.Clear();
            foreach (var kv in _settings.AutoBlockSuppressedUntil)
            {
                if (kv.Value > DateTime.UtcNow)
                    _suppressedUntil[kv.Key] = kv.Value;
            }
        }
    }

    private static void PruneExpired(Dictionary<string, DateTime> map)
    {
        var now = DateTime.UtcNow;
        foreach (var key in map.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList())
            map.Remove(key);
    }

    /// <summary>Status line for the GUI/TUI/web footers.</summary>
    public string Describe()
    {
        if (!Enabled)
            return "Auto-block OFF";
        var mode = DryRun ? "DRY RUN" : "armed";
        return $"Auto-block {mode} (≥{MinLevel})";
    }
}
