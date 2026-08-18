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
    Failed,
    /// <summary>
    /// A gate held the block back for a reason worth saying out loud. Only the tunnel-endpoint
    /// gate reports: every other gate refuses something ordinary (a LAN address, an allowlisted
    /// host), while this one refuses a *threat* against a live VPN peer. Silence there sends the
    /// operator hunting through firewall rules for a block that was never made.
    /// </summary>
    Skipped
}

/// <summary>
/// One threat the engine acted on — or, for <see cref="PreventionAction.Skipped"/>, deliberately
/// did not. The other gates filter silently; only a refusal the operator would otherwise have to
/// explain to themselves produces a decision without a rule.
/// </summary>
public sealed class PreventionDecision
{
    public required string Ip { get; init; }
    public required PreventionAction Action { get; init; }
    public required string Message { get; init; }
    public required ThreatEvent Threat { get; init; }

    /// <summary>Why the firewall refused, on a <see cref="PreventionAction.Failed"/> decision.</summary>
    public string? FailureReason { get; init; }
}

/// <summary>Where an alert's address stands with the enforcement engine.</summary>
public enum BlockState
{
    /// <summary>A rule was just written for it.</summary>
    Blocked,
    /// <summary>A rule this app owns was already in place.</summary>
    AlreadyBlocked,
    /// <summary>Dry run: it cleared every gate, but no rule was written.</summary>
    WouldBlock,
    /// <summary>A block was attempted and the firewall refused it.</summary>
    Failed,
    /// <summary>Left alone — see the text for which gate stopped it.</summary>
    NotBlocked
}

/// <summary>
/// The answer to "is this address being blocked?", phrased for an alert.
/// </summary>
public sealed record EnforcementStatus(BlockState State, string Text)
{
    /// <summary>True when traffic to and from the address is actually being dropped.</summary>
    public bool IsBlocked => State is BlockState.Blocked or BlockState.AlreadyBlocked;

    /// <summary>
    /// The verdict as a table cell — <see cref="Text"/> is the tooltip that explains it.
    /// One vocabulary for all three threat tables, so the GUI, the TUI and the web console
    /// cannot end up describing the same state three different ways.
    /// </summary>
    public string ShortText => State switch
    {
        BlockState.Blocked or BlockState.AlreadyBlocked => "Blocked",
        BlockState.WouldBlock => "Dry run",
        BlockState.Failed => "Failed",
        _ => "No"
    };
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

    /// <summary>What this pass decided about <paramref name="ip"/>, if it reached a decision at all.</summary>
    public PreventionDecision? DecisionFor(string ip)
        => Decisions.FirstOrDefault(d => string.Equals(d.Ip, ip, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// The single enforcement engine: every automatic block in Network Sentinel goes
/// through here, whatever raised the threat and whichever frontend is running.
///
/// This used to be three near-identical copies of ProcessAutoBlocks (GUI, TUI, web)
/// maintained in parallel, each with its own copy of the blocked-IP cache, the retry
/// map and the suppression map. Detection sources keep multiplying (heuristics,
/// threat intel, honeypot, ARP, Suricata, WireGuard, DNS hygiene); the decision to
/// drop traffic must not.
///
/// Ordered gates, cheapest first — a threat must clear all of them:
///   severity ≥ MinLevel → not informational-only → routable public IP →
///   not allowlisted → not this machine's own address → not a protected
///   endpoint (WireGuard peers) → not operator-protected → not already blocked →
///   not suppressed by a manual unblock → not attempted in the last RetryAfter.
///
/// The engine also answers for the alert channels: <see cref="DescribeEnforcement"/>
/// turns a threat plus the pass that ran over its batch into the "is this address being
/// blocked?" line that desktop toasts and webhooks carry, so a warning and the console
/// can never disagree about what was done.
///
/// In <see cref="DryRun"/> mode every gate still runs and decisions are still
/// reported, but no rule is written. That is the safe way to promote a noisy new
/// detection source (a fresh Suricata ruleset especially) from alerting to
/// blocking: watch what it *would* have dropped before letting it drop anything.
/// </summary>
public sealed class PreventionService
{
    /// <summary>How long an address stays claimed once a batch decides to block it.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long an address waits after a block attempt that failed for a reason that
    /// is not about elevation — a netsh call killed by the process timeout, a rule
    /// store briefly locked by another writer, a transient RPC error from the firewall
    /// service. Deliberately short: the full <see cref="RetryAfter"/> left an actively
    /// hammering attacker un-blocked for ten minutes over one transient error, while
    /// retrying on every ~2 s poll spawns a subprocess per poll for a failure that may
    /// never clear.
    /// </summary>
    public static readonly TimeSpan FailedAttemptRetryAfter = TimeSpan.FromSeconds(45);

    /// <summary>A manual unblock suppresses auto-block for this address for this long.</summary>
    public static readonly TimeSpan ManualUnblockSuppressFor = TimeSpan.FromHours(24);

    /// <summary>How often the same address may repeat a "not blocking, it is a tunnel endpoint" note.</summary>
    public static readonly TimeSpan ProtectedNoteCooldown = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long auto-block stands down after elevation itself fails. Elevation failure
    /// is never per-address — an unelevated process fails for every IP alike — so
    /// without a global pause each threat in each poll batch would log its own identical
    /// failure until the operator relaunched as Administrator.
    /// </summary>
    public static readonly TimeSpan ElevationFailureBackoff = TimeSpan.FromMinutes(5);

    private static readonly TimeSpan BlockedIpsMaxAge = TimeSpan.FromSeconds(15);

    private readonly FirewallService _firewall;
    private readonly AllowlistService _allowlist;
    private readonly AppSettings _settings;

    private readonly object _gate = new();

    /// <summary>
    /// Address → UTC time it becomes eligible again. Claimed when a batch decides to
    /// act (so two concurrent batches can't both block the same IP), then either
    /// cleared on success or shortened to <see cref="FailedAttemptRetryAfter"/> on a
    /// recoverable failure. Absolute rather than "time of last attempt" so the wait
    /// can differ by outcome.
    /// </summary>
    private readonly Dictionary<string, DateTime> _skipUntil = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _suppressedUntil = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _protectedUntil = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Address → when a "not blocking a tunnel endpoint" note may be repeated.</summary>
    private readonly Dictionary<string, DateTime> _noteCooldown = new(StringComparer.OrdinalIgnoreCase);

    private HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _blockedIpsRefreshedAt = DateTime.MinValue;
    private bool _refreshInFlight;
    private DateTime _elevationBackoffUntil = DateTime.MinValue;

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

    /// <summary>
    /// Extra never-auto-block guard on top of the allowlist and the operator shield.
    /// The frontends wire this to the monitor's VPN tunnel-endpoint check, covering
    /// WireGuard peers and IPSec peers alike: an endpoint is the public address a tunnel's
    /// encrypted packets come from, so a detector that flags it (a "new peer" alert, a
    /// per-peer transfer alert, Suricata on the tunnel port, a heuristic tripped by a
    /// site-to-site peer's long-lived flows) would otherwise cut that VPN dead. Like the
    /// operator shield, this only stops the machine deciding on its own — manual blocking
    /// is deliberately unaffected.
    /// </summary>
    public Func<string, bool>? IsProtectedAddress { get; set; }

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

        // Dry run writes no rule, so it has nothing to elevate for. Demanding privilege to
        // *simulate* blocked the one workflow the mode exists for: checking what a new
        // detection source would drop before giving it the right to drop anything.
        if (!DryRun && !_firewall.IsAdministrator)
        {
            return new PreventionResult
            {
                StatusMessage = "Auto-block is ON, but Administrator rights are required — restart elevated."
            };
        }

        // Dry run never elevates, so it keeps reporting through a backoff window.
        if (!DryRun)
        {
            bool backedOff;
            lock (_gate) backedOff = DateTime.UtcNow < _elevationBackoffUntil;
            if (backedOff)
            {
                // Only worth a status line when something would actually have been acted on.
                return threats.Any(t => t.Level >= MinLevel && t.Type != ThreatType.NewRemoteHost)
                    ? new PreventionResult { StatusMessage = "Auto-block paused: firewall elevation failed — retrying in a few minutes." }
                    : PreventionResult.Empty;
            }
        }

        var direction = ResolveDirection();
        var decisions = new List<PreventionDecision>();

        foreach (var threat in threats)
        {
            if (!ShouldConsider(threat, claimSlot: !DryRun, out var ip, out var heldBack))
            {
                if (heldBack != null)
                    decisions.Add(heldBack);
                continue;
            }

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
                // The "already blocked" gate takes over from here.
                lock (_gate)
                {
                    _blockedIps.Add(ip);
                    _skipUntil.Remove(ip);
                }
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
                decisions.Add(new PreventionDecision
                {
                    Ip = ip,
                    Action = PreventionAction.Failed,
                    Message = $"Auto-block failed for {ip}: {result.Message}",
                    FailureReason = result.Message,
                    Threat = threat
                });

                if (LooksLikeElevationFailure(result.Message))
                {
                    // Elevation failures are global, not per-address — stop trying the
                    // rest of the batch and stand down for the backoff window. That
                    // pause, not the per-address claim, is what stops an identical
                    // failure per poll, so the address keeps its full claim here.
                    lock (_gate) _elevationBackoffUntil = DateTime.UtcNow.Add(ElevationFailureBackoff);
                    break;
                }

                // Anything else is per-address and may well be transient (a killed netsh,
                // a briefly locked rule store). Retry soon rather than leaving an active
                // attacker un-blocked for the full RetryAfter.
                lock (_gate) _skipUntil[ip] = DateTime.UtcNow.Add(FailedAttemptRetryAfter);
            }
        }

        return decisions.Count == 0 ? PreventionResult.Empty : new PreventionResult { Decisions = decisions };
    }

    /// <summary>
    /// Says whether the address an alert names is being blocked, in words that can go
    /// straight into the warning. Pass the <paramref name="result"/> of the pass that ran
    /// over the same batch: a decision it reached is the authoritative answer, and every
    /// other case is read back off the gates.
    ///
    /// A warning that names an address but says nothing about enforcement leaves the
    /// reader to go and work out whether anything stopped it — at the one moment they can
    /// least afford to. Null means the threat names no blockable address (a persistence
    /// change, a new local listener), so there is nothing to claim either way.
    /// </summary>
    public EnforcementStatus? DescribeEnforcement(ThreatEvent threat, PreventionResult? result = null)
    {
        if (!FirewallService.TryNormalizeIp(threat.SourceIp, out var ip, out _))
            return null;

        if (result?.DecisionFor(ip) is { } decision)
        {
            return decision.Action switch
            {
                PreventionAction.Blocked => new EnforcementStatus(
                    BlockState.Blocked, "BLOCKED — auto-block rule added"),
                PreventionAction.Simulated => new EnforcementStatus(
                    BlockState.WouldBlock, "NOT blocked — dry run (it would have been blocked)"),
                _ => new EnforcementStatus(
                    BlockState.Failed, $"NOT blocked — the firewall refused the rule: {decision.FailureReason}")
            };
        }

        if (FirewallService.IsPrivateOrLocal(ip))
            return new EnforcementStatus(BlockState.NotBlocked, "Not blocked — private address, never auto-blocked");

        // Most useful answer first: a rule already covers it, whatever the gates would say.
        if (IsBlocked(ip))
            return new EnforcementStatus(BlockState.AlreadyBlocked, "BLOCKED — a rule for this address is already in place");

        if (!Enabled)
            return new EnforcementStatus(BlockState.NotBlocked, "NOT blocked — auto-block is off");

        if (threat.Level < MinLevel)
            return new EnforcementStatus(BlockState.NotBlocked,
                $"Not blocked — below the auto-block level (≥{MinLevel})");

        if (threat.Type == ThreatType.NewRemoteHost)
            return new EnforcementStatus(BlockState.NotBlocked, "Not blocked — first contact is informational only");

        if (_allowlist.IsAllowed(ip, out var reason))
            return new EnforcementStatus(BlockState.NotBlocked,
                $"Not blocked — allowlisted{(string.IsNullOrWhiteSpace(reason) ? "" : $" ({reason})")}");

        if (LocalAddresses.IsOwnAddress(ip))
            return new EnforcementStatus(BlockState.NotBlocked, "Not blocked — this machine's own address");

        if (IsProtectedAddress is { } externallyProtected && externallyProtected(ip))
            return new EnforcementStatus(BlockState.NotBlocked, "Not blocked — protected endpoint (blocking it would cut a VPN tunnel)");

        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if (_protectedUntil.TryGetValue(ip, out var protectedUntil) && now < protectedUntil)
                return new EnforcementStatus(BlockState.NotBlocked, "Not blocked — protected while you are administering from it");
            if (_suppressedUntil.TryGetValue(ip, out var suppressedUntil) && now < suppressedUntil)
                return new EnforcementStatus(BlockState.NotBlocked, "NOT blocked — you released this address manually");
            if (now < _elevationBackoffUntil)
                return new EnforcementStatus(BlockState.NotBlocked, "NOT blocked — auto-block paused after a failed elevation");
            if (_skipUntil.TryGetValue(ip, out var eligibleAt) && now < eligibleAt)
                return new EnforcementStatus(BlockState.NotBlocked, "Not blocked yet — already claimed by an earlier attempt");
        }

        if (DryRun)
            return new EnforcementStatus(BlockState.WouldBlock, "NOT blocked — prevention is in dry-run mode");

        // Last, because it is the answer least likely to be the interesting one: only an
        // address that cleared every other gate has a privilege problem worth reporting.
        if (!_firewall.IsAdministrator)
            return new EnforcementStatus(BlockState.NotBlocked,
                "NOT blocked — Administrator rights are required (restart elevated)");

        return new EnforcementStatus(BlockState.NotBlocked, "NOT blocked");
    }

    /// <summary>
    /// Matches the failure text of every no-privilege path out of
    /// <see cref="FirewallService"/>: this process not being elevated, and netsh or the
    /// firewall service itself refusing the operation for want of Administrator rights.
    /// </summary>
    private static bool LooksLikeElevationFailure(string message)
        => message.Contains("Administrator rights are required", StringComparison.OrdinalIgnoreCase)
           || message.Contains("requires elevation", StringComparison.OrdinalIgnoreCase)
           || message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)
           || message.Contains("relaunch as Administrator", StringComparison.OrdinalIgnoreCase)
           || message.Contains("Not elevated", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The gate stack. When <paramref name="claimSlot"/> is set, a passing threat claims the
    /// address as a side effect, so two concurrent batches naming the same IP can't both try
    /// to block it. Dry run passes false — it decides but never acts.
    ///
    /// <paramref name="heldBack"/> is set when a gate refused something the operator needs to
    /// know about (currently only the tunnel-endpoint shield), so the refusal surfaces instead
    /// of looking like a block that silently never happened.
    /// </summary>
    private bool ShouldConsider(ThreatEvent threat, bool claimSlot, out string ip, out PreventionDecision? heldBack)
    {
        ip = "";
        heldBack = null;

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

        // Never the machine's own interface addresses: a detector that attributes a
        // threat to the wrong end of a flow (a public-IP host especially) must not be
        // able to firewall the box off from itself.
        if (LocalAddresses.IsOwnAddress(normalized))
            return false;

        if (IsProtectedAddress is { } externallyProtected && externallyProtected(normalized))
        {
            // Worth reporting: a threat really was raised against a live VPN peer, and the
            // only reason no rule exists is that dropping it would take the tunnel with it.
            if (ShouldNote(normalized))
            {
                heldBack = new PreventionDecision
                {
                    Ip = normalized,
                    Action = PreventionAction.Skipped,
                    Message = $"Not blocking {normalized} ({threat.LevelText}: {threat.Title}) — " +
                              "it is a VPN tunnel endpoint; blocking it would cut that tunnel. Block it manually if you mean to.",
                    Threat = threat
                };
            }
            return false;
        }

        lock (_gate)
        {
            if (_protectedUntil.TryGetValue(normalized, out var protectedUntil) && DateTime.UtcNow < protectedUntil)
                return false;
            if (_blockedIps.Contains(normalized))
                return false;
            if (_suppressedUntil.TryGetValue(normalized, out var until) && DateTime.UtcNow < until)
                return false;
            if (_skipUntil.TryGetValue(normalized, out var eligibleAt) && DateTime.UtcNow < eligibleAt)
                return false;

            // Dry run writes no rule, so it must not consume the address's turn either:
            // burning the slot here meant every address the operator had just watched
            // in dry run was skipped for RetryAfter once they switched blocking on.
            if (claimSlot)
                _skipUntil[normalized] = DateTime.UtcNow.Add(RetryAfter);
        }

        ip = normalized;
        return true;
    }

    /// <summary>
    /// Rate-limits the held-back notes. A peer whose traffic keeps tripping a heuristic
    /// would otherwise repeat the same line on every poll and bury everything else.
    /// </summary>
    private bool ShouldNote(string ip)
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            if (_noteCooldown.TryGetValue(ip, out var until) && now < until)
                return false;
            _noteCooldown[ip] = now.Add(ProtectedNoteCooldown);
            if (_noteCooldown.Count > 64)
                PruneExpired(_noteCooldown);
            return true;
        }
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
    /// because listing rules means walking the Windows Firewall COM object model.
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

    /// <summary>
    /// Lifts the elevation stand-down after the operator has authorized elevation.
    /// The backoff is set when a firewall write is refused for want of Administrator
    /// rights, and it used to expire only with time — so acting on "Authorize elevation"
    /// changed nothing for the next five minutes, and the console kept reporting
    /// auto-block as paused. The corrective action has to actually correct it.
    /// </summary>
    public void NoteElevationAuthorized()
    {
        lock (_gate)
        {
            _elevationBackoffUntil = DateTime.MinValue;
            // Addresses parked by the failures that led here deserve the retry too.
            foreach (var key in _skipUntil.Keys.ToList())
                _skipUntil.Remove(key);
        }
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
            _skipUntil.Remove(normalized);
            if (!suppress)
                return;
            // Leave a cooldown marker so a concurrent batch also skips this address.
            _skipUntil[normalized] = DateTime.UtcNow.Add(RetryAfter);
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

    /// <summary>
    /// Auto-block state for every status line that reports it: the GUI's hero subtitle and
    /// tray tooltip, the TUI footer, the web console's pill, and the messages all three
    /// show when the toggle is flipped.
    ///
    /// The frontends each used to build this string themselves, and every one of them
    /// dropped the same thing — dry run. A console reading "Auto-block ON (≥High)" while
    /// the engine is deliberately writing no rules is the one state the operator most needs
    /// named, so the engine that knows it says it.
    /// </summary>
    public string Describe()
    {
        if (!Enabled)
            return "Auto-block OFF";
        var mode = DryRun ? "DRY RUN" : "armed";
        return $"Auto-block {mode} (≥{MinLevel})";
    }

    /// <summary>
    /// <see cref="Describe"/> for somewhere with no room — a window title, a taskbar label.
    /// Still distinguishes dry run: the compact form is where it was lost before.
    /// </summary>
    public string DescribeShort()
        => !Enabled ? "auto off" : DryRun ? $"dry≥{MinLevel}" : $"auto≥{MinLevel}";
}
