using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using NetworkSentinel.Models;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// Signature of <see cref="AllowlistService.IsAllowed"/>, so the DNS monitor can consult the
/// never-block list without taking a dependency on the service itself.
/// </summary>
public delegate bool AllowlistLookup(string ip, out string reason);

/// <summary>
/// Watches how this machine — and anything it forwards for — resolves names.
///
/// DNS is where a compromise usually shows first: almost nothing connects without
/// resolving a name, and DNS itself is a standard exfiltration channel that the
/// exfiltration monitor cannot see (it counts TCP socket bytes; DNS is UDP). Until
/// now this app had no view of DNS at all.
///
/// It also closes a specific hole in this app's own defences. AllowlistService
/// resolves allowlisted domains over whatever DNS the host is using, and
/// PreventionService will never auto-block a resolved allowlist address. Poison the
/// host's DNS and an attacker's address is written into the allowlist under a
/// trusted domain's name, permanently immune to blocking. Resolution drift is
/// detected here for exactly that reason.
///
/// What it can and cannot see:
///   - port 53 is plaintext DNS, and is detected wherever it goes
///   - port 853 is DoT, and is recognised as encrypted
///   - DoH is HTTPS on 443 and is indistinguishable from ordinary web traffic. It is
///     only counted as encrypted DNS when the destination is a resolver you listed
///     in <see cref="ApprovedResolvers"/> — allowlist entries do not count here, or every
///     HTTPS connection to a trusted site would read as encrypted DNS. Without that list,
///     a DoH setup looks like no DNS at all rather than like a leak.
///
/// Flows arrive from the ETW flow event source, which is also the only place UDP
/// peers are visible at all — an unconnected DNS socket has no remote address in
/// the UDP table. That needs Administrator; without it the status says so and no
/// detection runs.
/// </summary>
public sealed class DnsHygieneMonitor : IDisposable
{
    private const int DnsPort = 53;
    private const int DotPort = 853;
    private const int HttpsPort = 443;

    /// <summary>How long encrypted DNS must be absent before plaintext counts as a fallback.</summary>
    private static readonly TimeSpan FallbackQuietPeriod = TimeSpan.FromMinutes(5);

    private static readonly TimeSpan PlaintextCooldown = TimeSpan.FromHours(6);
    private static readonly TimeSpan UnapprovedCooldown = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan FallbackCooldown = TimeSpan.FromHours(1);
    private static readonly TimeSpan LeakCooldown = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan DriftCooldown = TimeSpan.FromHours(1);
    private static readonly TimeSpan LocalAddressRefresh = TimeSpan.FromMinutes(1);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.Ordinal);

    private HashSet<string> _approved = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _localAddresses = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _localAddressesAt = DateTime.MinValue;

    /// <summary>Networks each allowlisted domain has ever resolved into, for drift detection.</summary>
    private Dictionary<string, HashSet<string>> _domainNetworks = new(StringComparer.OrdinalIgnoreCase);

    private DateTime? _lastEncrypted;
    private DateTime? _lastPlaintext;
    private long _plaintextFlows;
    private long _encryptedFlows;

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private volatile string _status = "DNS hygiene monitoring not started";

    /// <summary>
    /// Resolvers you intend to use, comma separated. Queries anywhere else are treated as
    /// a hijack or a leak, and 443 traffic to these addresses counts as DoH.
    /// </summary>
    public string ApprovedResolvers
    {
        get { lock (_gate) return string.Join(",", _approved); }
        set
        {
            var parsed = ParseResolvers(value);
            lock (_gate) _approved = parsed;
        }
    }

    /// <summary>
    /// Tells the monitor whether an address belongs to a VPN client, so a forwarded query
    /// can be reported as a client leak rather than as this host's own traffic. Wired to
    /// the WireGuard peer list.
    /// </summary>
    public Func<string, bool>? IsVpnClientAddress { get; set; }

    /// <summary>
    /// Asks the allowlist whether a destination is already known-good, so a resolver you
    /// listed among your trusted sites counts as approved without having to be typed into
    /// <see cref="ApprovedResolvers"/> a second time. Wired to AllowlistService.IsAllowed.
    ///
    /// This only ever suppresses the <c>unapproved resolver</c> alert; the flow still falls
    /// through to the plaintext-egress and fallback checks, because an allowlisted address
    /// is a statement about who you trust, not about whether the query was encrypted.
    /// </summary>
    public AllowlistLookup? IsAddressAllowlisted { get; set; }

    public string Status => _status;

    /// <summary>Plaintext vs. encrypted DNS flows seen, for the console.</summary>
    public (long Plaintext, long Encrypted) Counters
        => (Interlocked.Read(ref _plaintextFlows), Interlocked.Read(ref _encryptedFlows));

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            LoadDomainNetworks();
            RefreshLocalAddresses(DateTime.Now);
            _loop = Task.Run(() => RunAsync(ct), ct);
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? loop;
        lock (_gate)
        {
            cts = _cts;
            loop = _loop;
            _cts = null;
            _loop = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { loop?.Wait(2000); } catch { /* shutting down */ }
        cts.Dispose();
        SaveDomainNetworks();
        _status = "DNS hygiene monitoring stopped";
    }

    public IReadOnlyList<ThreatEvent> DrainPending()
    {
        lock (_gate)
        {
            if (_pending.Count == 0) return Array.Empty<ThreatEvent>();
            var list = _pending.ToList();
            _pending.Clear();
            return list;
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.Now;
                lock (_gate)
                {
                    RefreshLocalAddresses(now);
                    _status = DescribeState(now);
                }
            }
            catch (Exception ex)
            {
                _status = $"DNS hygiene monitoring error: {ex.Message}";
            }

            try { await Task.Delay(TimeSpan.FromSeconds(20), ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>
    /// Classifies one new flow. Called on the ETW consumer thread for every new flow on
    /// the box, so the non-DNS path must stay cheap.
    /// </summary>
    public void ObserveFlow(FlowEvent flow, DateTime now)
    {
        var port = flow.DestinationPort;
        if (port is not (DnsPort or DotPort or HttpsPort))
            return;

        lock (_gate)
        {
            if (_cts == null) return;

            if (port == DotPort)
            {
                NoteEncrypted(now);
                return;
            }

            if (port == HttpsPort)
            {
                // Only 443 to a resolver you named is DoH; everything else on 443 is the web.
                if (_approved.Contains(flow.DestinationAddress))
                    NoteEncrypted(now);
                return;
            }

            // Plaintext DNS. Queries that stay on this machine are the wanted path —
            // a local resolver listening on loopback or on the tunnel address is exactly
            // the design that keeps queries visible here while encrypting the upstream hop.
            if (IsLocalAddress(flow.DestinationAddress))
                return;

            Interlocked.Increment(ref _plaintextFlows);
            _lastPlaintext = now;

            var fromVpnClient = IsVpnClientAddress?.Invoke(flow.SourceAddress) == true;
            var approved = IsApprovedDestination(flow.DestinationAddress, out var trustedBy);

            if (fromVpnClient)
            {
                AddClientLeak(flow, now);
                return;
            }

            // The approved list being empty means "not configured", not "nothing is approved" —
            // arming the check off the allowlist instead would flag every host that ever ran a
            // query, since the allowlist is populated out of the box.
            if (!approved && _approved.Count > 0)
            {
                AddUnapprovedResolver(flow, now);
                return;
            }

            // Encrypted DNS was working and has gone quiet while plaintext flows: most
            // resolvers fall back rather than fail, so this is the silent regression that
            // otherwise goes unnoticed for months.
            if (_lastEncrypted is { } enc && now - enc > FallbackQuietPeriod)
            {
                AddFallback(flow, enc, now);
                return;
            }

            AddPlaintextEgress(flow, now, trustedBy);
        }
    }

    /// <summary>
    /// Records where an allowlisted domain resolved. Called by AllowlistService after each
    /// refresh. Alerts when a domain's addresses move to networks it has never used —
    /// the shape of DNS poisoning aimed at this app's never-block list.
    /// </summary>
    public void ObserveAllowlistResolution(string domain, IReadOnlyCollection<string> ips, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(domain) || ips.Count == 0)
            return;

        var networks = ips.Select(NetworkOf).Where(n => n.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (networks.Count == 0)
            return;

        lock (_gate)
        {
            if (_cts == null) return;

            if (!_domainNetworks.TryGetValue(domain, out var known))
            {
                // First sighting seeds silently — the point of comparison does not exist yet.
                _domainNetworks[domain] = networks;
                return;
            }

            // Large sites legitimately rotate across many addresses, so only a move with
            // NO overlap against every network the domain has ever used is worth raising.
            if (known.Overlaps(networks))
            {
                foreach (var n in networks) known.Add(n);
                TrimNetworks(known);
                return;
            }

            var previous = string.Join(", ", known.Take(4));
            foreach (var n in networks) known.Add(n);
            TrimNetworks(known);

            if (!TryNoteEmit($"drift|{domain}", now, DriftCooldown))
                return;

            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.DnsAnomaly,
                Level = ThreatLevel.High,
                SourceIp = ips.First(),
                Title = $"Allowlisted domain {domain} moved networks",
                Detail = $"{domain} now resolves to {string.Join(", ", ips.Take(4))}, which shares no network " +
                         $"with anything it has resolved to before ({previous}). Allowlisted addresses are never " +
                         "auto-blocked, so a poisoned answer here would hand an attacker permanent immunity. " +
                         "Verify the domain really moved before trusting it.",
                Origin = "Resolving…",
                Method = "Allowlist resolution drift"
            });
        }
    }

    private void NoteEncrypted(DateTime now)
    {
        Interlocked.Increment(ref _encryptedFlows);
        _lastEncrypted = now;
    }

    /// <summary>
    /// Whether a destination is one this host is meant to resolve through: either typed into
    /// <see cref="ApprovedResolvers"/>, or already trusted by the allowlist. Checks the typed
    /// list first because it is a plain hash lookup and this runs per flow.
    /// </summary>
    private bool IsApprovedDestination(string address, out string trustedBy)
    {
        if (_approved.Contains(address))
        {
            trustedBy = "";
            return true;
        }

        if (IsAddressAllowlisted is { } lookup)
        {
            try
            {
                if (lookup(address, out var reason))
                {
                    trustedBy = string.IsNullOrWhiteSpace(reason) ? "the allowlist" : reason;
                    return true;
                }
            }
            catch
            {
                // A failing allowlist must not silence the check — fall through to unapproved.
            }
        }

        trustedBy = "";
        return false;
    }

    private void AddPlaintextEgress(FlowEvent flow, DateTime now, string trustedBy = "")
    {
        if (!TryNoteEmit($"plaintext|{flow.DestinationAddress}", now, PlaintextCooldown)) return;

        var trust = trustedBy.Length == 0
            ? ""
            : $"{flow.DestinationAddress} is not in your approved resolver list, but the allowlist already " +
              $"trusts it ({trustedBy}), so this is reported as a plaintext query rather than as a hijack. ";

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.DnsAnomaly,
            Level = ThreatLevel.Medium,
            SourceIp = flow.DestinationAddress,
            Title = $"Plaintext DNS to {flow.DestinationAddress}",
            Detail = trust +
                     "Queries are leaving this machine unencrypted on port 53, so the network path can read " +
                     "and rewrite them. Windows 11 can encrypt them itself — add the resolver with " +
                     "`netsh dns add encryption` and set the adapter to DoH — which keeps queries visible " +
                     "here while hiding them from the network.",
            Origin = "Resolving…",
            Method = "DNS hygiene · plaintext egress"
        });
    }

    private void AddUnapprovedResolver(FlowEvent flow, DateTime now)
    {
        if (!TryNoteEmit($"unapproved|{flow.DestinationAddress}", now, UnapprovedCooldown)) return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.DnsAnomaly,
            Level = ThreatLevel.High,
            SourceIp = flow.DestinationAddress,
            Title = $"DNS to unapproved resolver {flow.DestinationAddress}",
            Detail = $"{flow.SourceAddress} queried {flow.DestinationAddress}:53, which is neither in the " +
                     "approved resolver list nor on the allowlist. Something changed the resolver " +
                     "configuration, or answers are being redirected on the network. If this resolver is " +
                     "yours, add it to Approved resolvers — allowlisting it also clears this alert, but only " +
                     "the approved list makes HTTPS to it count as DoH.",
            Origin = "Resolving…",
            Method = "DNS hygiene · unapproved resolver"
        });
    }

    private void AddFallback(FlowEvent flow, DateTime lastEncrypted, DateTime now)
    {
        if (!TryNoteEmit("fallback", now, FallbackCooldown)) return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.DnsAnomaly,
            Level = ThreatLevel.High,
            SourceIp = flow.DestinationAddress,
            Title = "Encrypted DNS stopped — queries are in the clear",
            Detail = $"Encrypted DNS was last seen at {lastEncrypted:HH:mm:ss}, and plaintext queries to " +
                     $"{flow.DestinationAddress}:53 are flowing now. Resolvers usually fall back to plaintext " +
                     "rather than fail, so a broken upstream, a blocked port 853, or an expired certificate " +
                     "silently removes the protection you configured.",
            Origin = "Resolving…",
            Method = "DNS hygiene · encrypted-DNS fallback"
        });
    }

    private void AddClientLeak(FlowEvent flow, DateTime now)
    {
        if (!TryNoteEmit($"leak|{flow.SourceAddress}|{flow.DestinationAddress}", now, LeakCooldown)) return;

        _pending.Add(new ThreatEvent
        {
            Timestamp = now,
            Type = ThreatType.DnsAnomaly,
            Level = ThreatLevel.Medium,
            SourceIp = flow.DestinationAddress,
            Title = $"VPN client {flow.SourceAddress} is bypassing your resolver",
            Detail = $"Tunnel client {flow.SourceAddress} sent plaintext DNS straight to " +
                     $"{flow.DestinationAddress}:53 instead of using this server's resolver. Its lookups are " +
                     "visible to the network beyond this host, which is usually the exact thing the VPN was " +
                     "meant to prevent. Check that client's DNS setting.",
            Origin = "Resolving…",
            Method = "DNS hygiene · VPN client leak"
        });
    }

    private bool TryNoteEmit(string key, DateTime now, TimeSpan cooldown)
    {
        if (_lastEmit.TryGetValue(key, out var last) && now - last < cooldown)
            return false;
        _lastEmit[key] = now;
        if (_lastEmit.Count > 512)
        {
            foreach (var stale in _lastEmit.Where(kv => now - kv.Value > TimeSpan.FromHours(12))
                         .Select(kv => kv.Key).ToList())
                _lastEmit.Remove(stale);
        }
        return true;
    }

    private string DescribeState(DateTime now)
    {
        var (plain, enc) = Counters;
        if (plain == 0 && enc == 0)
            return "Watching DNS — no queries seen yet (needs Administrator for kernel flow events)";

        if (enc > 0 && _lastEncrypted is { } e && now - e <= FallbackQuietPeriod)
            return $"Encrypted DNS active · {enc} encrypted / {plain} plaintext flows seen";

        if (enc > 0)
            return $"Encrypted DNS last seen {(now - _lastEncrypted!.Value).TotalMinutes:0} min ago · " +
                   $"{enc} encrypted / {plain} plaintext flows seen";

        return $"No encrypted DNS seen · {plain} plaintext flows — queries are leaving in the clear";
    }

    /// <summary>
    /// Addresses that mean "this machine". A query to any of them stays local, which is
    /// the wanted arrangement rather than a leak.
    /// </summary>
    private void RefreshLocalAddresses(DateTime now)
    {
        if (now - _localAddressesAt < LocalAddressRefresh) return;
        _localAddressesAt = now;

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "::1" };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        set.Add(addr.Address.ToString());
                }
            }
        }
        catch
        {
            // Keep whatever we already had rather than treating everything as remote.
            if (_localAddresses.Count > 0) return;
        }

        _localAddresses = set;
    }

    private bool IsLocalAddress(string ip) => _localAddresses.Contains(ip);

    /// <summary>
    /// Coarse network key for drift comparison: /24 for IPv4, /48 for IPv6. Finer than
    /// this and every CDN rotation looks like an attack.
    /// </summary>
    internal static string NetworkOf(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return "";
        var bytes = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24",
            AddressFamily.InterNetworkV6 =>
                $"{bytes[0]:x2}{bytes[1]:x2}:{bytes[2]:x2}{bytes[3]:x2}:{bytes[4]:x2}{bytes[5]:x2}::/48",
            _ => ""
        };
    }

    internal static HashSet<string> ParseResolvers(string? raw)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw)) return set;
        foreach (var part in raw.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (IPAddress.TryParse(part.Trim(), out var ip))
                set.Add(ip.ToString());
        }
        return set;
    }

    private static void TrimNetworks(HashSet<string> networks)
    {
        // A domain that has legitimately used hundreds of networks tells us nothing;
        // cap the memory so the file cannot grow without bound.
        if (networks.Count <= 64) return;
        foreach (var extra in networks.Skip(64).ToList())
            networks.Remove(extra);
    }

    private static string StatePath => Path.Combine(AppPaths.DataDirectory, "dns-domain-networks.json");

    private void LoadDomainNetworks()
    {
        try
        {
            if (!File.Exists(StatePath)) return;
            var loaded = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(File.ReadAllText(StatePath));
            if (loaded == null) return;
            _domainNetworks = loaded.ToDictionary(
                kv => kv.Key,
                kv => new HashSet<string>(kv.Value, StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            _domainNetworks = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void SaveDomainNetworks()
    {
        try
        {
            Dictionary<string, List<string>> snapshot;
            lock (_gate)
                snapshot = _domainNetworks.ToDictionary(kv => kv.Key, kv => kv.Value.ToList());
            AppPaths.WriteAtomic(StatePath, JsonSerializer.Serialize(snapshot));
        }
        catch
        {
            // best-effort, same as the other stores
        }
    }

    public void Dispose() => Stop();
}
