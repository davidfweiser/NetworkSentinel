using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSentinel.Services;

/// <summary>
/// Known-good domain/IP database. Prevents blocking trusted services
/// (GitHub, xAI/Grok, Microsoft, etc.). Combines built-in defaults,
/// a local user JSON file, and an optional remote JSON feed.
/// </summary>
public sealed class AllowlistService : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(12) };
    private readonly object _gate = new();
    private readonly SemaphoreSlim _resolveGate = new(1, 1);
    private readonly ConcurrentDictionary<string, string> _ipToReason = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _staticIps = new(StringComparer.OrdinalIgnoreCase);
    // Last successfully resolved IPs per domain — kept when a later DNS pass
    // fails so a DNS outage never strips allowlist protection.
    private readonly Dictionary<string, HashSet<string>> _domainIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(IPAddress Network, int Prefix)> _cidrs = new();
    private readonly List<AllowlistEntryView> _entries = new();
    private DateTime _lastResolveUtc = DateTime.MinValue;
    private DateTime _lastRemoteFetchUtc = DateTime.MinValue;

    public const string DefaultRemoteUrl =
        "https://raw.githubusercontent.com/davidfweiser/NetworkSentinel/main/Data/allowlist-default.json";

    public string LocalDatabasePath { get; }
    public string StatusText { get; private set; } = "Allowlist not loaded.";
    public int DomainCount { get { lock (_gate) return _domains.Count; } }
    public int ProtectedIpCount => _ipToReason.Count;
    public bool UseRemoteFeed { get; set; } = true;
    public string RemoteFeedUrl { get; set; } = DefaultRemoteUrl;

    public AllowlistService()
    {
        LocalDatabasePath = Path.Combine(AppPaths.DataDirectory, "allowlist.json");
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkSentinel/1.0 (allowlist)");
    }

    public IReadOnlyList<AllowlistEntryView> GetEntries()
    {
        lock (_gate)
            return _entries.OrderBy(e => e.Kind).ThenBy(e => e.Value).ToList();
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        LoadAllSources(includeRemote: false);
        await ResolveDomainsAsync(force: true, ct);
        if (UseRemoteFeed)
        {
            await TryFetchRemoteAsync(ct);
            await ResolveDomainsAsync(force: true, ct);
        }

        StatusText = $"Allowlist ready · {_domains.Count} domains · {_staticIps.Count} static IPs · {_ipToReason.Count} resolved IPs protected.";
    }

    public async Task RefreshAsync(CancellationToken ct = default)
    {
        LoadAllSources(includeRemote: false);
        if (UseRemoteFeed)
            await TryFetchRemoteAsync(ct);
        await ResolveDomainsAsync(force: true, ct);
        StatusText = $"Allowlist refreshed · {_domains.Count} domains · {_ipToReason.Count} IPs protected · {DateTime.Now:HH:mm:ss}.";
    }

    public bool IsAllowed(string ip, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(ip))
            return false;

        if (!IPAddress.TryParse(ip.Trim(), out var address))
            return false;

        var key = address.ToString();

        if (_ipToReason.TryGetValue(key, out var why))
        {
            reason = why;
            return true;
        }

        // Also check IPv4-mapped forms
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
        {
            var v4 = address.MapToIPv4().ToString();
            if (_ipToReason.TryGetValue(v4, out why))
            {
                reason = why;
                return true;
            }
        }

        lock (_gate)
        {
            if (_staticIps.Contains(key))
            {
                reason = "Static allowlist IP";
                return true;
            }

            foreach (var (network, prefix) in _cidrs)
            {
                if (IsInCidr(address, network, prefix))
                {
                    reason = $"Allowlist CIDR {network}/{prefix}";
                    return true;
                }
            }
        }

        // Opportunistic refresh if stale (fire-and-forget)
        if (DateTime.UtcNow - _lastResolveUtc > TimeSpan.FromMinutes(30))
            _ = ResolveDomainsAsync(force: false);

        return false;
    }

    public bool TryAddDomain(string domain, out string message)
    {
        domain = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(domain) || domain.Contains(' '))
        {
            message = "Enter a valid domain (e.g. github.com).";
            return false;
        }

        lock (_gate)
        {
            if (!_domains.Add(domain))
            {
                message = $"{domain} is already on the allowlist.";
                return false;
            }
        }

        SaveUserDatabase();
        _ = ResolveDomainsAsync(force: true);
        message = $"Added {domain} to the allowlist.";
        return true;
    }

    public bool TryAddIp(string ip, out string message)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out var error))
        {
            message = error;
            return false;
        }

        lock (_gate)
        {
            _staticIps.Add(normalized);
        }

        _ipToReason[normalized] = "User allowlist IP";
        SaveUserDatabase();
        RebuildEntryViews();
        message = $"Added {normalized} to the allowlist.";
        return true;
    }

    public bool TryRemove(string value, string kind, out string message)
    {
        value = value.Trim();
        lock (_gate)
        {
            if (kind.Equals("Domain", StringComparison.OrdinalIgnoreCase))
            {
                if (_domains.Remove(NormalizeDomain(value)))
                {
                    SaveUserDatabase();
                    // drop resolved IPs that only cited this domain — full re-resolve
                    message = $"Removed domain {value}.";
                }
                else
                {
                    message = "Domain not found.";
                    return false;
                }
            }
            else if (kind.Equals("IP", StringComparison.OrdinalIgnoreCase))
            {
                if (_staticIps.Remove(value))
                {
                    _ipToReason.TryRemove(value, out _);
                    SaveUserDatabase();
                    message = $"Removed IP {value}.";
                }
                else
                {
                    message = "Only user-added static IPs can be removed here (built-in list is protected).";
                    return false;
                }
            }
            else if (kind.Equals("CIDR", StringComparison.OrdinalIgnoreCase))
            {
                message = "CIDR ranges come from the allowlist JSON files — edit those to remove them.";
                return false;
            }
            else
            {
                message = "Unknown entry kind.";
                return false;
            }
        }

        _ = ResolveDomainsAsync(force: true);
        return true;
    }

    public void EnsureUserDatabaseExists()
    {
        if (File.Exists(LocalDatabasePath))
            return;

        var seed = new AllowlistFile
        {
            Version = 1,
            Description = "Your personal allowlist. Domains and IPs here are never blocked by Network Sentinel.",
            Domains = new List<string>(),
            Ips = new List<string>(),
            Notes = "Add domains like \"myservice.example.com\" or literal IPs. Built-in defaults are always merged."
        };
        File.WriteAllText(LocalDatabasePath, JsonSerializer.Serialize(seed, JsonOptions));
    }

    private void LoadAllSources(bool includeRemote)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var cidrs = new List<(IPAddress Network, int Prefix)>();

        Merge(LoadEmbeddedDefault(), domains, ips, cidrs);
        Merge(LoadFromPath(GetBundledDefaultPath()), domains, ips, cidrs);

        EnsureUserDatabaseExists();
        Merge(LoadFromPath(LocalDatabasePath), domains, ips, cidrs);

        lock (_gate)
        {
            _domains.Clear();
            foreach (var d in domains) _domains.Add(d);
            _staticIps.Clear();
            foreach (var ip in ips) _staticIps.Add(ip);
            _cidrs.Clear();
            _cidrs.AddRange(cidrs);
        }

        foreach (var ip in ips)
            _ipToReason[ip] = "Allowlist static IP";

        RebuildEntryViews();
        StatusText = $"Loaded allowlist · {domains.Count} domains · {ips.Count} static IPs.";
    }

    private async Task TryFetchRemoteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(RemoteFeedUrl))
            return;

        if (DateTime.UtcNow - _lastRemoteFetchUtc < TimeSpan.FromMinutes(10))
            return;

        try
        {
            using var response = await _http.GetAsync(RemoteFeedUrl, ct);
            if (!response.IsSuccessStatusCode)
            {
                StatusText = $"Remote allowlist fetch failed ({(int)response.StatusCode}). Using local/built-in lists.";
                return;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var file = await JsonSerializer.DeserializeAsync<AllowlistFile>(stream, JsonOptions, ct);
            if (file == null) return;

            lock (_gate)
            {
                foreach (var d in file.Domains ?? Enumerable.Empty<string>())
                {
                    var n = NormalizeDomain(d);
                    if (!string.IsNullOrWhiteSpace(n))
                        _domains.Add(n);
                }

                foreach (var ip in file.Ips ?? Enumerable.Empty<string>())
                {
                    if (IPAddress.TryParse(ip, out var a))
                    {
                        var s = a.ToString();
                        _staticIps.Add(s);
                        _ipToReason[s] = "Remote allowlist IP";
                    }
                }

                foreach (var cidr in file.Cidrs ?? Enumerable.Empty<string>())
                {
                    if (TryParseCidr(cidr, out var parsed) && !_cidrs.Contains(parsed))
                        _cidrs.Add(parsed);
                }
            }

            _lastRemoteFetchUtc = DateTime.UtcNow;
            // Cache remote copy for offline
            var cachePath = Path.Combine(
                Path.GetDirectoryName(LocalDatabasePath)!,
                "allowlist-remote-cache.json");
            await File.WriteAllTextAsync(cachePath, JsonSerializer.Serialize(file, JsonOptions), ct);
            RebuildEntryViews();
        }
        catch (Exception ex)
        {
            // Try offline cache
            var cachePath = Path.Combine(
                Path.GetDirectoryName(LocalDatabasePath)!,
                "allowlist-remote-cache.json");
            Merge(LoadFromPath(cachePath),
                lockAddDomains: true,
                lockAddIps: true);
            StatusText = $"Remote allowlist unavailable ({ex.Message}). Using cache/local lists.";
        }
    }

    private void Merge(AllowlistFile? file, bool lockAddDomains, bool lockAddIps)
    {
        if (file == null) return;
        lock (_gate)
        {
            if (lockAddDomains)
            {
                foreach (var d in file.Domains ?? Enumerable.Empty<string>())
                {
                    var n = NormalizeDomain(d);
                    if (!string.IsNullOrWhiteSpace(n)) _domains.Add(n);
                }
            }

            if (lockAddIps)
            {
                foreach (var ip in file.Ips ?? Enumerable.Empty<string>())
                {
                    if (IPAddress.TryParse(ip, out var a))
                    {
                        var s = a.ToString();
                        _staticIps.Add(s);
                        _ipToReason[s] = "Cached remote allowlist IP";
                    }
                }

                foreach (var cidr in file.Cidrs ?? Enumerable.Empty<string>())
                {
                    if (TryParseCidr(cidr, out var parsed) && !_cidrs.Contains(parsed))
                        _cidrs.Add(parsed);
                }
            }
        }
    }

    private static void Merge(AllowlistFile? file, HashSet<string> domains, HashSet<string> ips,
        List<(IPAddress Network, int Prefix)> cidrs)
    {
        if (file == null) return;
        foreach (var d in file.Domains ?? Enumerable.Empty<string>())
        {
            var n = NormalizeDomain(d);
            if (!string.IsNullOrWhiteSpace(n))
                domains.Add(n);
        }

        foreach (var ip in file.Ips ?? Enumerable.Empty<string>())
        {
            if (IPAddress.TryParse(ip, out var a))
                ips.Add(a.ToString());
        }

        foreach (var cidr in file.Cidrs ?? Enumerable.Empty<string>())
        {
            if (TryParseCidr(cidr, out var parsed) && !cidrs.Contains(parsed))
                cidrs.Add(parsed);
        }
    }

    private async Task ResolveDomainsAsync(bool force, CancellationToken ct = default)
    {
        if (!force && DateTime.UtcNow - _lastResolveUtc < TimeSpan.FromMinutes(15))
            return;

        // Serialize resolves — a fire-and-forget refresh must not interleave
        // with a forced one and race on the resolved-IP map.
        if (!await _resolveGate.WaitAsync(0, ct))
            return;

        try
        {
            List<string> domains;
            lock (_gate) domains = _domains.ToList();

            // Fresh results per domain; domains that fail this pass are absent
            // and keep their previous IPs.
            var resolvedNow = new ConcurrentDictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

            await Parallel.ForEachAsync(domains, new ParallelOptions
            {
                MaxDegreeOfParallelism = 6,
                CancellationToken = ct
            }, async (domain, token) =>
            {
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    cts.CancelAfter(TimeSpan.FromSeconds(3));
                    var addresses = await Dns.GetHostAddressesAsync(domain, cts.Token);
                    var ips = addresses
                        .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        .Select(a => a.ToString())
                        .ToArray();
                    if (ips.Length > 0)
                        resolvedNow[domain] = ips;
                }
                catch
                {
                    // DNS failure — keep the domain's previously resolved IPs
                }
            });

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            lock (_gate)
            {
                foreach (var (domain, ips) in resolvedNow)
                    _domainIps[domain] = new HashSet<string>(ips, StringComparer.OrdinalIgnoreCase);

                // Drop cached IPs only for domains removed from the allowlist
                foreach (var gone in _domainIps.Keys.Where(d => !_domains.Contains(d)).ToList())
                    _domainIps.Remove(gone);

                foreach (var ip in _staticIps)
                    map[ip] = "Allowlist static IP";

                foreach (var (domain, ips) in _domainIps)
                {
                    foreach (var ip in ips)
                    {
                        if (!map.ContainsKey(ip))
                            map[ip] = $"Allowlist domain: {domain}";
                    }
                }
            }

            foreach (var key in _ipToReason.Keys.ToList())
            {
                if (!map.ContainsKey(key))
                    _ipToReason.TryRemove(key, out _);
            }

            foreach (var (ip, reason) in map)
                _ipToReason[ip] = reason;

            _lastResolveUtc = DateTime.UtcNow;
            RebuildEntryViews();
        }
        finally
        {
            _resolveGate.Release();
        }
    }

    private void SaveUserDatabase()
    {
        try
        {
            List<string> userDomains;
            List<string> userIps;
            lock (_gate)
            {
                // Persist everything currently loaded into user file would overwrite built-in —
                // store only extras: compare against defaults
                var defaults = LoadEmbeddedDefault() ?? new AllowlistFile();
                var defaultDomains = new HashSet<string>(
                    (defaults.Domains ?? new List<string>()).Select(NormalizeDomain),
                    StringComparer.OrdinalIgnoreCase);
                var defaultIps = new HashSet<string>(
                    (defaults.Ips ?? new List<string>()).Where(i => IPAddress.TryParse(i, out _)).Select(i => IPAddress.Parse(i).ToString()),
                    StringComparer.OrdinalIgnoreCase);

                userDomains = _domains.Where(d => !defaultDomains.Contains(d)).OrderBy(d => d).ToList();
                userIps = _staticIps.Where(i => !defaultIps.Contains(i)).OrderBy(i => i).ToList();
            }

            var file = new AllowlistFile
            {
                Version = 1,
                Description = "Your personal allowlist additions (merged with built-in defaults).",
                Domains = userDomains,
                Ips = userIps
            };
            File.WriteAllText(LocalDatabasePath, JsonSerializer.Serialize(file, JsonOptions));
        }
        catch
        {
            // best effort
        }
    }

    private void RebuildEntryViews()
    {
        lock (_gate)
        {
            _entries.Clear();
            foreach (var d in _domains)
                _entries.Add(new AllowlistEntryView { Kind = "Domain", Value = d, Detail = "Never block after DNS resolve" });
            foreach (var ip in _staticIps)
                _entries.Add(new AllowlistEntryView { Kind = "IP", Value = ip, Detail = "Static allowlist IP" });
            foreach (var (network, prefix) in _cidrs)
                _entries.Add(new AllowlistEntryView { Kind = "CIDR", Value = $"{network}/{prefix}", Detail = "Allowlist address range" });
            foreach (var kv in _ipToReason.OrderBy(k => k.Key).Take(500))
            {
                if (_staticIps.Contains(kv.Key)) continue;
                _entries.Add(new AllowlistEntryView { Kind = "Resolved", Value = kv.Key, Detail = kv.Value });
            }
        }
    }

    private static AllowlistFile? LoadEmbeddedDefault()
    {
        try
        {
            var asm = typeof(AllowlistService).Assembly;
            var name = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("allowlist-default.json", StringComparison.OrdinalIgnoreCase));
            if (name == null) return LoadFromPath(GetBundledDefaultPath());
            using var stream = asm.GetManifestResourceStream(name);
            if (stream == null) return null;
            return JsonSerializer.Deserialize<AllowlistFile>(stream, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string GetBundledDefaultPath()
    {
        // Next to the executable / content file
        var baseDir = AppContext.BaseDirectory;
        return Path.Combine(baseDir, "Data", "allowlist-default.json");
    }

    private static AllowlistFile? LoadFromPath(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AllowlistFile>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return "";
        domain = domain.Trim().ToLowerInvariant();
        if (domain.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            domain = domain["http://".Length..];
        if (domain.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            domain = domain["https://".Length..];
        var slash = domain.IndexOf('/');
        if (slash >= 0) domain = domain[..slash];
        return domain.Trim().TrimEnd('.');
    }

    private static bool TryParseCidr(string? cidr, out (IPAddress Network, int Prefix) parsed)
    {
        parsed = default;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out var network)) return false;
        if (!int.TryParse(parts[1], out var prefix)) return false;

        int maxPrefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > maxPrefix) return false;

        parsed = (network, prefix);
        return true;
    }

    private static bool IsInCidr(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily != network.AddressFamily) return false;

        var addrBytes = address.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        int fullBytes = prefix / 8;
        int remainderBits = prefix % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (addrBytes[i] != netBytes[i]) return false;
        }

        if (remainderBits > 0)
        {
            int mask = 0xFF << (8 - remainderBits);
            if ((addrBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask)) return false;
        }

        return true;
    }

    public void Dispose()
    {
        _http.Dispose();
        _resolveGate.Dispose();
    }
}

public sealed class AllowlistFile
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }

    [JsonPropertyName("ips")]
    public List<string>? Ips { get; set; }

    [JsonPropertyName("cidrs")]
    public List<string>? Cidrs { get; set; }

    [JsonPropertyName("notes")]
    public string? Notes { get; set; }
}

public sealed class AllowlistEntryView
{
    public string Kind { get; init; } = "";
    public string Value { get; init; } = "";
    public string Detail { get; init; } = "";
}
