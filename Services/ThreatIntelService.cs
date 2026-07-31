using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Known-bad IP lookup against public threat-intel feeds: FireHOL level1 and
/// Spamhaus DROP. A connection to or from a listed address needs no heuristics
/// — it is an instant Critical alert.
///
/// Feeds are fetched over HTTPS, cached in Application Support for offline
/// starts, and refreshed daily. Both feeds are IPv4 CIDR lists; FireHOL level1
/// also contains bogon/private space, so callers must skip non-public IPs
/// before asking (the service double-checks anyway).
/// </summary>
public sealed class ThreatIntelService : IDisposable
{
    private static readonly (string Name, string Url)[] Feeds =
    {
        ("FireHOL level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"),
        ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt")
    };

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(24);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(20) };
    private readonly object _gate = new();

    /// <summary>(network, prefix, feed) entries bucketed by first octet for cheap lookup.</summary>
    private Dictionary<byte, List<(uint Network, int Prefix, string Feed)>> _buckets = new();
    private int _entryCount;
    private DateTime _fetchedUtc = DateTime.MinValue;
    private Task? _refreshTask;
    private volatile string _status = "Threat-intel feeds not loaded";

    private static string CachePath => Path.Combine(AppPaths.DataDirectory, "threat-intel-cache.json");

    public string Status => _status;
    public int EntryCount => _entryCount;

    public ThreatIntelService()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkSentinel/1.0 (threat-intel)");
        LoadCache();
    }

    /// <summary>
    /// Kicks off a background refresh when the cached copy is stale. Safe to
    /// call every poll; only one refresh runs at a time.
    /// </summary>
    public void EnsureFresh()
    {
        lock (_gate)
        {
            if (_refreshTask is { IsCompleted: false }) return;
            if (DateTime.UtcNow - _fetchedUtc < RefreshInterval) return;
            _refreshTask = Task.Run(RefreshAsync);
        }
    }

    /// <summary>True when <paramref name="ip"/> falls inside a feed's CIDR ranges.</summary>
    public bool IsListed(string ip, out string feedName)
    {
        feedName = "";
        if (GeoIpService.IsNonPublic(ip)) return false;
        if (!IPAddress.TryParse(ip, out var address)) return false;
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            else return false; // feeds are IPv4
        }

        var bytes = address.GetAddressBytes();
        uint value = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);

        Dictionary<byte, List<(uint, int, string)>> buckets;
        lock (_gate) buckets = _buckets;

        // Prefixes shorter than /8 span buckets; those live under key 0.
        foreach (var key in new[] { bytes[0], (byte)0 })
        {
            if (!buckets.TryGetValue(key, out var list)) continue;
            foreach (var (network, prefix, feed) in list)
            {
                uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
                if ((value & mask) == network)
                {
                    feedName = feed;
                    return true;
                }
            }
        }

        return false;
    }

    private async Task RefreshAsync()
    {
        var entries = new List<(uint Network, int Prefix, string Feed)>();
        var okFeeds = new List<string>();
        var failed = new List<string>();

        foreach (var (name, url) in Feeds)
        {
            try
            {
                var text = await _http.GetStringAsync(url);
                int before = entries.Count;
                ParseFeed(text, name, entries);
                if (entries.Count > before) okFeeds.Add($"{name} ({entries.Count - before})");
                else failed.Add(name);
            }
            catch
            {
                failed.Add(name);
            }
        }

        if (okFeeds.Count == 0)
        {
            _status = _entryCount > 0
                ? $"Threat-intel refresh failed ({string.Join(", ", failed)}) — using cached copy of {_entryCount} ranges"
                : $"Threat-intel feeds unavailable ({string.Join(", ", failed)})";
            return;
        }

        Apply(entries, DateTime.UtcNow);
        SaveCache(entries);
        _status = $"Threat intel ready · {string.Join(" · ", okFeeds)}" +
                  (failed.Count > 0 ? $" · failed: {string.Join(", ", failed)}" : "");
    }

    private static void ParseFeed(string text, string feed, List<(uint, int, string)> entries)
    {
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                continue;

            // Spamhaus DROP: "1.2.3.0/24 ; SBL123"
            var semi = line.IndexOf(';');
            if (semi >= 0) line = line[..semi].Trim();
            if (line.Length == 0) continue;

            string cidr = line;
            int prefix = 32;
            var slash = line.IndexOf('/');
            if (slash > 0)
            {
                cidr = line[..slash];
                if (!int.TryParse(line[(slash + 1)..], out prefix) || prefix is < 0 or > 32)
                    continue;
            }

            if (!IPAddress.TryParse(cidr, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork)
                continue;

            var bytes = address.GetAddressBytes();
            uint value = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            entries.Add((value & mask, prefix, feed));
        }
    }

    private void Apply(List<(uint Network, int Prefix, string Feed)> entries, DateTime fetchedUtc)
    {
        var buckets = new Dictionary<byte, List<(uint, int, string)>>();
        foreach (var e in entries)
        {
            byte key = e.Prefix >= 8 ? (byte)(e.Network >> 24) : (byte)0;
            if (!buckets.TryGetValue(key, out var list))
            {
                list = new List<(uint, int, string)>();
                buckets[key] = list;
            }
            list.Add(e);
        }

        lock (_gate)
        {
            _buckets = buckets;
            _entryCount = entries.Count;
            _fetchedUtc = fetchedUtc;
        }
    }

    private void LoadCache()
    {
        try
        {
            if (!File.Exists(CachePath)) return;
            var cache = JsonSerializer.Deserialize<CacheFile>(File.ReadAllText(CachePath), JsonOptions);
            if (cache?.Entries == null || cache.Entries.Count == 0) return;

            var entries = cache.Entries
                .Where(e => e.Prefix is >= 0 and <= 32)
                .Select(e => (e.Network, e.Prefix, e.Feed ?? "cached"))
                .ToList();
            Apply(entries, cache.FetchedUtc);
            _status = $"Threat intel loaded from cache · {entries.Count} ranges · fetched {cache.FetchedUtc:u}";
        }
        catch
        {
            // corrupt cache — refetch
        }
    }

    private void SaveCache(List<(uint Network, int Prefix, string Feed)> entries)
    {
        try
        {
            var cache = new CacheFile
            {
                FetchedUtc = DateTime.UtcNow,
                Entries = entries.Select(e => new CacheEntry
                {
                    Network = e.Network,
                    Prefix = e.Prefix,
                    Feed = e.Feed
                }).ToList()
            };
            File.WriteAllText(CachePath, JsonSerializer.Serialize(cache, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    public void Dispose() => _http.Dispose();

    private sealed class CacheFile
    {
        [JsonPropertyName("fetchedUtc")]
        public DateTime FetchedUtc { get; set; }

        [JsonPropertyName("entries")]
        public List<CacheEntry>? Entries { get; set; }
    }

    private sealed class CacheEntry
    {
        [JsonPropertyName("n")]
        public uint Network { get; set; }

        [JsonPropertyName("p")]
        public int Prefix { get; set; }

        [JsonPropertyName("f")]
        public string? Feed { get; set; }
    }
}
