using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;

namespace NetworkSentinel.Services;

public sealed class GeoIpService : IDisposable
{
    private readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(4)
    };

    private readonly ConcurrentDictionary<string, GeoResult> _cache = new();
    private readonly ConcurrentDictionary<string, DateTime> _failedAt = new();
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();
    private static readonly TimeSpan FailureRetryAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// When false, the external ip-api.com web lookup is skipped entirely
    /// (reverse DNS still runs). Note the free ip-api endpoint is plain HTTP,
    /// so the IPs this machine talks to are visible on the wire when enabled.
    /// </summary>
    public bool LookupsEnabled { get; set; } = true;

    public GeoIpService()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkSentinel/1.0");
    }

    public async Task<GeoResult> LookupAsync(string ip, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ip) || IsNonPublic(ip))
        {
            return new GeoResult
            {
                Ip = ip,
                HostName = IsLoopback(ip) ? "localhost" : "Private / local network",
                Country = IsLoopback(ip) ? "Localhost" : "LAN",
                City = "",
                Isp = "Private address space",
                Summary = IsLoopback(ip) ? "This computer" : "Private / local network"
            };
        }

        if (_cache.TryGetValue(ip, out var cached))
        {
            // Transient failures are retried after a cooldown instead of
            // pinning "lookup unavailable" for the rest of the session.
            if (_failedAt.TryGetValue(ip, out var failedAt))
            {
                if (DateTime.UtcNow - failedAt < FailureRetryAfter)
                    return cached;
                _cache.TryRemove(ip, out _);
                _failedAt.TryRemove(ip, out _);
            }
            else
            {
                return cached;
            }
        }

        if (!_inFlight.TryAdd(ip, 0))
        {
            // Another lookup is running; wait briefly for cache.
            for (int i = 0; i < 20 && !_cache.ContainsKey(ip); i++)
                await Task.Delay(100, ct);
            return _cache.TryGetValue(ip, out cached)
                ? cached
                : new GeoResult { Ip = ip, Summary = "Resolving…" };
        }

        try
        {
            string hostName = await ResolveHostNameAsync(ip, ct);

            if (!LookupsEnabled)
            {
                var dnsOnly = new GeoResult
                {
                    Ip = ip,
                    HostName = hostName,
                    Summary = string.IsNullOrWhiteSpace(hostName)
                        ? "Geo lookup disabled"
                        : $"Host: {hostName}"
                };
                _cache[ip] = dnsOnly;
                return dnsOnly;
            }

            var geo = await QueryIpApiAsync(ip, ct);

            var result = new GeoResult
            {
                Ip = ip,
                HostName = hostName,
                Country = geo.Country,
                City = geo.City,
                Isp = geo.Isp,
                Lat = geo.Lat,
                Lon = geo.Lon,
                Summary = BuildSummary(geo.City, geo.Country, geo.Isp, hostName)
            };

            _cache[ip] = result;
            return result;
        }
        catch
        {
            string hostName = await ResolveHostNameAsync(ip, ct);
            var fallback = new GeoResult
            {
                Ip = ip,
                HostName = hostName,
                Summary = string.IsNullOrWhiteSpace(hostName)
                    ? "Location lookup unavailable"
                    : $"Host: {hostName}"
            };
            _cache[ip] = fallback;
            _failedAt[ip] = DateTime.UtcNow;
            return fallback;
        }
        finally
        {
            _inFlight.TryRemove(ip, out _);
        }
    }

    private async Task<(string Country, string City, string Isp, double Lat, double Lon)> QueryIpApiAsync(
        string ip, CancellationToken ct)
    {
        // Free non-commercial endpoint (no key). Rate-limited; we cache aggressively.
        var url = $"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon,query";
        using var response = await _http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        var root = doc.RootElement;

        if (root.TryGetProperty("status", out var status) &&
            status.GetString() is not "success")
        {
            return ("", "", "", 0, 0);
        }

        string country = root.TryGetProperty("country", out var c) ? c.GetString() ?? "" : "";
        string city = root.TryGetProperty("city", out var ci) ? ci.GetString() ?? "" : "";
        string isp = root.TryGetProperty("isp", out var i) ? i.GetString() ?? "" : "";
        double lat = root.TryGetProperty("lat", out var la) ? la.GetDouble() : 0;
        double lon = root.TryGetProperty("lon", out var lo) ? lo.GetDouble() : 0;
        return (country, city, isp, lat, lon);
    }

    private static async Task<string> ResolveHostNameAsync(string ip, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(ip, cts.Token);
            return entry.HostName ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static string BuildSummary(string city, string country, string isp, string host)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(city)) parts.Add(city);
        if (!string.IsNullOrWhiteSpace(country)) parts.Add(country);
        if (!string.IsNullOrWhiteSpace(isp)) parts.Add(isp);
        if (parts.Count == 0 && !string.IsNullOrWhiteSpace(host))
            return $"Host: {host}";
        if (parts.Count == 0) return "Location unknown";
        return string.Join(" · ", parts);
    }

    public static bool IsNonPublic(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return true;
        if (IPAddress.IsLoopback(address)) return true;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            if (bytes[0] == 0) return true;
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
                return true;
            if (address.Equals(IPAddress.IPv6Any)) return true;
        }
        return false;
    }

    private static bool IsLoopback(string ip)
        => IPAddress.TryParse(ip, out var a) && IPAddress.IsLoopback(a);

    public void Dispose() => _http.Dispose();
}

public sealed class GeoResult
{
    public string Ip { get; init; } = "";
    public string HostName { get; init; } = "";
    public string Country { get; init; } = "";
    public string City { get; init; } = "";
    public string Isp { get; init; } = "";
    public double Lat { get; init; }
    public double Lon { get; init; }
    public string Summary { get; init; } = "";
}
