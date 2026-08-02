using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetworkSentinel.Services;

/// <summary>
/// DuckDNS dynamic-DNS config. Lives in its own 0600 file rather than settings.json:
/// the token is a credential that can rewrite the subdomain's records.
/// </summary>
public sealed class DuckDnsConfig
{
    public bool Enabled { get; set; }

    /// <summary>Subdomain label(s) only — "myhost" or "myhost,other". The .duckdns.org suffix is stripped on save.</summary>
    public string Domain { get; set; } = "";

    /// <summary>DuckDNS account token (UUID from duckdns.org). Never echoed back to the browser.</summary>
    public string Token { get; set; } = "";

    /// <summary>Minutes between refreshes (clamped 1–1440).</summary>
    public int IntervalMinutes { get; set; } = 5;

    [JsonIgnore]
    public bool IsUsable => Enabled && Domain.Length > 0 && Token.Length > 0;
}

/// <summary>
/// Keeps a DuckDNS A record pointed at this machine's public IP so the web console
/// stays reachable by name across ISP address changes.
/// </summary>
public sealed class DuckDnsUpdater : IDisposable
{
    private const string UpdateEndpoint = "https://www.duckdns.org/update";
    private const string DomainSuffix = ".duckdns.org";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    private readonly string _configPath;
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public DuckDnsUpdater() : this(AppPaths.DataDirectory) { }

    public DuckDnsUpdater(string dataDirectory)
    {
        _configPath = Path.Combine(dataDirectory, "duckdns.json");
        Config = LoadConfig(_configPath);
    }

    public DuckDnsConfig Config { get; private set; }

    /// <summary>Human-readable state for the console's settings page. Never contains the token.</summary>
    public string Status { get; private set; } = "DuckDNS: off";

    /// <summary>Public IP DuckDNS saw on the last successful update, if it reported one.</summary>
    public string? LastPublicIp { get; private set; }

    /// <summary>Fully qualified hostname, e.g. "myhost.duckdns.org" — empty when unconfigured.</summary>
    public string Hostname
    {
        get
        {
            var first = Config.Domain.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault();
            return string.IsNullOrEmpty(first) ? "" : first + DomainSuffix;
        }
    }

    /// <summary>
    /// Accepts "myhost", "myhost.duckdns.org", or "https://myhost.duckdns.org/" and returns
    /// the bare label(s) DuckDNS expects. Comma-separated lists are preserved.
    /// </summary>
    public static string NormalizeDomain(string raw)
    {
        var parts = (raw ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p =>
            {
                var v = p.Trim().ToLowerInvariant();
                if (v.StartsWith("https://", StringComparison.Ordinal)) v = v["https://".Length..];
                else if (v.StartsWith("http://", StringComparison.Ordinal)) v = v["http://".Length..];
                v = v.TrimEnd('/');
                if (v.EndsWith(DomainSuffix, StringComparison.Ordinal))
                    v = v[..^DomainSuffix.Length];
                return v.Trim('.');
            })
            .Where(p => p.Length > 0 && p.All(c => char.IsLetterOrDigit(c) || c is '-' || c is '.'));

        return string.Join(",", parts);
    }

    public void Start()
    {
        Stop();
        if (!Config.IsUsable)
        {
            Status = Config.Enabled
                ? "DuckDNS: needs a subdomain and token"
                : "DuckDNS: off";
            return;
        }

        // The first update runs on the loop below; report intent now so callers that echo
        // Status straight back to the user do not show the previous state.
        Status = $"DuckDNS: refreshing {Hostname}…";

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _loop = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                await UpdateOnceAsync(token).ConfigureAwait(false);
                var minutes = Math.Clamp(Config.IntervalMinutes, 1, 1440);
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(minutes), token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }, token);
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        _cts?.Dispose();
        _cts = null;
        _loop = null;
    }

    /// <summary>Persist new settings and restart the refresh loop. Returns the resulting status text.</summary>
    public string Apply(DuckDnsConfig config)
    {
        lock (_gate)
        {
            Config = new DuckDnsConfig
            {
                Enabled = config.Enabled,
                Domain = NormalizeDomain(config.Domain),
                Token = (config.Token ?? "").Trim(),
                IntervalMinutes = Math.Clamp(config.IntervalMinutes <= 0 ? 5 : config.IntervalMinutes, 1, 1440)
            };
            SaveConfig();
        }

        Start();
        return Status;
    }

    /// <summary>One update pass. Failures are recorded in <see cref="Status"/>, never thrown.</summary>
    public async Task<bool> UpdateOnceAsync(CancellationToken ct = default)
    {
        var cfg = Config;
        if (!cfg.IsUsable)
        {
            Status = "DuckDNS: off";
            return false;
        }

        // Empty ip= tells DuckDNS to use the source address of this request — which is
        // exactly the public IP we want the record to hold.
        var url = $"{UpdateEndpoint}?domains={Uri.EscapeDataString(cfg.Domain)}" +
                  $"&token={Uri.EscapeDataString(cfg.Token)}&ip=&verbose=true";

        try
        {
            using var res = await Http.GetAsync(url, ct).ConfigureAwait(false);
            var body = (await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();
            var lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim()).ToArray();

            if (lines.Length > 0 && lines[0].Equals("OK", StringComparison.OrdinalIgnoreCase))
            {
                if (lines.Length > 1 && lines[1].Length > 0)
                    LastPublicIp = lines[1];
                var changed = lines.Length > 3 && lines[3].Equals("UPDATED", StringComparison.OrdinalIgnoreCase);
                Status = LastPublicIp is { Length: > 0 }
                    ? $"DuckDNS: {Hostname} → {LastPublicIp} ({(changed ? "updated" : "unchanged")} {DateTime.Now:HH:mm})"
                    : $"DuckDNS: {Hostname} updated {DateTime.Now:HH:mm}";
                return true;
            }

            // "KO" means bad token or unknown subdomain. The response never echoes the token.
            Status = $"DuckDNS: rejected ({(lines.Length > 0 ? lines[0] : "no response")}) — check the subdomain and token";
            return false;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Status = $"DuckDNS: update failed — {ex.Message}";
            return false;
        }
    }

    private static DuckDnsConfig LoadConfig(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new DuckDnsConfig();
            var cfg = JsonSerializer.Deserialize<DuckDnsConfig>(File.ReadAllText(path)) ?? new DuckDnsConfig();
            cfg.Domain = NormalizeDomain(cfg.Domain);
            return cfg;
        }
        catch
        {
            return new DuckDnsConfig();
        }
    }

    private void SaveConfig()
    {
        try
        {
            var tmp = _configPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(Config, new JsonSerializerOptions { WriteIndented = true }));
            // Owner-only: the token can rewrite this subdomain's DNS records.
            TrySetOwnerOnly(tmp);
            File.Move(tmp, _configPath, overwrite: true);
            TrySetOwnerOnly(_configPath);
        }
        catch
        {
            // best-effort persistence
        }
    }

    private static void TrySetOwnerOnly(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // filesystem may not support it
        }
    }

    public void Dispose() => Stop();
}
