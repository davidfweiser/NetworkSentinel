using System.Net.Http;
using System.Text;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Pushes alerts to a user-configured webhook so intrusions reach you when
/// you're away from the machine. Payload adapts to the endpoint:
///
///  * Slack  (hooks.slack.com)        → {"text": "..."}
///  * Discord (discord.com/api/webhooks) → {"content": "..."}
///  * ntfy   (host contains "ntfy")   → plain-text body + Title/Priority headers
///  * anything else                    → generic JSON document
///
/// Fire-and-forget with a per-(IP|type) cooldown so a burst can't flood the
/// channel. Failures update <see cref="Status"/> and are otherwise silent.
/// </summary>
public sealed class WebhookNotifier : IDisposable
{
    private static readonly TimeSpan SendCooldown = TimeSpan.FromMinutes(5);

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastSent = new(StringComparer.OrdinalIgnoreCase);
    private volatile string _status = "Webhook idle";

    public string Status => _status;

    public WebhookNotifier()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("NetworkSentinel/1.0 (webhook)");
    }

    /// <summary>Queues matching threats for delivery. Safe to call from the poll loop.</summary>
    public void Notify(IReadOnlyList<ThreatEvent> threats, string url, ThreatLevel minLevel)
    {
        if (string.IsNullOrWhiteSpace(url)) return;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != "https" && uri.Scheme != "http"))
        {
            _status = "Webhook URL is not a valid http(s) address";
            return;
        }

        var now = DateTime.Now;
        var toSend = new List<ThreatEvent>();
        lock (_gate)
        {
            foreach (var t in threats)
            {
                if (t.Level < minLevel) continue;
                var key = $"{t.SourceIp}|{t.Type}";
                if (_lastSent.TryGetValue(key, out var last) && now - last < SendCooldown)
                    continue;
                _lastSent[key] = now;
                toSend.Add(t);
            }

            if (_lastSent.Count > 2000)
            {
                foreach (var stale in _lastSent.Where(kv => now - kv.Value > SendCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastSent.Remove(stale);
                }
            }
        }

        foreach (var t in toSend)
        {
            var threat = t;
            _ = Task.Run(() => SendAsync(uri, threat));
        }
    }

    private async Task SendAsync(Uri uri, ThreatEvent t)
    {
        try
        {
            var summary = $"[{t.LevelText}] {t.Title} — {t.SourceIp} · {t.Detail}";
            using var request = new HttpRequestMessage(HttpMethod.Post, uri);

            var host = uri.Host;
            if (host.EndsWith("hooks.slack.com", StringComparison.OrdinalIgnoreCase) ||
                uri.AbsoluteUri.Contains("hooks.slack.com/", StringComparison.OrdinalIgnoreCase))
            {
                request.Content = JsonContent(new { text = $"🛡️ Network Sentinel\n{summary}" });
            }
            else if (host.EndsWith("discord.com", StringComparison.OrdinalIgnoreCase) ||
                     host.EndsWith("discordapp.com", StringComparison.OrdinalIgnoreCase))
            {
                request.Content = JsonContent(new { content = $"🛡️ **Network Sentinel** — {summary}" });
            }
            else if (host.Contains("ntfy", StringComparison.OrdinalIgnoreCase))
            {
                request.Content = new StringContent(t.Detail, Encoding.UTF8, "text/plain");
                request.Headers.TryAddWithoutValidation("Title", $"Network Sentinel: {t.Title}");
                request.Headers.TryAddWithoutValidation("Priority", t.Level >= ThreatLevel.Critical ? "urgent" : "high");
                request.Headers.TryAddWithoutValidation("Tags", "shield,warning");
            }
            else
            {
                request.Content = JsonContent(new
                {
                    app = "NetworkSentinel",
                    title = t.Title,
                    level = t.LevelText,
                    type = t.TypeText,
                    source_ip = t.SourceIp,
                    detail = t.Detail,
                    origin = t.Origin,
                    method = t.Method,
                    time = t.Timestamp.ToString("O")
                });
            }

            using var response = await _http.SendAsync(request);
            _status = response.IsSuccessStatusCode
                ? $"Webhook delivered ({(int)response.StatusCode}) at {DateTime.Now:HH:mm:ss}"
                : $"Webhook returned {(int)response.StatusCode} at {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            _status = $"Webhook delivery failed: {ex.Message}";
        }
    }

    private static StringContent JsonContent(object payload)
        => new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    public void Dispose() => _http.Dispose();
}
