using System.IO;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Ingests Suricata's EVE JSON alert stream and turns signature matches into
/// ThreatEvents, so they flow through everything Network Sentinel already has:
/// the threat list, the persistent log, geo/origin enrichment, webhooks, the
/// allowlist, and the prevention engine.
///
/// This is the deliberate answer to the one gap connection-metadata heuristics
/// cannot close: payload inspection. Writing a DPI engine — protocol decoders,
/// stream reassembly, and the target-based defragmentation that stops an
/// attacker evading it — is a multi-year project whose failure mode is a bypass
/// nobody notices. Suricata already does it, already runs on Windows against a
/// WinDivert or npcap capture, and already has ET Open rules maintained by people
/// who do that full time. So Network Sentinel is the manager, not the engine:
/// Suricata decides what matched, this app decides what happens next.
///
/// Suricata's log directory under Program Files is not world-readable, so this
/// usually needs Administrator; the monitor degrades gracefully and explains
/// itself in <see cref="Status"/>.
/// </summary>
public sealed class SuricataService : IDisposable
{
    /// <summary>
    /// Where the Windows installer puts it. Not a const because the Program Files
    /// location is resolved from the environment rather than assumed to be on C:.
    /// </summary>
    public static readonly string DefaultEvePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "Suricata", "log", "eve.json");

    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan IdleDelay = TimeSpan.FromMilliseconds(500);
    /// <summary>
    /// How long to wait before looking for eve.json again. Kept short: Network Sentinel
    /// and Suricata start independently, and whichever wins the race, this is how long
    /// signature coverage is missing at boot. One File.Exists every few seconds is free.
    /// </summary>
    private static readonly TimeSpan MissingFileDelay = TimeSpan.FromSeconds(3);

    /// <summary>Backoff after a read error, where retrying hard would just spin.</summary>
    private static readonly TimeSpan ErrorRetryDelay = TimeSpan.FromSeconds(15);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.Ordinal);

    private CancellationTokenSource? _cts;
    private Task? _tail;
    private volatile string _status = "Suricata ingestion not started";
    private long _alertsSeen;
    private long _alertsAccepted;

    /// <summary>Path to Suricata's EVE JSON log.</summary>
    public string EvePath { get; set; } = DefaultEvePath;

    /// <summary>
    /// Highest Suricata severity number to accept (Suricata counts down: 1 is most
    /// severe). 3 keeps informational noise out while retaining real detections.
    /// </summary>
    public int MaxSeverity { get; set; } = 3;

    /// <summary>Signature IDs to ignore entirely — the per-rule mute for a known false positive.</summary>
    public IReadOnlySet<long> IgnoredSids { get; set; } = new HashSet<long>();

    public string Status => _status;

    /// <summary>Alert counters for the console, so an operator can see the feed is alive.</summary>
    public (long Seen, long Accepted) Counters => (Interlocked.Read(ref _alertsSeen), Interlocked.Read(ref _alertsAccepted));

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            _tail = Task.Run(() => TailAsync(ct), ct);
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? tail;
        lock (_gate)
        {
            cts = _cts;
            tail = _tail;
            _cts = null;
            _tail = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { tail?.Wait(1500); } catch { /* shutting down */ }
        cts.Dispose();
        _status = "Suricata ingestion stopped";
    }

    /// <summary>Returns alerts converted since the last drain (called from the monitor poll loop).</summary>
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

    private async Task TailAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!File.Exists(EvePath))
                {
                    _status = $"Waiting for {EvePath} — is Suricata running with the eve-log output enabled?";
                    await Task.Delay(MissingFileDelay, ct);
                    continue;
                }

                await FollowAsync(ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (UnauthorizedAccessException)
            {
                _status = $"{EvePath} not readable by this user — restart as Administrator, or grant read access to the log directory";
                await SafeDelay(ErrorRetryDelay, ct);
            }
            catch (Exception ex)
            {
                _status = $"Suricata ingestion error: {ex.Message}";
                await SafeDelay(ErrorRetryDelay, ct);
            }
        }
    }

    /// <summary>
    /// Follows one incarnation of the file. Returns when it is rotated or truncated
    /// so the caller can reopen — rotation would otherwise leave us reading a stale
    /// handle forever, silently blind while alerts pile up in the new file.
    /// </summary>
    private async Task FollowAsync(CancellationToken ct)
    {
        await using var stream = new FileStream(
            EvePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        // Start at the end: replaying history on every launch would re-alert on
        // attacks that were already handled days ago.
        stream.Seek(0, SeekOrigin.End);
        using var reader = new StreamReader(stream);

        _status = $"Reading Suricata alerts from {EvePath}";

        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(ct);
            if (line == null)
            {
                if (WasRotated(stream))
                    return;
                await Task.Delay(IdleDelay, ct);
                continue;
            }

            if (line.Length == 0)
                continue;

            ProcessLine(line, DateTime.Now);
        }
    }

    private bool WasRotated(FileStream stream)
    {
        try
        {
            var info = new FileInfo(EvePath);
            // Truncated in place, or replaced by a smaller/new file.
            return !info.Exists || info.Length < stream.Position;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>Parses one EVE JSON line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        // Cheap reject before paying for a JSON parse — eve.json is dominated by
        // flow/http/dns records and only a fraction are alerts.
        if (!line.Contains("\"event_type\":\"alert\"", StringComparison.Ordinal) &&
            !line.Contains("\"event_type\": \"alert\"", StringComparison.Ordinal))
            return;

        JsonDocument doc;
        try { doc = JsonDocument.Parse(line); }
        catch (JsonException) { return; }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            if (!root.TryGetProperty("event_type", out var et) || et.GetString() != "alert") return;
            if (!root.TryGetProperty("alert", out var alert) || alert.ValueKind != JsonValueKind.Object) return;

            Interlocked.Increment(ref _alertsSeen);

            var severity = GetInt(alert, "severity") ?? 3;
            if (severity > MaxSeverity)
                return;

            var sid = GetLong(alert, "signature_id") ?? 0;
            if (IgnoredSids.Contains(sid))
                return;

            var signature = GetString(alert, "signature") ?? $"Suricata signature {sid}";
            var category = GetString(alert, "category") ?? "";
            var action = GetString(alert, "action") ?? "";

            var srcIp = GetString(root, "src_ip") ?? "";
            var destIp = GetString(root, "dest_ip") ?? "";
            var srcPort = GetInt(root, "src_port") ?? 0;
            var destPort = GetInt(root, "dest_port") ?? 0;
            var proto = GetString(root, "proto") ?? "";
            var appProto = GetString(root, "app_proto") ?? "";

            var (remoteIp, remotePort, inbound) = ResolveRemote(srcIp, srcPort, destIp, destPort);
            if (string.IsNullOrEmpty(remoteIp))
                return;

            // Rate-limit per signature+peer: one rule matching every packet of a
            // session would otherwise bury every other alert in the console.
            var key = $"{sid}|{remoteIp}";
            lock (_gate)
            {
                if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
                    return;
                _lastEmit[key] = now;
                PruneEmitHistory(now);
            }

            Interlocked.Increment(ref _alertsAccepted);

            var level = MapLevel(severity);
            var direction = inbound ? "inbound" : "outbound";
            var details = new List<string> { $"Suricata sid:{sid} (severity {severity})" };
            if (!string.IsNullOrWhiteSpace(category)) details.Add(category);
            details.Add(inbound
                ? $"{remoteIp}:{remotePort} → {destIp}:{destPort}"
                : $"{srcIp}:{srcPort} → {remoteIp}:{remotePort}");
            if (!string.IsNullOrWhiteSpace(proto)) details.Add(proto + (string.IsNullOrWhiteSpace(appProto) ? "" : $"/{appProto}"));
            // In IPS mode Suricata reports what it did with the packet itself.
            if (action.Equals("blocked", StringComparison.OrdinalIgnoreCase))
                details.Add("already dropped by Suricata");

            var threat = new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.SignatureMatch,
                Level = level,
                SourceIp = remoteIp,
                Title = signature,
                Method = $"Suricata rule match ({direction})",
                Detail = string.Join(" · ", details),
                AutoBlockHoldReason = SourceMayBeForged(proto, appProto)
                    ? "the alert is on a flow with no completed TCP handshake (UDP, ICMP or half-open), so the source address may be forged"
                    : null
            };

            lock (_gate) _pending.Add(threat);
        }
    }

    /// <summary>
    /// Picks which end of the flow is the threat. Suricata's src_ip is the packet
    /// source, which for an outbound C2 callback is *this machine* — blocking that
    /// would firewall the host off from itself, so the remote end is whichever side
    /// is not local. "Local" must include this machine's own interface addresses,
    /// not just private ranges: on a VPS or VPN server the host's address is public,
    /// and a private-range check alone made an outbound alert name the host itself
    /// as the threat.
    /// </summary>
    private static (string Ip, int Port, bool Inbound) ResolveRemote(string srcIp, int srcPort, string destIp, int destPort)
    {
        var srcLocal = !string.IsNullOrEmpty(srcIp) && IsThisMachineOrLan(srcIp);
        var destLocal = !string.IsNullOrEmpty(destIp) && IsThisMachineOrLan(destIp);

        if (srcLocal && !destLocal)
            return (destIp, destPort, false);
        if (!srcLocal && destLocal)
            return (srcIp, srcPort, true);

        // Both remote or both local (LAN-to-LAN): the packet source is the actor.
        return (srcIp, srcPort, true);
    }

    /// <summary>
    /// True when nothing in the alert proves the remote address is real. Suricata only
    /// assigns an app-layer protocol to a TCP flow after the handshake, so TCP with an
    /// app_proto is a conversation the remote end really took part in. UDP and ICMP
    /// have no handshake at all — a reply going out proves nothing, since it goes to
    /// whoever the forged packet named.
    /// </summary>
    internal static bool SourceMayBeForged(string proto, string appProto)
        => !proto.Equals("TCP", StringComparison.OrdinalIgnoreCase)
           || string.IsNullOrWhiteSpace(appProto)
           || appProto.Equals("failed", StringComparison.OrdinalIgnoreCase);

    private static bool IsThisMachineOrLan(string ip)
        => FirewallService.IsPrivateOrLocal(ip) || LocalAddresses.IsOwnAddress(ip);

    /// <summary>
    /// Suricata counts severity down — 1 is most severe. Anything it rates 1 is the
    /// class of signature (exploit, trojan CnC) that justifies dropping traffic, so it
    /// lands at Critical and clears a default High auto-block threshold.
    /// </summary>
    private static ThreatLevel MapLevel(int severity) => severity switch
    {
        <= 1 => ThreatLevel.Critical,
        2 => ThreatLevel.High,
        3 => ThreatLevel.Medium,
        _ => ThreatLevel.Low
    };

    private void PruneEmitHistory(DateTime now)
    {
        if (_lastEmit.Count < 2048) return;
        foreach (var key in _lastEmit.Where(kv => now - kv.Value > EmitCooldown).Select(kv => kv.Key).ToList())
            _lastEmit.Remove(key);
    }

    private static async Task SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { /* shutting down */ }
    }

    private static string? GetString(JsonElement e, string name)
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int? GetInt(JsonElement e, string name)
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;

    private static long? GetLong(JsonElement e, string name)
        => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : null;

    /// <summary>Parses a comma/space separated sid list from settings.</summary>
    public static HashSet<long> ParseSids(string? raw)
    {
        var set = new HashSet<long>();
        if (string.IsNullOrWhiteSpace(raw)) return set;
        foreach (var part in raw.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (long.TryParse(part.Trim(), out var sid)) set.Add(sid);
        }
        return set;
    }

    public void Dispose() => Stop();
}
