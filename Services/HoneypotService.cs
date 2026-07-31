using System.Net;
using System.Net.Sockets;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Decoy listeners on ports this machine does not actually serve. Nothing
/// legitimate ever connects to a decoy, so an accepted connection is a
/// 100%-confidence Critical alert — far stronger evidence than any rate
/// threshold. The socket is closed immediately after logging the peer.
///
/// Binds only ports that are actually free; ports already in use (e.g. 5900
/// when a VNC server is running) are skipped and reported in <see cref="Status"/>.
/// </summary>
public sealed class HoneypotService : IDisposable
{
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<TcpListener> _listeners = new();
    private CancellationTokenSource? _cts;
    private volatile string _status = "Honeypot off";

    public string Status => _status;

    /// <summary>Ports currently bound as decoys (for excluding from other heuristics' noise).</summary>
    public IReadOnlySet<int> ActivePorts
    {
        get { lock (_gate) return _listeners.Select(l => ((IPEndPoint)l.LocalEndpoint).Port).ToHashSet(); }
    }

    public void Start(IEnumerable<int> ports)
    {
        Stop();

        var bound = new List<int>();
        var skipped = new List<int>();
        lock (_gate)
        {
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;

            foreach (var port in ports.Where(p => p is > 0 and <= 65535).Distinct())
            {
                try
                {
                    var listener = new TcpListener(IPAddress.IPv6Any, port);
                    listener.Server.DualMode = true;
                    listener.Start();
                    _listeners.Add(listener);
                    bound.Add(port);
                    _ = Task.Run(() => AcceptLoopAsync(listener, port, ct));
                }
                catch
                {
                    skipped.Add(port); // in use or not permitted
                }
            }
        }

        _status = bound.Count > 0
            ? $"Honeypot armed on {string.Join(", ", bound)}" +
              (skipped.Count > 0 ? $" (skipped {string.Join(", ", skipped)}: port busy)" : "")
            : skipped.Count > 0
                ? $"Honeypot could not bind any decoy port ({string.Join(", ", skipped)} busy)"
                : "Honeypot enabled but no valid ports configured";
    }

    public void Stop()
    {
        lock (_gate)
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            foreach (var l in _listeners)
            {
                try { l.Stop(); } catch { /* ignore */ }
            }
            _listeners.Clear();
        }
        _status = "Honeypot off";
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

    private async Task AcceptLoopAsync(TcpListener listener, int port, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient? client = null;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct);
                var remote = (client.Client.RemoteEndPoint as IPEndPoint)?.Address;
                if (remote == null) continue;
                if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
                var ip = remote.ToString();
                if (IPAddress.IsLoopback(remote)) continue;

                var now = DateTime.Now;
                lock (_gate)
                {
                    var key = $"{ip}|{port}";
                    if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
                        continue;
                    _lastEmit[key] = now;

                    _pending.Add(new ThreatEvent
                    {
                        Timestamp = now,
                        Type = ThreatType.HoneypotHit,
                        Level = ThreatLevel.Critical,
                        SourceIp = ip,
                        Title = $"Honeypot connection on decoy port {port}",
                        Detail = $"{ip} completed a TCP connection to decoy port {port} ({Native.PortCatalog.GetHint(port, "TCP")}). " +
                                 "Nothing legitimate connects to a decoy — this host is actively probing this machine.",
                        Origin = "Origin resolving…",
                        Method = $"Honeypot decoy (TCP {port})"
                    });
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch
            {
                // transient accept failure — keep listening
            }
            finally
            {
                try { client?.Close(); } catch { /* ignore */ }
            }
        }
    }

    public static IReadOnlyList<int> ParsePorts(string? csv)
    {
        var result = new List<int>();
        foreach (var token in (csv ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, out var port) && port is > 0 and <= 65535 && !result.Contains(port))
                result.Add(port);
        }
        return result;
    }

    public void Dispose() => Stop();
}
