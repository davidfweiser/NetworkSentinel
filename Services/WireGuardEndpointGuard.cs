using System.IO;
using System.Text.Json;

namespace NetworkSentinel.Services;

/// <summary>
/// The set of public addresses that carry a WireGuard tunnel to or from this host —
/// the one thing the prevention engine must never firewall off.
///
/// Blocking a peer's endpoint does not drop "an attacker": it drops the tunnel, and
/// with it every service reached through the tunnel. On a VPN gateway that is the
/// whole point of the machine, and the failure is invisible from the inside — the
/// rule is applied, the console keeps working over the LAN, and a remote user simply
/// finds the VPN dead. Recovery needs a second path into the box, which is exactly
/// what the tunnel was there to provide.
///
/// <see cref="WireGuardMonitor"/> already knows the peers, but only while WireGuard
/// *monitoring* is switched on (default off) — so the gate that was meant to prevent
/// this was inert on precisely the hosts that need it. This guard is deliberately
/// independent of that setting, and of the monitor's lifetime:
///
///   - `wg show all dump` for live peer endpoints, sampled on its own cadence;
///   - `Endpoint =` lines in <c>/etc/wireguard/*.conf</c>, which still name the
///     server when the interface is down — the state a client is in after the very
///     block this guard exists to prevent;
///   - a persisted 24 h memory of every endpoint seen, so a restart, a roaming peer,
///     a momentary `wg` failure, or a tunnel that has *already* dropped never opens a
///     window where the address becomes blockable.
///
/// Hostnames in a config (`Endpoint = vpn.example.org:51820`) are deliberately not
/// resolved: an attacker who can answer DNS could otherwise write their own address
/// into a never-block list. The live dump reports the resolved address anyway, and
/// the memory keeps it across the downtime.
///
/// Peer endpoints need root (CAP_NET_ADMIN), as does <c>/etc/wireguard</c>. When a
/// WireGuard interface exists but neither can be read, <see cref="Status"/> says so
/// in as many words — an unprivileged run with pkexec available can still write
/// firewall rules, so silence there would be the dangerous case.
/// </summary>
public sealed class WireGuardEndpointGuard : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(60);

    /// <summary>
    /// How long an endpoint stays shielded after it was last seen. Generous on purpose:
    /// the cost of remembering a stale address is that one address cannot be auto-blocked
    /// for a day, and the cost of forgetting a live one is a severed tunnel.
    /// </summary>
    public static readonly TimeSpan RememberFor = TimeSpan.FromHours(24);

    private const string ConfigDirectory = "/etc/wireguard";
    private const string NetClassDirectory = "/sys/class/net";

    private readonly object _gate = new();

    /// <summary>endpoint address → when it was last observed (UTC).</summary>
    private readonly Dictionary<string, DateTime> _endpoints = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _dirty;
    private volatile string _status = "WireGuard endpoint protection has not sampled yet";

    public WireGuardEndpointGuard() => Load();

    /// <summary>Human-readable state for the settings panels.</summary>
    public string Status => _status;

    /// <summary>Addresses currently shielded from auto-block. For display and tests.</summary>
    public IReadOnlyCollection<string> Endpoints
    {
        get
        {
            lock (_gate)
            {
                var cutoff = DateTime.UtcNow - RememberFor;
                return _endpoints.Where(kv => kv.Value > cutoff).Select(kv => kv.Key).ToList();
            }
        }
    }

    /// <summary>True when the address is (or recently was) a WireGuard tunnel endpoint.</summary>
    public bool IsProtected(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return false;

        lock (_gate)
            return _endpoints.TryGetValue(normalized, out var seen) && DateTime.UtcNow - seen <= RememberFor;
    }

    /// <summary>
    /// Records an address as a tunnel endpoint. Also called with the live monitor's peers,
    /// so a roaming client's new endpoint is shielded from the moment it is first seen
    /// rather than at the next sample.
    /// </summary>
    public void Remember(string? endpointIp)
    {
        if (string.IsNullOrWhiteSpace(endpointIp) ||
            !FirewallService.TryNormalizeIp(endpointIp, out var normalized, out _))
            return;

        lock (_gate)
        {
            _endpoints[normalized] = DateTime.UtcNow;
            _dirty = true;
        }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
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
        if (cts != null)
        {
            cts.Cancel();
            try { loop?.Wait(2000); } catch { /* shutting down */ }
            cts.Dispose();
        }

        // Unconditional: endpoints learned from the live peer list (which the prevention
        // gate feeds in, loop or no loop) must reach disk before the process goes away.
        Save();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { SampleOnce(); }
            catch (Exception ex) { _status = $"WireGuard endpoint protection error: {ex.Message}"; }

            try { await Task.Delay(SampleInterval, ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>One refresh pass. Internal so tests can drive it without the loop.</summary>
    internal void SampleOnce()
    {
        var interfaces = WireGuardInterfaces();
        if (interfaces.Count == 0)
        {
            // Nothing to shield, and no reason to spawn `wg`. Remembered endpoints are
            // kept: an interface that is down right now is the case that matters most.
            _status = Remembered() > 0
                ? $"No WireGuard interface is up; {Remembered()} recent endpoint(s) still shielded from auto-block"
                : "No WireGuard interfaces on this host";
            Save();
            return;
        }

        var names = string.Join(", ", interfaces);
        var live = 0;
        string? failure = null;

        if (WireGuardMonitor.TryRunWgDump(out var dump, out var error))
        {
            foreach (var peer in WireGuardMonitor.ParseDump(dump))
            {
                if (string.IsNullOrEmpty(peer.EndpointIp)) continue;
                Remember(peer.EndpointIp);
                live++;
            }
        }
        else
        {
            failure = error;
        }

        var fromConfig = 0;
        foreach (var endpoint in ConfiguredEndpoints())
        {
            Remember(endpoint);
            fromConfig++;
        }

        Save();

        var shielded = Remembered();
        if (failure == null || live > 0 || fromConfig > 0)
        {
            _status = $"Shielding {shielded} WireGuard endpoint(s) on {names} from auto-block";
        }
        else
        {
            // The dangerous combination: a tunnel is up, its endpoints are unreadable,
            // and auto-block may still be armed through pkexec/sudo.
            _status = $"{names} is up but its peer endpoints cannot be read ({failure}) — " +
                      "run as root, or a VPN client's address can be auto-blocked.";
        }
    }

    private int Remembered()
    {
        lock (_gate)
        {
            var cutoff = DateTime.UtcNow - RememberFor;
            return _endpoints.Count(kv => kv.Value > cutoff);
        }
    }

    /// <summary>
    /// WireGuard interfaces from sysfs — no root, no subprocess, and unlike a `wg` call
    /// it answers "is there a tunnel here at all" even when peer state is unreadable.
    /// </summary>
    internal static List<string> WireGuardInterfaces()
    {
        var found = new List<string>();
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(NetClassDirectory))
            {
                try
                {
                    var uevent = Path.Combine(dir, "uevent");
                    if (!File.Exists(uevent)) continue;
                    foreach (var line in File.ReadLines(uevent))
                    {
                        if (!line.StartsWith("DEVTYPE=", StringComparison.Ordinal)) continue;
                        if (line["DEVTYPE=".Length..].Trim() == "wireguard")
                            found.Add(Path.GetFileName(dir));
                        break;
                    }
                }
                catch
                {
                    // An interface that vanished mid-scan contributes nothing.
                }
            }
        }
        catch
        {
            // No sysfs (a container, a non-Linux test host) — treat as "no interfaces".
        }
        found.Sort(StringComparer.Ordinal);
        return found;
    }

    /// <summary>Endpoint addresses named in <c>/etc/wireguard/*.conf</c>. Root-only, best effort.</summary>
    private static List<string> ConfiguredEndpoints()
    {
        var found = new List<string>();
        try
        {
            foreach (var file in Directory.EnumerateFiles(ConfigDirectory, "*.conf"))
            {
                try { found.AddRange(ParseConfigEndpoints(File.ReadAllText(file))); }
                catch { /* unreadable without root, or removed mid-scan */ }
            }
        }
        catch
        {
            // No /etc/wireguard, or no permission to list it.
        }
        return found;
    }

    /// <summary>
    /// Pulls literal endpoint addresses out of a wg-quick config. Hostnames yield nothing
    /// on purpose (see the class remarks), and no other field is read — a config also holds
    /// private and preshared keys, which must never enter this process.
    /// </summary>
    internal static List<string> ParseConfigEndpoints(string config)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(config)) return found;

        foreach (var raw in config.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';') continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            if (!line[..eq].Trim().Equals("Endpoint", StringComparison.OrdinalIgnoreCase)) continue;

            // Strip a trailing comment: "Endpoint = 1.2.3.4:51820  # home".
            var value = line[(eq + 1)..].Trim();
            var comment = value.IndexOfAny(new[] { '#', ';' });
            if (comment >= 0) value = value[..comment].Trim();

            var ip = WireGuardMonitor.ExtractIp(value);
            if (!string.IsNullOrEmpty(ip))
                found.Add(ip);
        }

        return found;
    }

    private static string StatePath => Path.Combine(AppPaths.DataDirectory, "wireguard-endpoints.json");

    /// <summary>
    /// Endpoint addresses only. A restart with an empty memory would re-open the block
    /// window at exactly the wrong moment — the tunnel is down, so `wg` reports no
    /// endpoint, so the address that would restore it looks like any other stranger.
    /// </summary>
    private void Load()
    {
        try
        {
            if (!File.Exists(StatePath)) return;
            var loaded = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(StatePath));
            if (loaded == null) return;

            var cutoff = DateTime.UtcNow - RememberFor;
            lock (_gate)
            {
                foreach (var kv in loaded)
                {
                    if (kv.Value > cutoff)
                        _endpoints[kv.Key] = kv.Value;
                }
            }
        }
        catch
        {
            // A corrupt state file just means an empty memory; the next sample refills it.
        }
    }

    private void Save()
    {
        Dictionary<string, DateTime> snapshot;
        lock (_gate)
        {
            if (!_dirty) return;
            var cutoff = DateTime.UtcNow - RememberFor;
            foreach (var key in _endpoints.Where(kv => kv.Value <= cutoff).Select(kv => kv.Key).ToList())
                _endpoints.Remove(key);
            snapshot = new Dictionary<string, DateTime>(_endpoints);
            _dirty = false;
        }

        try { AppPaths.WriteAtomic(StatePath, JsonSerializer.Serialize(snapshot)); }
        catch { /* best-effort persistence, same as the other stores */ }
    }

    public void Dispose() => Stop();
}
