using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.Json;

namespace NetworkSentinel.Services;

/// <summary>
/// The IPSec half of the tunnel-endpoint shield — the set of public addresses that carry
/// an IPSec (IKE/ESP) tunnel to or from this host, which the prevention engine must never
/// firewall off.
///
/// <see cref="WireGuardEndpointGuard"/> already makes this argument for WireGuard, and it
/// applies with more force here. A site-to-site IPSec tunnel is the case where the peer is
/// *not* a laptop that can phone home: it is another office's router, the address it dials
/// in from is a plain public IP indistinguishable from any stranger's, and its traffic is
/// exactly the shape that trips heuristics — a fixed remote address holding long-lived
/// flows to whatever the tunnel carries, re-keying on a timer, retrying hard whenever the
/// link flaps. Auto-block that address and the tunnel drops for both sites at once. From
/// this end nothing looks wrong: the rule applied, the console still answers, and the
/// remote site simply loses the VPN with no way back through it.
///
/// Sources, in the same belt-and-braces spirit as the WireGuard guard:
///
///   - <c>ip xfrm state</c> for live kernel SAs. This is the source that matters most,
///     because it is implementation-independent — strongSwan, libreswan and Openswan all
///     install the same XFRM state, so one parser covers every IPSec stack.
///   - <c>swanctl --list-sas</c> / <c>ipsec status</c>, which still name the peer during
///     the window where IKE is up but no child SA has been installed yet.
///   - <c>right=</c> / <c>left=</c> in <c>ipsec.conf</c> and <c>ipsec.d/*.conf</c>, and
///     <c>remote_addrs</c> / <c>local_addrs</c> in <c>swanctl.conf</c> and
///     <c>swanctl/conf.d/*.conf</c>, which name the peer even with the tunnel down — the
///     state a site is in after the very block this guard exists to prevent.
///   - a persisted 24 h memory of every peer seen, so a restart, a re-keying window, a
///     momentary command failure, or a tunnel that has *already* dropped never opens a
///     gap where the address becomes blockable.
///
/// Only single addresses are ever taken from a config. Traffic selectors
/// (<c>leftsubnet</c>, <c>remote_ts</c>, …) are deliberately not read: they routinely hold
/// <c>0.0.0.0/0</c>, and a shield that swallowed a default route would silently disable
/// auto-block for the whole internet. Hostnames are not resolved and <c>%any</c> is
/// ignored, for the same reason the WireGuard guard skips them — anyone who can answer DNS
/// could otherwise write their own address into a never-block list.
///
/// Live SAs need root (CAP_NET_ADMIN), as do the config directories. When this host
/// clearly runs IPSec but neither can be read, <see cref="Status"/> says so in as many
/// words: an unprivileged run with pkexec available can still write firewall rules, so
/// silence there would be the dangerous case.
/// </summary>
public sealed class IpsecEndpointGuard : IDisposable
{
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(60);

    /// <summary>
    /// How long a peer stays shielded after it was last seen. Matches the WireGuard guard
    /// deliberately: the cost of remembering a stale address is that one address cannot be
    /// auto-blocked for a day, and the cost of forgetting a live one is a severed tunnel.
    /// </summary>
    public static readonly TimeSpan RememberFor = TimeSpan.FromHours(24);

    /// <summary>Config locations for strongSwan (both eras) and libreswan/Openswan.</summary>
    private const string IpsecConfFile = "/etc/ipsec.conf";
    private const string IpsecConfDirectory = "/etc/ipsec.d";
    private const string SwanctlConfFile = "/etc/swanctl/swanctl.conf";
    private const string SwanctlConfDirectory = "/etc/swanctl/conf.d";

    /// <summary>Present whenever the kernel's XFRM stack is loaded — i.e. something set up IPSec.</summary>
    private const string XfrmStatFile = "/proc/net/xfrm_stat";

    private readonly object _gate = new();

    /// <summary>peer address → when it was last observed (UTC).</summary>
    private readonly Dictionary<string, DateTime> _endpoints = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _dirty;
    private volatile string _status = "IPSec endpoint protection has not sampled yet";

    public IpsecEndpointGuard() => Load();

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

    /// <summary>True when the address is (or recently was) an IPSec tunnel endpoint.</summary>
    public bool IsProtected(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return false;

        lock (_gate)
            return _endpoints.TryGetValue(normalized, out var seen) && DateTime.UtcNow - seen <= RememberFor;
    }

    /// <summary>
    /// Records an address as a tunnel endpoint. Unroutable addresses are dropped rather
    /// than stored: a tunnel's *inner* addresses are private by design and are never
    /// auto-blocked anyway, so remembering them would only pad the shield.
    /// </summary>
    public void Remember(string? peerIp)
    {
        if (string.IsNullOrWhiteSpace(peerIp) ||
            !FirewallService.TryNormalizeIp(peerIp, out var normalized, out _))
            return;

        // "0.0.0.0" and "::" reach here from a wildcard SA or a %any config; they are not
        // peers, and shielding the unspecified address would be meaningless at best.
        if (!IPAddress.TryParse(normalized, out var parsed) ||
            parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any))
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

        // Unconditional, as in the WireGuard guard: peers learned outside the loop must
        // reach disk before the process goes away.
        Save();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { SampleOnce(); }
            catch (Exception ex) { _status = $"IPSec endpoint protection error: {ex.Message}"; }

            try { await Task.Delay(SampleInterval, ct); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>One refresh pass. Internal so tests can drive it without the loop.</summary>
    internal void SampleOnce()
    {
        if (!IpsecPresent())
        {
            // No IPSec on this host: nothing to shield, and no reason to spawn anything.
            // Remembered peers are kept — a tunnel that is down right now is the case that
            // matters most, and its config may have been removed along with it.
            _status = Remembered() > 0
                ? $"No IPSec configuration found; {Remembered()} recent endpoint(s) still shielded from auto-block"
                : "No IPSec configuration on this host";
            Save();
            return;
        }

        var live = 0;
        string? failure = null;

        if (TryRunXfrmState(out var xfrm, out var xfrmError))
        {
            foreach (var peer in ParseXfrmState(xfrm))
            {
                Remember(peer);
                live++;
            }
        }
        else
        {
            failure = xfrmError;
        }

        // IKE is up but no child SA is installed yet — a window `ip xfrm state` shows
        // nothing for, and the window a flapping tunnel spends most of its time in.
        if (TryRunIkeStatus(out var status))
        {
            foreach (var peer in ParseSaStatus(status))
            {
                Remember(peer);
                live++;
            }
        }

        var fromConfig = 0;
        foreach (var peer in ConfiguredPeers())
        {
            Remember(peer);
            fromConfig++;
        }

        Save();

        var shielded = Remembered();
        if (failure == null || live > 0 || fromConfig > 0)
        {
            _status = $"Shielding {shielded} IPSec endpoint(s) from auto-block";
        }
        else
        {
            // The dangerous combination: this host runs IPSec, its peers are unreadable,
            // and auto-block may still be armed through pkexec/sudo.
            _status = $"IPSec is configured here but its peers cannot be read ({failure}) — " +
                      "run as root, or a VPN peer's address can be auto-blocked.";
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
    /// Whether this host runs IPSec at all — checked from the filesystem, with no
    /// subprocess, so a host without it spends nothing. XFRM state counts on its own:
    /// the kernel only reports SAs when something actually established a tunnel, which
    /// covers stacks that keep their config somewhere this guard does not look.
    /// </summary>
    internal static bool IpsecPresent()
    {
        try
        {
            if (File.Exists(IpsecConfFile) || File.Exists(SwanctlConfFile)) return true;
            if (Directory.Exists(IpsecConfDirectory) || Directory.Exists(SwanctlConfDirectory)) return true;
            return HasXfrmState();
        }
        catch
        {
            // No /etc or no /proc (a container, a non-Linux test host) — treat as absent.
            return false;
        }
    }

    /// <summary>
    /// True when the kernel reports at least one non-zero XFRM counter. Reading the file
    /// itself proves only that the module is loaded, which is true on plenty of hosts that
    /// never ran a tunnel; a non-zero counter means packets actually went through it.
    /// </summary>
    private static bool HasXfrmState()
    {
        try
        {
            if (!File.Exists(XfrmStatFile)) return false;
            foreach (var line in File.ReadLines(XfrmStatFile))
            {
                var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && long.TryParse(parts[^1].Trim(), out var count) && count > 0)
                    return true;
            }
        }
        catch
        {
            // Unreadable /proc entry — no evidence either way, so no claim.
        }
        return false;
    }

    /// <summary>
    /// Runs <c>ip xfrm state</c>. Internal so the guard and its tests share one path.
    /// Note this deliberately reads *state* and not *policy*: policies carry traffic
    /// selectors, which is exactly the subnet data that must not enter the shield.
    /// </summary>
    internal static bool TryRunXfrmState(out string output, out string error)
        => TryRun("ip", new[] { "xfrm", "state" }, out output, out error);

    /// <summary>
    /// Asks the IKE daemon directly. strongSwan 5.9+ ships <c>swanctl</c>; older
    /// strongSwan and libreswan answer <c>ipsec status</c>. Failure is not reported as an
    /// error — plenty of correct hosts have neither binary, and <c>ip xfrm state</c> has
    /// already covered the established case.
    /// </summary>
    internal static bool TryRunIkeStatus(out string output)
    {
        if (TryRun("swanctl", new[] { "--list-sas" }, out output, out _) && !string.IsNullOrWhiteSpace(output))
            return true;
        return TryRun("ipsec", new[] { "status" }, out output, out _) && !string.IsNullOrWhiteSpace(output);
    }

    private static bool TryRun(string file, IReadOnlyList<string> args, out string output, out string error)
    {
        output = "";
        error = "";
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            foreach (var arg in args) psi.ArgumentList.Add(arg);

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                error = $"Could not start `{file}`";
                return false;
            }

            output = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(5000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                error = $"`{file} {string.Join(' ', args)}` timed out";
                return false;
            }

            if (proc.ExitCode != 0)
            {
                error = stderr.Contains("permitted", StringComparison.OrdinalIgnoreCase) ||
                        stderr.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
                        stderr.Contains("root", StringComparison.OrdinalIgnoreCase)
                    ? "reading IPSec state needs root (CAP_NET_ADMIN) — run the service as root"
                    : $"`{file} {string.Join(' ', args)}` failed: {FirstLine(stderr)}";
                return false;
            }

            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            error = $"`{file}` not found";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Pulls both ends of every SA out of <c>ip xfrm state</c>. Internal for tests /
    /// replaying captured output.
    ///
    /// State blocks open with a line of the form <c>src A dst B</c>. Both addresses are
    /// kept: which one is the peer depends on the SA's direction, and this host's own
    /// address is refused by the prevention engine independently, so taking the pair
    /// costs nothing and avoids guessing wrong on one direction of the pair.
    ///
    /// Keys and nonces appear in this output (<c>auth-trunc</c>, <c>enc</c>, <c>aead</c>);
    /// no line but the <c>src … dst …</c> header is read, so they never enter the process.
    /// </summary>
    internal static List<string> ParseXfrmState(string output)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(output)) return found;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith("src ", StringComparison.Ordinal)) continue;

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i + 1 < parts.Length; i++)
            {
                if (parts[i] is not ("src" or "dst")) continue;

                // A tunnel-mode SA header carries bare addresses; anything with a prefix
                // length is a selector line and must not be taken.
                var value = parts[i + 1];
                if (value.Contains('/')) continue;
                if (TryCanonicalAddress(value, out var address))
                    found.Add(address);
            }
        }

        return found;
    }

    /// <summary>
    /// Pulls peer addresses out of <c>swanctl --list-sas</c> or <c>ipsec status</c>.
    /// Internal for tests / replaying captured output.
    ///
    /// The two formats differ but agree on how they write an endpoint — an address
    /// followed by a bracketed IKE port:
    ///
    ///   swanctl:  <c>remote 'peer' @ 198.51.100.7[500]</c>
    ///   ipsec:    <c>site-to-site[1]: ESTABLISHED, 203.0.113.4[500]...198.51.100.7[500]</c>
    ///
    /// Matching on that shape covers both without a parser per daemon, and ignores the
    /// identities, subnets and SPIs around it. Identities are quoted and can contain
    /// anything, including an address — hence the bracketed port is required, not optional.
    /// </summary>
    internal static List<string> ParseSaStatus(string output)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(output)) return found;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            for (var i = 0; i < line.Length; i++)
            {
                if (line[i] != '[') continue;

                var close = line.IndexOf(']', i + 1);
                if (close < 0) break;

                // "[500]" — a port, so what precedes it is an endpoint. An IPv6 endpoint
                // is written "[2001:db8::1]:500" instead and is handled below.
                if (close > i + 1 && line[(i + 1)..close].All(char.IsDigit))
                {
                    var host = HostBefore(line, i);
                    if (!string.IsNullOrEmpty(host)) found.Add(host);
                    i = close;
                    continue;
                }

                // A bracketed IPv6 literal: take it when a port follows, which is what
                // distinguishes an endpoint from a subnet or an identity.
                if (close + 1 < line.Length && line[close + 1] == ':' &&
                    TryCanonicalAddress(line[(i + 1)..close], out var v6))
                {
                    found.Add(v6);
                    i = close;
                }
            }
        }

        return found;
    }

    /// <summary>
    /// The address immediately left of a bracketed port, scanning back over the characters
    /// an address can contain and stopping at the separators these formats use (space,
    /// the <c>...</c> between the two ends of an SA, a quote closing an identity).
    /// </summary>
    private static string HostBefore(string line, int bracket)
    {
        var end = bracket;
        var start = end;
        while (start > 0)
        {
            var c = line[start - 1];
            if (char.IsAsciiHexDigit(c) || c is '.' or ':')
                start--;
            else
                break;
        }

        if (start >= end) return "";

        // "...198.51.100.7" leaves the separating dots once the scan stops at the space.
        var candidate = line[start..end].TrimStart('.');
        return TryCanonicalAddress(candidate, out var host) ? host : "";
    }

    /// <summary>
    /// Parses an address and insists it round-trips. <see cref="IPAddress.TryParse(string, out IPAddress)"/>
    /// alone accepts shorthand forms, so a connection named <c>tunnel123</c> in
    /// <c>ipsec status</c> — or a stray <c>left = 123</c> — would otherwise be read as
    /// 0.0.0.123 and quietly enter the never-block list. Requiring the canonical text back
    /// rejects those without rejecting an uppercase IPv6 literal, hence the case-insensitive
    /// comparison.
    /// </summary>
    private static bool TryCanonicalAddress(string candidate, out string canonical)
    {
        canonical = "";
        if (string.IsNullOrEmpty(candidate) || !IPAddress.TryParse(candidate, out var parsed))
            return false;

        var text = parsed.ToString();
        if (!text.Equals(candidate, StringComparison.OrdinalIgnoreCase))
            return false;

        canonical = text;
        return true;
    }

    /// <summary>Peer addresses named in the IPSec config files. Root-only, best effort.</summary>
    private static List<string> ConfiguredPeers()
    {
        var found = new List<string>();

        foreach (var file in ConfigFiles())
        {
            try { found.AddRange(ParseConfigPeers(File.ReadAllText(file))); }
            catch { /* unreadable without root, or removed mid-scan */ }
        }

        return found;
    }

    private static List<string> ConfigFiles()
    {
        var files = new List<string>();

        void AddFile(string path)
        {
            try { if (File.Exists(path)) files.Add(path); }
            catch { /* unreadable — nothing to add */ }
        }

        void AddDirectory(string path)
        {
            try
            {
                if (Directory.Exists(path))
                    files.AddRange(Directory.EnumerateFiles(path, "*.conf"));
            }
            catch { /* no permission to list it */ }
        }

        AddFile(IpsecConfFile);
        AddFile(SwanctlConfFile);
        // /etc/ipsec.d also holds certificates and private keys, in their own
        // subdirectories — only *.conf at the top level is ever opened.
        AddDirectory(IpsecConfDirectory);
        AddDirectory(SwanctlConfDirectory);

        files.Sort(StringComparer.Ordinal);
        return files;
    }

    /// <summary>
    /// Pulls literal peer addresses out of an <c>ipsec.conf</c>- or <c>swanctl.conf</c>-style
    /// config. Internal for tests.
    ///
    /// Only four keys are read — <c>left</c>, <c>right</c>, <c>local_addrs</c> and
    /// <c>remote_addrs</c> — and only when the value is a bare address. Everything else in
    /// these files is either a secret (<c>*secret</c>, key paths), an identity that an
    /// attacker controls, or a traffic selector holding subnets. Prefixes such as
    /// <c>leftsubnet</c> and <c>rightsourceip</c> therefore have to fail the match, which
    /// is why the comparison is on the whole key and not a <c>StartsWith</c>.
    ///
    /// Both ends are read for the same reason <see cref="ParseXfrmState"/> keeps both: the
    /// convention that <c>left</c> is the local end is only a convention, configs are
    /// routinely written from the other site's perspective, and shielding this host's own
    /// address changes nothing — it is already never auto-blocked.
    /// </summary>
    internal static List<string> ParseConfigPeers(string config)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(config)) return found;

        foreach (var raw in config.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';') continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;

            var key = line[..eq].Trim();
            if (!key.Equals("left", StringComparison.OrdinalIgnoreCase) &&
                !key.Equals("right", StringComparison.OrdinalIgnoreCase) &&
                !key.Equals("local_addrs", StringComparison.OrdinalIgnoreCase) &&
                !key.Equals("remote_addrs", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = line[(eq + 1)..].Trim();
            var comment = value.IndexOfAny(new[] { '#', ';' });
            if (comment >= 0) value = value[..comment].Trim();

            // swanctl takes a list: "remote_addrs = 198.51.100.7, 203.0.113.9".
            foreach (var item in value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = item.Trim();
                if (candidate.Length == 0) continue;

                // "%any" (accept any peer), a hostname, or a subnet. None of them names a
                // single address this host can safely add to a never-block list.
                if (candidate.StartsWith('%') || candidate.Contains('/')) continue;

                if (TryCanonicalAddress(candidate, out var address))
                    found.Add(address);
            }
        }

        return found;
    }

    private static string StatePath => Path.Combine(AppPaths.DataDirectory, "ipsec-endpoints.json");

    /// <summary>
    /// Peer addresses only. A restart with an empty memory would re-open the block window
    /// at exactly the wrong moment — the tunnel is down, so the kernel reports no SA, so
    /// the address that would restore it looks like any other stranger.
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

    private static string FirstLine(string text)
    {
        var line = text.Split('\n').FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
        return string.IsNullOrWhiteSpace(line) ? "unknown error" : line.Trim();
    }

    public void Dispose() => Stop();
}
