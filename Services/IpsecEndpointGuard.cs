using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
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
///   - <c>netsh advfirewall monitor show mmsa</c> and <c>qmsa</c> for live security
///     associations. These are the implementation-independent source: an IKEv2 client VPN,
///     an RRAS site-to-site tunnel and a domain-isolation policy all install SAs the same
///     Windows Filtering Platform reports, so one parser covers every case.
///   - <c>netsh advfirewall consec show rule name=all</c>, the connection-security rules,
///     which name the far end even with no tunnel established — the Windows analogue of
///     reading <c>ipsec.conf</c>.
///   - the RAS phonebooks: <c>ras\router.pbk</c> for RRAS demand-dial (site-to-site)
///     interfaces and <c>rasphone.pbk</c> for client VPN connections. Plain INI files, read
///     directly with no subprocess, and they still name the peer of a tunnel that is
///     already down — the state a site is in after the very block this guard prevents.
///   - a persisted 24 h memory of every peer seen, so a restart, a re-keying window, a
///     momentary command failure, or a tunnel that has *already* dropped never opens a
///     gap where the address becomes blockable.
///
/// Only single addresses are ever taken. A connection-security rule's endpoints can hold a
/// subnet or an address range, and a phonebook entry can name a whole pool; anything
/// carrying a prefix or a range is skipped, because a shield that swallowed a default route
/// would silently disable auto-block for the whole internet. Hostnames are not resolved —
/// a phonebook overwhelmingly holds them, and whoever can answer DNS could otherwise write
/// their own address into a never-block list. The live SA views report the address itself.
///
/// Reading SA state needs Administrator. When this host clearly runs IPSec but that state
/// cannot be read, <see cref="Status"/> says so in as many words: an unelevated run that
/// later gains rights through UAC can still write firewall rules, so silence there would be
/// the dangerous case.
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

        // "0.0.0.0" and "::" reach here from a wildcard SA or an "any" endpoint; they are
        // not peers, and shielding the unspecified address would be meaningless at best.
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
        // The phonebooks are plain files readable without elevation, so they answer "does
        // this host dial a VPN at all" for nothing, and they keep answering it in the
        // unelevated case below where nothing else can be read.
        var configured = 0;
        foreach (var peer in PhonebookPeers())
        {
            Remember(peer);
            configured++;
        }

        if (!IsElevated())
        {
            // Every netsh view used here refuses without elevation, so there is nothing to
            // gain by spawning them. This is not the alarming case the Linux guard warns
            // about: writing a firewall rule needs Administrator too, so a process that
            // cannot read the tunnel state cannot auto-block its peer either. The memory
            // still shields whatever earlier elevated runs recorded.
            Save();
            var remembered = Remembered();
            _status = remembered > 0
                ? $"Not elevated: live IPSec state is unreadable, but no rule can be written either; " +
                  $"{remembered} remembered endpoint(s) still shielded"
                : "Not elevated: live IPSec state is unreadable, and no firewall rule can be written either";
            return;
        }

        // Unlike the Linux guard there is no cheap file check for the rest — a
        // connection-security rule lives in the firewall, not in a file — so the netsh
        // views are queried on every pass. Three small queries a minute is well under what
        // the rule list already costs the console.
        var live = 0;
        string? failure = null;

        if (TryRunNetsh("advfirewall monitor show mmsa", out var mmsa, out var mmError))
        {
            foreach (var peer in ParseAddresses(mmsa))
            {
                Remember(peer);
                live++;
            }
        }
        else
        {
            failure = mmError;
        }

        // The child SA. Established later than the IKE SA above, so on its own it would
        // miss the window a flapping tunnel spends most of its time in.
        if (TryRunNetsh("advfirewall monitor show qmsa", out var qmsa, out _))
        {
            foreach (var peer in ParseAddresses(qmsa))
            {
                Remember(peer);
                live++;
            }
        }

        // Connection-security rules name the far end whether or not anything is up.
        var rules = 0;
        if (TryRunNetsh("advfirewall consec show rule name=all", out var consec, out _))
        {
            foreach (var peer in ParseAddresses(consec))
            {
                Remember(peer);
                rules++;
            }
        }

        Save();

        var shielded = Remembered();
        var evidence = live + rules + configured;

        if (failure != null && live == 0 && evidence > 0)
        {
            // The dangerous combination: this host clearly does IPSec, its live peers are
            // unreadable, and this process can write firewall rules.
            _status = $"IPSec is configured here but its security associations cannot be read ({failure}) — " +
                      "a VPN peer's address can be auto-blocked.";
            return;
        }

        if (evidence == 0)
        {
            // Nothing here does IPSec. Remembered peers are kept — a tunnel that is down
            // right now is the case that matters most, and its config may have gone with it.
            _status = shielded > 0
                ? $"No IPSec configuration found; {shielded} recent endpoint(s) still shielded from auto-block"
                : "No IPSec configuration on this host";
            return;
        }

        _status = $"Shielding {shielded} IPSec endpoint(s) from auto-block";
    }

    /// <summary>
    /// Whether this process can read IPSec state at all. Every netsh view the guard uses
    /// refuses without elevation, and refuses in a way no exit code reports (see
    /// <see cref="TryRunNetsh"/>), so the question is asked up front instead.
    /// </summary>
    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
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
    /// Runs one netsh query. Separate from <see cref="FirewallService"/>'s own runner
    /// because this one must report *why* it failed: "needs Administrator" is the whole
    /// point of the status line, and a guard that silently reported nothing would be
    /// indistinguishable from a host with no tunnels.
    /// </summary>
    private static bool TryRunNetsh(string arguments, out string output, out string error)
    {
        output = "";
        error = "";
        try
        {
            var netshExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
            if (!File.Exists(netshExe)) netshExe = "netsh";

            var psi = new ProcessStartInfo
            {
                FileName = netshExe,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                error = "could not start netsh";
                return false;
            }

            // Drained concurrently: a full rule dump can fill a pipe buffer, and a
            // sequential read of one stream would deadlock against the other.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(10000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                error = "netsh timed out";
                return false;
            }

            output = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();
            var combined = stderr + output;

            // netsh reports this refusal on stdout and still exits 0, so the exit code
            // alone would read an unelevated run as "this host has no IPSec" — the exact
            // silence this guard exists to avoid. Belt and braces with the privilege check
            // in SampleOnce, and it is the only defence if a view is ever restricted some
            // other way.
            if (combined.Contains("requires elevation", StringComparison.OrdinalIgnoreCase) ||
                combined.Contains("Run as administrator", StringComparison.OrdinalIgnoreCase))
            {
                error = "needs Administrator";
                return false;
            }

            if (proc.ExitCode != 0)
            {
                error = combined.Contains("denied", StringComparison.OrdinalIgnoreCase)
                    ? "needs Administrator"
                    : FirstLine(combined);
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Every single address in a netsh view, whatever the labels around it are called.
    /// Internal for tests / replaying captured output.
    ///
    /// Label-blind on purpose. netsh output is localized, so keying on "Remote IP Address"
    /// would make the shield work only on English installs — and in these three views every
    /// address that appears *is* an endpoint or an endpoint's peer, so there is nothing else
    /// to pick up. Both ends are kept for the same reason the Linux guard keeps both: which
    /// one is the peer depends on the SA's direction, and this host's own address is refused
    /// by the prevention engine independently, so taking the pair costs nothing.
    ///
    /// Anything carrying a prefix or written as a range is skipped — those are the selectors
    /// and address pools that must never enter a never-block list.
    /// </summary>
    internal static List<string> ParseAddresses(string output)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(output)) return found;

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            // A rule's own name can be anything at all, including something that parses as
            // an address, so the name line is skipped rather than scanned.
            if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase)) continue;

            foreach (var token in line.Split(new[] { ' ', '\t', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = token.Trim();
                if (candidate.Length == 0) continue;

                // "10.0.0.0/24" is a selector, "10.0.0.1-10.0.0.9" a pool. Neither names a
                // single peer, and a shield that took them could swallow a default route.
                if (candidate.Contains('/') || candidate.Contains('-')) continue;

                if (TryCanonicalAddress(candidate, out var address))
                    found.Add(address);
            }
        }

        return found;
    }

    /// <summary>
    /// Peer addresses named in the RAS phonebooks. Internal for tests.
    ///
    /// A phonebook is INI: one section per connection, with the far end in
    /// <c>PhoneNumber</c>. <c>router.pbk</c> holds RRAS demand-dial interfaces — the
    /// site-to-site case — and <c>rasphone.pbk</c> holds client VPN connections.
    ///
    /// Only <c>PhoneNumber</c> is read. The rest of the file is credentials, adapter GUIDs
    /// and dial parameters, and one of the other address-shaped fields (<c>IpAddress</c>,
    /// <c>IpDnsAddress</c>) is this host's *inner* tunnel address, which is not a peer.
    /// Hostnames — which is what most entries hold — contribute nothing, deliberately.
    /// </summary>
    internal static List<string> ParsePhonebookPeers(string phonebook)
    {
        var found = new List<string>();
        if (string.IsNullOrWhiteSpace(phonebook)) return found;

        foreach (var raw in phonebook.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';' or '[') continue;

            var eq = line.IndexOf('=');
            if (eq <= 0) continue;

            if (!line[..eq].Trim().Equals("PhoneNumber", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = line[(eq + 1)..].Trim();
            if (value.Length == 0 || value.Contains('/') || value.Contains('-')) continue;

            if (TryCanonicalAddress(value, out var address))
                found.Add(address);
        }

        return found;
    }

    /// <summary>
    /// Parses an address and insists it round-trips. <see cref="IPAddress.TryParse(string, out IPAddress)"/>
    /// alone accepts shorthand forms, so a rule named <c>tunnel123</c> — or any bare number
    /// in the output — would otherwise be read as 0.0.0.123 and quietly enter the
    /// never-block list. Requiring the canonical text back rejects those without rejecting
    /// an uppercase IPv6 literal, hence the case-insensitive comparison.
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

    /// <summary>Peer addresses from every phonebook this host has. Best effort.</summary>
    private static List<string> PhonebookPeers()
    {
        var found = new List<string>();

        foreach (var file in PhonebookFiles())
        {
            try { found.AddRange(ParsePhonebookPeers(File.ReadAllText(file))); }
            catch { /* unreadable without rights, or removed mid-scan */ }
        }

        return found;
    }

    private static List<string> PhonebookFiles()
    {
        var files = new List<string>();

        void AddFile(string path)
        {
            try { if (path.Length > 0 && File.Exists(path)) files.Add(path); }
            catch { /* unreadable — nothing to add */ }
        }

        // RRAS demand-dial interfaces: the site-to-site case.
        AddFile(Path.Combine(Environment.SystemDirectory, "ras", "router.pbk"));

        // Client VPN connections, all-user and per-user.
        var pbk = Path.Combine("Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk");
        AddFile(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), pbk));
        AddFile(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), pbk));

        files.Sort(StringComparer.OrdinalIgnoreCase);
        return files;
    }

    private static string StatePath => Path.Combine(AppPaths.DataDirectory, "ipsec-endpoints.json");

    /// <summary>
    /// Peer addresses only. A restart with an empty memory would re-open the block window
    /// at exactly the wrong moment — the tunnel is down, so there is no SA to read, so the
    /// address that would restore it looks like any other stranger.
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
