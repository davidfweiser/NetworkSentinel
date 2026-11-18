using System.IO;
using System.Net;
using System.Text.Json;
using NetworkSentinel.Native;

namespace NetworkSentinel.Services;

/// <summary>
/// Addresses people actually administer this machine from — over Remote Desktop, SMB,
/// WinRM or SSH — which auto-block leaves alone. Without it the operator's own address
/// was fair game: four mistyped passwords from a public IP within ten minutes raise a
/// High logon burst, and the default auto-block level then firewalls them off the box
/// for a day, in both directions, taking the session they were typing into with it.
///
/// An address counts when it has <em>authenticated</em>, never merely connected: an
/// attacker's brute-force connections are established TCP sessions too. Three sources:
/// <list type="bullet">
/// <item>Remote Desktop sessions someone is logged on to right now (see
/// <see cref="WtsSessions"/>);</item>
/// <item>successful remote logons in the last <see cref="RememberFor"/>, from 4624
/// events in the Security log (see <see cref="AuthLogMonitor"/>), kept on disk so a
/// restart does not forget them;</item>
/// <item>the SSH session this process itself was started from (SSH_CONNECTION), as when
/// the terminal UI runs over Windows' OpenSSH server.</item>
/// </list>
/// OpenSSH logons are otherwise not seen: the Security log records them with no client
/// address, and OpenSSH's own event channel can be written to by any local process, so
/// an "Accepted" line there proves nothing.
///
/// The remembered logons live in the data directory, which every local user can write
/// to (see <see cref="AppPaths"/>) — the same standing as the allowlist beside it, which
/// already decides what auto-block may touch.
///
/// Like the console's own operator shield, this only stops the machine deciding on its
/// own; blocking an address by hand still works.
/// </summary>
public sealed class RemoteLogonShield
{
    /// <summary>How long a successful logon keeps its address shielded.</summary>
    public static readonly TimeSpan RememberFor = TimeSpan.FromDays(30);

    private static readonly TimeSpan LiveCacheFor = TimeSpan.FromSeconds(10);
    private const int MaxRemembered = 256;

    private readonly string _storePath;
    private readonly Func<IEnumerable<string>> _readLiveSessions;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _logins = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _live = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _liveReadAt = DateTime.MinValue;

    /// <summary>The clock; tests move it.</summary>
    internal Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    public RemoteLogonShield()
        : this(Path.Combine(AppPaths.DataDirectory, "remote-logons.json"), WtsSessions.LoggedOnClientAddresses)
    {
    }

    internal RemoteLogonShield(string storePath, Func<IEnumerable<string>> readLiveSessions)
    {
        _storePath = storePath;
        _readLiveSessions = readLiveSessions;
        Load();
    }

    /// <summary>Remembers a successful remote logon from <paramref name="ip"/>.</summary>
    public void RecordLogin(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;
        // Never auto-blocked in the first place, so not worth a line on disk.
        if (FirewallService.IsPrivateOrLocal(normalized))
            return;

        lock (_gate)
        {
            _logins[normalized] = UtcNow();
            SaveLocked();
        }
    }

    /// <summary>
    /// Shields the client of the SSH session this process runs in, if it runs in one.
    /// OpenSSH sets SSH_CONNECTION ("client port server port") only after authentication.
    /// </summary>
    public void RecordCurrentProcessSession()
    {
        foreach (var name in new[] { "SSH_CONNECTION", "SSH_CLIENT" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            var client = value?.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (client != null && IPAddress.TryParse(client, out _))
            {
                RecordLogin(client);
                return;
            }
        }
    }

    /// <summary>Whether <paramref name="ip"/> is logged on now, or logged on recently.</summary>
    public bool IsShielded(string ip)
    {
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return false;

        lock (_gate)
        {
            var now = UtcNow();
            if (_logins.TryGetValue(normalized, out var at) && now - at <= RememberFor)
                return true;

            if (now - _liveReadAt > LiveCacheFor)
            {
                _live = ReadLiveSessions();
                _liveReadAt = now;
            }
            return _live.Contains(normalized);
        }
    }

    private HashSet<string> ReadLiveSessions()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var ip in _readLiveSessions())
            {
                if (FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                    result.Add(normalized);
            }
        }
        catch
        {
            // Remote Desktop Services not running, or not readable from here: no live
            // sessions, and the remembered logons still apply.
        }
        return result;
    }

    private void PruneLocked()
    {
        var now = UtcNow();
        foreach (var stale in _logins.Where(kv => now - kv.Value > RememberFor).Select(kv => kv.Key).ToList())
            _logins.Remove(stale);

        // Oldest first past the cap; a busy jump host does not need its whole history.
        if (_logins.Count > MaxRemembered)
        {
            foreach (var oldest in _logins.OrderBy(kv => kv.Value).Take(_logins.Count - MaxRemembered)
                         .Select(kv => kv.Key).ToList())
                _logins.Remove(oldest);
        }
    }

    private void Load()
    {
        lock (_gate)
        {
            MergeFromDiskLocked();
            PruneLocked();
        }
    }

    /// <summary>
    /// Takes in what the file holds, keeping the later of two times for one address. The
    /// desktop app and the web service each keep a shield over the same file, so a save
    /// that wrote only its own set would drop every logon the other one had recorded.
    /// </summary>
    private void MergeFromDiskLocked()
    {
        try
        {
            if (!File.Exists(_storePath)) return;
            var saved = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(_storePath));
            if (saved == null) return;
            foreach (var (ip, at) in saved)
            {
                if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                    continue;
                var utc = DateTime.SpecifyKind(at, DateTimeKind.Utc);
                if (!_logins.TryGetValue(normalized, out var known) || utc > known)
                    _logins[normalized] = utc;
            }
        }
        catch
        {
            // A damaged file only means going on without the logons it held.
        }
    }

    private void SaveLocked()
    {
        try
        {
            MergeFromDiskLocked();
            PruneLocked();
            Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);
            AppPaths.WriteAtomic(_storePath, JsonSerializer.Serialize(_logins));
        }
        catch
        {
            // Best effort: the in-memory set still protects until the next restart.
        }
    }
}
