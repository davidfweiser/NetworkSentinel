using System.Net;
using System.Text;
using System.Text.Json;

namespace NetworkSentinel.Services;

/// <summary>
/// Addresses people actually administer this machine from over SSH, which auto-block
/// leaves alone. Without it the operator's own address was fair game: two mistyped
/// passwords from a public IP were enough to raise a High logon burst, and the
/// default auto-block level then firewalled them off the box for a day — in both
/// directions, killing the session they were typing into.
///
/// An address counts when it has *authenticated*, never merely connected: an
/// attacker's brute-force connections are established TCP sessions too. Three
/// sources, all of which only root can write:
/// <list type="bullet">
/// <item>sessions logged in right now, from the utmp table (/run/utmp) sshd keeps;</item>
/// <item>successful logins in the last <see cref="RememberFor"/>, from sshd's
/// "Accepted …" lines in journald (see <see cref="AuthLogMonitor"/>), kept on disk so a
/// restart does not forget them;</item>
/// <item>the SSH session this process itself was started from (SSH_CONNECTION), as when
/// the terminal UI runs over SSH.</item>
/// </list>
/// Like the console's own operator shield, this only stops the machine deciding on its
/// own; blocking an address by hand still works.
/// </summary>
public sealed class SshOperatorShield
{
    /// <summary>How long a successful login keeps its address shielded.</summary>
    public static readonly TimeSpan RememberFor = TimeSpan.FromDays(30);

    private static readonly TimeSpan LiveCacheFor = TimeSpan.FromSeconds(10);
    private const int MaxRemembered = 256;

    // glibc's struct utmp on 64-bit Linux (x86_64 and arm64 alike).
    private const int UtmpRecordSize = 384;
    private const short UserProcess = 7;
    private const int UtHostOffset = 76;
    private const int UtHostLength = 256;
    private const int UtAddrOffset = 348;

    private readonly string _storePath;
    private readonly string _utmpPath;
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _logins = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _live = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _liveReadAt = DateTime.MinValue;

    /// <summary>The clock; tests move it.</summary>
    internal Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    public SshOperatorShield()
        : this(Path.Combine(AppPaths.DataDirectory, "ssh-logins.json"), "/run/utmp")
    {
    }

    internal SshOperatorShield(string storePath, string utmpPath)
    {
        _storePath = storePath;
        _utmpPath = utmpPath;
        Load();
    }

    /// <summary>Remembers a successful SSH login from <paramref name="ip"/>.</summary>
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
            PruneLocked();
            SaveLocked();
        }
    }

    /// <summary>
    /// Shields the client of the SSH session this process runs in, if it runs in one.
    /// sshd sets SSH_CONNECTION ("client port server port") only after authentication.
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

    /// <summary>Whether <paramref name="ip"/> is logged in over SSH now, or did so recently.</summary>
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

    /// <summary>Remembered and live addresses, for display.</summary>
    public IReadOnlyCollection<string> Addresses
    {
        get
        {
            lock (_gate)
            {
                var now = UtcNow();
                return _logins.Where(kv => now - kv.Value <= RememberFor).Select(kv => kv.Key)
                    .Concat(_live)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }
    }

    private HashSet<string> ReadLiveSessions()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(_utmpPath)) return result;
            foreach (var ip in ParseUtmp(File.ReadAllBytes(_utmpPath)))
            {
                if (FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                    result.Add(normalized);
            }
        }
        catch
        {
            // Unreadable or a layout this parser does not know: no live sessions, and the
            // remembered logins still apply.
        }
        return result;
    }

    /// <summary>
    /// Remote addresses of the logged-in sessions in a utmp file. A login over SSH is a
    /// USER_PROCESS record whose ut_addr_v6 holds the client address (network byte order,
    /// IPv4 in the first four bytes), with ut_host as a fallback when sshd left it empty.
    /// A file that is not a whole number of records is not glibc's 64-bit layout and is
    /// ignored rather than misread.
    /// </summary>
    internal static List<string> ParseUtmp(byte[] data)
    {
        var addresses = new List<string>();
        if (data.Length == 0 || data.Length % UtmpRecordSize != 0)
            return addresses;

        for (var offset = 0; offset < data.Length; offset += UtmpRecordSize)
        {
            if (BitConverter.ToInt16(data, offset) != UserProcess)
                continue;

            var addr = data.AsSpan(offset + UtAddrOffset, 16);
            if (addr.IndexOfAnyExcept((byte)0) >= 0)
            {
                var v4 = addr[4..].IndexOfAnyExcept((byte)0) < 0;
                addresses.Add(new IPAddress(v4 ? addr[..4] : addr).ToString());
                continue;
            }

            var hostBytes = data.AsSpan(offset + UtHostOffset, UtHostLength);
            var end = hostBytes.IndexOf((byte)0);
            var host = Encoding.ASCII.GetString(end >= 0 ? hostBytes[..end] : hostBytes);
            if (IPAddress.TryParse(host, out var parsed))
                addresses.Add(parsed.ToString());
        }
        return addresses;
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
        try
        {
            if (!File.Exists(_storePath)) return;
            var saved = JsonSerializer.Deserialize<Dictionary<string, DateTime>>(File.ReadAllText(_storePath));
            if (saved == null) return;
            lock (_gate)
            {
                foreach (var (ip, at) in saved)
                {
                    if (FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                        _logins[normalized] = DateTime.SpecifyKind(at, DateTimeKind.Utc);
                }
                PruneLocked();
            }
        }
        catch
        {
            // A damaged file only means starting without remembered logins.
        }
    }

    private void SaveLocked()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);
            AppPaths.WriteAtomic(_storePath, JsonSerializer.Serialize(_logins),
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // Best effort: the in-memory set still protects until the next restart.
        }
    }
}
