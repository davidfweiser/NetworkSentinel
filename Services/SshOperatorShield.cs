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
/// attacker's brute-force connections are established TCP sessions too. It counts for
/// the accounts that logged in from it, which is what a failed-logon burst is held
/// against: a login as one account does not excuse guesses at another. Three sources,
/// none of which another local account can forge:
/// <list type="bullet">
/// <item>sessions logged in right now, from the utmp records (/run/utmp) sshd writes the
/// client's address into — not ut_host, which libutempter's setgid-utmp helper lets any
/// local user fill in;</item>
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
    private const int UtUserOffset = 44;
    private const int UtUserLength = 32;
    private const int UtAddrOffset = 348;

    private readonly string _storePath;
    private readonly string _utmpPath;
    private readonly object _gate = new();
    /// <summary>Address → account → when it last logged in from there.</summary>
    private readonly Dictionary<string, Dictionary<string, DateTime>> _logins = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Address → accounts logged in from it right now.</summary>
    private Dictionary<string, HashSet<string>> _live = new(StringComparer.OrdinalIgnoreCase);
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

    /// <summary>Remembers a successful SSH login as <paramref name="account"/> from <paramref name="ip"/>.</summary>
    public void RecordLogin(string ip, string account)
    {
        if (!IsAccountName(account))
            return;
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return;
        // Never auto-blocked in the first place, so not worth a line on disk.
        if (FirewallService.IsPrivateOrLocal(normalized))
            return;

        lock (_gate)
        {
            if (!_logins.TryGetValue(normalized, out var accounts))
                _logins[normalized] = accounts = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            accounts[account] = UtcNow();
            PruneLocked();
            SaveLocked();
        }
    }

    /// <summary>What sshd logs as an account that logged in: no whitespace, no control characters.</summary>
    private static bool IsAccountName(string? account) =>
        !string.IsNullOrEmpty(account) && account.Length <= 256
        && !account.Any(c => char.IsWhiteSpace(c) || char.IsControl(c));

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
                RecordLogin(client, Environment.UserName);
                return;
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="ip"/> is logged in over SSH now, or did so within
    /// <see cref="RememberFor"/>. Given <paramref name="accounts"/> — the accounts a
    /// failed-logon burst tried — only when every one of them is an account that did:
    /// someone with a login here guessing root's password from the same address is not
    /// the operator mistyping their own. An empty list, or an attempt that named no
    /// account (""), is never shielded.
    /// </summary>
    public bool IsShielded(string ip, IReadOnlyCollection<string>? accounts = null)
    {
        if (accounts is { Count: 0 })
            return false;
        if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
            return false;

        lock (_gate)
        {
            var now = UtcNow();
            if (now - _liveReadAt > LiveCacheFor)
            {
                _live = ReadLiveSessions();
                _liveReadAt = now;
            }

            var loggedIn = new HashSet<string>(StringComparer.Ordinal);
            if (_logins.TryGetValue(normalized, out var remembered))
                loggedIn.UnionWith(remembered.Where(kv => now - kv.Value <= RememberFor).Select(kv => kv.Key));
            if (_live.TryGetValue(normalized, out var live))
                loggedIn.UnionWith(live);

            return accounts == null ? loggedIn.Count > 0 : accounts.All(loggedIn.Contains);
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
                return _logins.Where(kv => kv.Value.Values.Any(at => now - at <= RememberFor)).Select(kv => kv.Key)
                    .Concat(_live.Keys)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }
    }

    private Dictionary<string, HashSet<string>> ReadLiveSessions()
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(_utmpPath)) return result;
            foreach (var (ip, account) in ParseUtmp(File.ReadAllBytes(_utmpPath)))
            {
                if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                    continue;
                if (!result.TryGetValue(normalized, out var accounts))
                    result[normalized] = accounts = new HashSet<string>(StringComparer.Ordinal);
                accounts.Add(account);
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
    /// Remote addresses and accounts of the logged-in sessions in a utmp file. A login
    /// over SSH is a USER_PROCESS record whose ut_addr_v6 holds the client address
    /// (network byte order, IPv4 in the first four bytes) — sshd fills it in from the
    /// socket. A record without one is not taken on the word of its ut_host: that is free
    /// text, and libutempter's setgid-utmp helper (installed with most terminal emulators)
    /// lets any local user add a record with whatever host they like. It never sets
    /// ut_addr_v6, and the ut_user it writes is the caller's own. A file that is not a
    /// whole number of records is not glibc's 64-bit layout and is ignored rather than
    /// misread.
    /// </summary>
    internal static List<(string Address, string Account)> ParseUtmp(byte[] data)
    {
        var sessions = new List<(string, string)>();
        if (data.Length == 0 || data.Length % UtmpRecordSize != 0)
            return sessions;

        for (var offset = 0; offset < data.Length; offset += UtmpRecordSize)
        {
            if (BitConverter.ToInt16(data, offset) != UserProcess)
                continue;

            var addr = data.AsSpan(offset + UtAddrOffset, 16);
            if (addr.IndexOfAnyExcept((byte)0) < 0)
                continue;

            var userBytes = data.AsSpan(offset + UtUserOffset, UtUserLength);
            var end = userBytes.IndexOf((byte)0);
            var account = Encoding.ASCII.GetString(end >= 0 ? userBytes[..end] : userBytes);
            if (!IsAccountName(account))
                continue;

            var v4 = addr[4..].IndexOfAnyExcept((byte)0) < 0;
            sessions.Add((new IPAddress(v4 ? addr[..4] : addr).ToString(), account));
        }
        return sessions;
    }

    private void PruneLocked()
    {
        var now = UtcNow();
        foreach (var accounts in _logins.Values)
        {
            foreach (var stale in accounts.Where(kv => now - kv.Value > RememberFor).Select(kv => kv.Key).ToList())
                accounts.Remove(stale);
        }

        // Oldest first past the cap; a busy jump host does not need its whole history.
        var logins = _logins.SelectMany(ip => ip.Value.Select(a => (Ip: ip.Key, Account: a.Key, At: a.Value))).ToList();
        if (logins.Count > MaxRemembered)
        {
            foreach (var oldest in logins.OrderBy(l => l.At).Take(logins.Count - MaxRemembered))
                _logins[oldest.Ip].Remove(oldest.Account);
        }

        foreach (var empty in _logins.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList())
            _logins.Remove(empty);
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_storePath)) return;
            // { address: { account: last login } }. A file from before accounts were
            // recorded ({ address: last login }) does not parse as this and is dropped:
            // it cannot say whose logins it vouches for.
            var saved = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, DateTime>>>(
                File.ReadAllText(_storePath));
            if (saved == null) return;
            lock (_gate)
            {
                foreach (var (ip, accounts) in saved)
                {
                    if (!FirewallService.TryNormalizeIp(ip, out var normalized, out _))
                        continue;
                    foreach (var (account, at) in accounts)
                    {
                        if (!IsAccountName(account))
                            continue;
                        if (!_logins.TryGetValue(normalized, out var known))
                            _logins[normalized] = known = new Dictionary<string, DateTime>(StringComparer.Ordinal);
                        known[account] = DateTime.SpecifyKind(at, DateTimeKind.Utc);
                    }
                }
                PruneLocked();
            }
        }
        catch
        {
            // A damaged or older file only means starting without remembered logins.
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
