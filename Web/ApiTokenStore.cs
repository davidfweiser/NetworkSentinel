using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Services;

namespace NetworkSentinel.Web;

/// <summary>
/// Tokens for the token API (<c>/api/v1/*</c>) — the credential a bot calls with, kept
/// apart from the master password and the sessions it opens.
///
/// A browser session is the whole console, Settings and credentials included. Handing
/// that to an unattended client would make every place the bot keeps its configuration
/// a route to all of it. A token from here reads by default; one created with control
/// access can also run the console's actions, short of Settings — and because that
/// reaches the firewall, such a token only exists pinned to the addresses the bot calls
/// from. Either kind expires and is revoked on its own without touching the password.
///
/// Only a SHA-256 of each token is stored. That is not the shortcut it would be for a
/// password: the secret is 256 bits from the CSPRNG, so there is no dictionary to run
/// and nothing for a slow hash to slow down — PBKDF2 here would only tax every poll.
/// </summary>
public sealed class ApiTokenStore
{
    /// <summary>Marks the string as ours, so a leaked one is recognisable in a config dump or a log.</summary>
    public const string TokenPrefix = "nsm_";

    public const int MaxTokens = 16;
    public const int MaxNameLength = 48;
    public const int MaxExpiryDays = 3650;

    /// <summary>Per token. A poller needs a handful; this only stops a runaway loop from costing the host.</summary>
    public const int RequestsPerMinute = 120;

    private const string AccessRead = "read";
    private const string AccessControl = "control";

    private const int IdLength = 12;
    private const int SecretBytes = 32;
    private static readonly TimeSpan RateWindow = TimeSpan.FromMinutes(1);

    /// <summary>Last-used bookkeeping is written back this often at most, not on every poll.</summary>
    private static readonly TimeSpan UsePersistInterval = TimeSpan.FromMinutes(5);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly object _gate = new();
    private readonly string _dataDirectory;
    private List<TokenRecord> _tokens = new();
    private DateTime _lastPersistUtc = DateTime.MinValue;

    /// <summary>What the file looked like when this process last read or wrote it.</summary>
    private (bool Exists, DateTime WrittenUtc, long Length) _diskStamp;

    /// <summary>
    /// Tokens revoked here whose removal has not reached the disk yet. Until it does,
    /// the file still lists them — so they are struck out again after every reload,
    /// and the write is retried, rather than a revocation lasting only until the next
    /// time something else touches the file.
    /// </summary>
    private readonly HashSet<string> _unsavedRevocations = new(StringComparer.Ordinal);
    private DateTime _lastSaveAttemptUtc = DateTime.MinValue;
    private static readonly TimeSpan SaveRetryInterval = TimeSpan.FromSeconds(10);

    /// <summary>Replaced by the tests, which cannot wait out an expiry or a rate window.</summary>
    internal Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    public ApiTokenStore() : this(AppPaths.DataDirectory)
    {
    }

    public ApiTokenStore(string dataDirectory)
    {
        _dataDirectory = dataDirectory;
        Load();
    }

    public const string FileName = "web-api-tokens.json";

    private string StorePath => Path.Combine(_dataDirectory, FileName);

    /// <summary>
    /// Mints a token and returns it — the only time it exists in the clear on this side.
    /// </summary>
    /// <param name="expiresInDays">0 means the token does not expire.</param>
    /// <param name="allowedSources">Comma-separated addresses or CIDR blocks; empty allows any source.</param>
    /// <param name="control">Also allow the control route. Requires <paramref name="allowedSources"/>.</param>
    public bool TryCreate(string? name, int expiresInDays, string? allowedSources, bool control,
        out string token, out string message)
    {
        token = "";

        var label = (name ?? "").Trim();
        if (label.Length == 0)
        {
            message = "Give the token a name — it is how you will tell tokens apart when one has to be revoked.";
            return false;
        }

        if (label.Length > MaxNameLength || label.Any(char.IsControl))
        {
            message = $"Token name must be plain text of at most {MaxNameLength} characters.";
            return false;
        }

        if (expiresInDays is < 0 or > MaxExpiryDays)
        {
            message = $"Expiry must be between 1 and {MaxExpiryDays} days, or 0 for no expiry.";
            return false;
        }

        if (!FirewallRuleSpecs.TryParseAddresses(allowedSources, out var sources, out var sourceError))
        {
            message = $"Allowed source addresses: {sourceError}";
            return false;
        }

        // A read-only token that leaks shows someone the dashboard. A control token that
        // leaks hands them the firewall, so it is never valid from just anywhere.
        if (control && sources.Count == 0)
        {
            message = "A control token can change the firewall, so it must name the addresses the bot calls from. " +
                      "Fill in Allowed source addresses (for example 203.0.113.7 or 10.8.0.0/24).";
            return false;
        }

        lock (_gate)
        {
            using var fileLock = AcquireFileLock();
            SyncFromDiskUnlocked();

            if (_tokens.Count >= MaxTokens)
            {
                message = $"There are already {MaxTokens} tokens — revoke one that is no longer used first.";
                return false;
            }

            if (_tokens.Any(t => string.Equals(t.Name, label, StringComparison.OrdinalIgnoreCase)))
            {
                message = $"A token named \"{label}\" already exists. Revoke it first, or pick another name.";
                return false;
            }

            string id;
            do
            {
                id = Convert.ToHexString(RandomNumberGenerator.GetBytes(IdLength / 2)).ToLowerInvariant();
            } while (_tokens.Any(t => t.Id == id));

            var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(SecretBytes))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            token = $"{TokenPrefix}{id}_{secret}";

            var now = UtcNow();
            _tokens.Add(new TokenRecord
            {
                Id = id,
                Name = label,
                Hash = Convert.ToHexString(HashToken(token)),
                CreatedUtc = now,
                ExpiresUtc = expiresInDays > 0 ? now.AddDays(expiresInDays) : null,
                AllowedSources = sources,
                Access = control ? AccessControl : AccessRead
            });

            try
            {
                SaveUnlocked();
            }
            catch (Exception ex)
            {
                // A token that exists only in memory would work until the next restart
                // and then vanish, with nothing on disk to revoke in the meantime.
                _tokens.RemoveAll(t => t.Id == id);
                token = "";
                message = $"The token could not be saved, so none was created: {ex.Message}";
                return false;
            }
        }

        message = $"{(control ? "Control" : "Read-only")} API token \"{label}\" created. Copy it now — only its hash is stored, so it cannot be shown again.";
        return true;
    }

    public bool Revoke(string? id, out string message)
    {
        var key = (id ?? "").Trim();

        lock (_gate)
        {
            using var fileLock = AcquireFileLock();
            SyncFromDiskUnlocked();

            var record = _tokens.FirstOrDefault(t => string.Equals(t.Id, key, StringComparison.OrdinalIgnoreCase));
            if (record == null)
            {
                message = "That token no longer exists.";
                return false;
            }

            _tokens.Remove(record);
            try
            {
                SaveUnlocked();
            }
            catch (Exception ex)
            {
                // Refused from this moment regardless — requests are checked against
                // memory, and the id is remembered so a reload cannot bring it back. But
                // the file still lists it and a restart would; that must not pass for a
                // clean revocation. The write is retried until it lands.
                _unsavedRevocations.Add(record.Id);
                message = $"API token \"{record.Name}\" is refused from now on, but the change could not be saved " +
                          $"({ex.Message}). This console keeps retrying; until it succeeds the token would come back " +
                          "on a restart — fix the token file's permissions or disk space and check this list again.";
                return false;
            }

            message = $"API token \"{record.Name}\" revoked — it stops working immediately.";
            return true;
        }
    }

    /// <summary>
    /// Revokes every token. What a master-password change does: a password is usually
    /// changed because something leaked, other sessions die with it, and a token minted
    /// under the old password is exactly the credential that should not survive.
    /// </summary>
    /// <param name="saved">False when the tokens are refused but the file could not be rewritten.</param>
    public int RevokeAll(out bool saved)
    {
        lock (_gate)
        {
            using var fileLock = AcquireFileLock();
            SyncFromDiskUnlocked();

            saved = true;
            var revoked = _tokens.Select(t => t.Id).ToList();
            if (revoked.Count == 0)
                return 0;

            _tokens.Clear();
            try
            {
                SaveUnlocked();
            }
            catch
            {
                _unsavedRevocations.UnionWith(revoked);
                saved = false;
            }

            return revoked.Count;
        }
    }

    /// <summary>What the settings page lists. Never the token, and never its hash.</summary>
    public IReadOnlyList<ApiTokenInfo> List()
    {
        lock (_gate)
        {
            SyncFromDiskUnlocked();
            var now = UtcNow();
            return _tokens.OrderBy(t => t.CreatedUtc).Select(t => Describe(t, now)).ToList();
        }
    }

    /// <summary>
    /// Decides one request. Every refusal looks the same from outside — unknown, wrong,
    /// expired and wrong-address all come back <see cref="ApiTokenOutcome.Rejected"/> — so
    /// the answer cannot be used to learn that a stolen token is real but pinned
    /// elsewhere. The reason is kept for the operator instead, on the token's own row.
    /// </summary>
    public ApiTokenVerdict Verify(string? presented, IPAddress? remote)
    {
        var candidate = (presented ?? "").Trim();
        // Hashed before the lookup, so a miss costs the same work as a hit.
        var candidateHash = HashToken(candidate);
        var id = ParseId(candidate);
        var from = Normalize(remote);

        lock (_gate)
        {
            SyncFromDiskUnlocked();

            var record = id == null ? null : _tokens.FirstOrDefault(t => t.Id == id);
            if (!CryptographicOperations.FixedTimeEquals(candidateHash, StoredHash(record)) || record == null)
                return ApiTokenVerdict.Rejected;

            var now = UtcNow();

            if (record.ExpiresUtc is { } expires && now >= expires)
                return Refuse(record, now, from, "the token has expired");

            if (!SourceAllowed(record.AllowedSources, from))
                return Refuse(record, now, from, "the address is not in the token's allowed sources");

            if (now - record.WindowStartUtc >= RateWindow)
            {
                record.WindowStartUtc = now;
                record.WindowCount = 0;
            }

            if (++record.WindowCount > RequestsPerMinute)
            {
                var wait = record.WindowStartUtc + RateWindow - now;
                return new ApiTokenVerdict(ApiTokenOutcome.RateLimited, null,
                    wait > TimeSpan.Zero ? wait : TimeSpan.FromSeconds(1),
                    // Once per window: a runaway loop must not also fill the audit log.
                    record.WindowCount == RequestsPerMinute + 1
                        ? $"token \"{record.Name}\" ({record.Id}) reached the rate limit"
                        : null);
            }

            record.LastUsedUtc = now;
            record.LastUsedFrom = from?.ToString();
            PersistIfStaleUnlocked(now);

            return new ApiTokenVerdict(ApiTokenOutcome.Accepted, Describe(record, now), TimeSpan.Zero);
        }
    }

    /// <summary>Records what a control token last did, for the token's row on the settings page.</summary>
    public void NoteAction(string id, string action)
    {
        lock (_gate)
        {
            SyncFromDiskUnlocked();
            var record = _tokens.FirstOrDefault(t => t.Id == id);
            if (record == null)
                return;

            var now = UtcNow();
            record.LastActionUtc = now;
            record.LastAction = action;
            PersistIfStaleUnlocked(now);
        }
    }

    /// <summary>
    /// Marks a live token that arrived over plain HTTP. The request is refused whatever
    /// this finds; the point is that the operator hears about it too. Telling only the
    /// caller leaves the one person who can revoke the token unaware it was on the wire.
    /// </summary>
    /// <returns>
    /// The token, the first time it is seen exposed. Null when what was sent is not one
    /// of ours — or is one already flagged: this path is reached before any throttle,
    /// so it must not be something a caller can make write a log line per request.
    /// </returns>
    public ApiTokenInfo? NoteExposure(string? presented, IPAddress? remote)
    {
        var candidate = (presented ?? "").Trim();
        var candidateHash = HashToken(candidate);
        var id = ParseId(candidate);

        lock (_gate)
        {
            SyncFromDiskUnlocked();

            var record = id == null ? null : _tokens.FirstOrDefault(t => t.Id == id);
            if (!CryptographicOperations.FixedTimeEquals(candidateHash, StoredHash(record)) || record == null)
                return null;

            if (record.ExposedUtc != null)
                return null;

            var now = UtcNow();
            record.ExposedUtc = now;
            record.ExposedFrom = Normalize(remote)?.ToString();
            // Written now, not on the bookkeeping schedule: this is the one note that
            // has to survive a restart, or the token goes back to looking safe.
            _lastPersistUtc = DateTime.MinValue;
            PersistIfStaleUnlocked(now);
            return Describe(record, now);
        }
    }

    private ApiTokenVerdict Refuse(TokenRecord record, DateTime now, IPAddress? from, string why)
    {
        record.LastRefusedUtc = now;
        record.LastRefusedFrom = from?.ToString();
        record.LastRefusedWhy = why;
        PersistIfStaleUnlocked(now);
        // The caller gets the bare refusal; the note is for the operator's audit log.
        return ApiTokenVerdict.Rejected with { Note = $"token \"{record.Name}\" ({record.Id}): {why}" };
    }

    private static ApiTokenInfo Describe(TokenRecord t, DateTime now) => new()
    {
        Id = t.Id,
        Name = t.Name,
        CreatedUtc = t.CreatedUtc,
        ExpiresUtc = t.ExpiresUtc,
        Expired = t.ExpiresUtc is { } expires && now >= expires,
        // Anything but the exact word reads as read-only, so a hand-edited file fails closed.
        CanControl = string.Equals(t.Access, AccessControl, StringComparison.Ordinal),
        AllowedSources = string.Join(", ", t.AllowedSources),
        LastUsedUtc = t.LastUsedUtc,
        LastUsedFrom = t.LastUsedFrom,
        LastRefusedUtc = t.LastRefusedUtc,
        LastRefusedFrom = t.LastRefusedFrom,
        LastRefusedWhy = t.LastRefusedWhy,
        LastActionUtc = t.LastActionUtc,
        LastAction = t.LastAction,
        ExposedUtc = t.ExposedUtc,
        ExposedFrom = t.ExposedFrom
    };

    private static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    /// <summary>All zeroes for a missing or damaged record — no SHA-256 output a caller can produce.</summary>
    private static byte[] StoredHash(TokenRecord? record)
    {
        if (record != null)
        {
            try
            {
                var hash = Convert.FromHexString(record.Hash);
                if (hash.Length == SHA256.HashSizeInBytes)
                    return hash;
            }
            catch
            {
                // A hand-edited file — treated as a token nobody holds.
            }
        }

        return new byte[SHA256.HashSizeInBytes];
    }

    /// <summary>
    /// The id is cut out by position rather than split on '_': the secret is base64url,
    /// which uses that character itself.
    /// </summary>
    private static string? ParseId(string token)
    {
        var secretStart = TokenPrefix.Length + IdLength + 1;
        if (token.Length <= secretStart ||
            !token.StartsWith(TokenPrefix, StringComparison.Ordinal) ||
            token[secretStart - 1] != '_')
            return null;

        return token.Substring(TokenPrefix.Length, IdLength);
    }

    /// <summary>One spelling per address: dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d.</summary>
    private static IPAddress? Normalize(IPAddress? address)
    {
        if (address == null)
            return null;
        if (address.IsIPv4MappedToIPv6)
            return address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            return new IPAddress(address.GetAddressBytes());
        return address;
    }

    /// <summary>An empty list allows any source; a caller whose address is unknown matches nothing.</summary>
    internal static bool SourceAllowed(IReadOnlyList<string> allowed, IPAddress? remote)
    {
        if (allowed.Count == 0)
            return true;

        remote = Normalize(remote);
        if (remote == null)
            return false;

        foreach (var entry in allowed)
        {
            var slash = entry.IndexOf('/');
            if (!IPAddress.TryParse(slash < 0 ? entry : entry[..slash], out var network))
                continue;

            var bits = network.GetAddressBytes().Length * 8;
            var prefix = bits;
            if (slash >= 0 && (!int.TryParse(entry[(slash + 1)..], out prefix) || prefix < 0 || prefix > bits))
                continue;

            if (InNetwork(remote, Normalize(network)!, prefix))
                return true;
        }

        return false;
    }

    private static bool InNetwork(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily != network.AddressFamily)
            return false;

        var addr = address.GetAddressBytes();
        var net = network.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainderBits = prefix % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (addr[i] != net[i])
                return false;
        }

        if (remainderBits == 0)
            return true;

        var mask = 0xFF << (8 - remainderBits);
        return (addr[fullBytes] & mask) == (net[fullBytes] & mask);
    }

    private void Load()
    {
        _tokens = ReadFile();
        _diskStamp = ReadStamp();
    }

    private List<TokenRecord> ReadFile()
    {
        try
        {
            var path = StorePath;
            if (!File.Exists(path))
                return new List<TokenRecord>();

            var file = JsonSerializer.Deserialize<TokenFile>(File.ReadAllText(path), JsonOptions);
            if (file?.Tokens != null)
                return file.Tokens.Where(t => t.Id.Length == IdLength && t.Hash.Length > 0).ToList();
        }
        catch
        {
            // Unreadable means no token is valid: a damaged file must fail closed.
        }

        return new List<TokenRecord>();
    }

    private (bool, DateTime, long) ReadStamp()
    {
        try
        {
            var info = new FileInfo(StorePath);
            return info.Exists ? (true, info.LastWriteTimeUtc, info.Length) : default;
        }
        catch
        {
            return default;
        }
    }

    /// <summary>
    /// Takes the file as the truth whenever it has changed underneath this process.
    ///
    /// The list in memory is only a copy of it. Left alone, a token revoked by another
    /// console on the same data directory — or by an operator deleting the file in a
    /// hurry — stayed valid here until a restart, and the next last-used write then put
    /// this process's whole stale list back on disk, un-revoking it for everyone. So
    /// this runs before every decision and every write: a revocation made anywhere is
    /// seen by the next request, and nothing saved from here can resurrect one.
    /// </summary>
    private void SyncFromDiskUnlocked()
    {
        var stamp = ReadStamp();
        if (stamp == _diskStamp)
            return;

        var previous = _tokens;
        _tokens = ReadFile();
        _diskStamp = stamp;
        if (_unsavedRevocations.Count > 0)
            _tokens.RemoveAll(t => _unsavedRevocations.Contains(t.Id));

        // Rate windows and bookkeeping not yet written carry over — but only onto the
        // same credential. An id that came back with a different hash is another token.
        foreach (var record in _tokens)
        {
            var old = previous.FirstOrDefault(t => t.Id == record.Id && t.Hash == record.Hash);
            if (old == null)
                continue;

            record.WindowStartUtc = old.WindowStartUtc;
            record.WindowCount = old.WindowCount;
            if (old.LastUsedUtc > (record.LastUsedUtc ?? DateTime.MinValue))
                (record.LastUsedUtc, record.LastUsedFrom) = (old.LastUsedUtc, old.LastUsedFrom);
            if (old.LastRefusedUtc > (record.LastRefusedUtc ?? DateTime.MinValue))
                (record.LastRefusedUtc, record.LastRefusedFrom, record.LastRefusedWhy) =
                    (old.LastRefusedUtc, old.LastRefusedFrom, old.LastRefusedWhy);
            if (old.LastActionUtc > (record.LastActionUtc ?? DateTime.MinValue))
                (record.LastActionUtc, record.LastAction) = (old.LastActionUtc, old.LastAction);
            if (old.ExposedUtc != null && record.ExposedUtc == null)
                (record.ExposedUtc, record.ExposedFrom) = (old.ExposedUtc, old.ExposedFrom);
        }
    }

    /// <summary>
    /// Held across every read-modify-write of the file. Re-reading before a write makes
    /// one process see another's changes, but not the one that lands between that read
    /// and the write — where a bookkeeping save here could still overwrite a revocation
    /// made there a moment earlier. Two consoles on one data directory take turns.
    /// </summary>
    /// <returns>
    /// Null when the lock cannot be had — a read-only directory, or a holder that never
    /// lets go. The caller goes ahead regardless: a revocation written without the lock
    /// is better than one not written.
    /// </returns>
    private FileStream? AcquireFileLock()
    {
        var path = Path.Combine(_dataDirectory, FileName + ".lock");
        for (var attempt = 0; attempt < 40; attempt++)
        {
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.OpenOrCreate,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.None
                };
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                return new FileStream(path, options);
            }
            catch (IOException)
            {
                Thread.Sleep(25);
            }
            catch
            {
                return null;
            }
        }

        return null;
    }

    private void PersistIfStaleUnlocked(DateTime now)
    {
        // A revocation waiting to reach the disk is retried far sooner than bookkeeping
        // is written, but not on every request while the disk stays broken.
        var due = _unsavedRevocations.Count > 0
            ? now - _lastSaveAttemptUtc >= SaveRetryInterval
            : now - _lastPersistUtc >= UsePersistInterval;
        if (!due)
            return;

        _lastSaveAttemptUtc = now;
        try
        {
            using var fileLock = AcquireFileLock();
            // Whatever another process wrote since this request began is taken first,
            // so this write adds bookkeeping to the current list instead of replacing it.
            SyncFromDiskUnlocked();
            SaveUnlocked();
        }
        catch
        {
            // Bookkeeping only — a full disk must not turn a valid poll into an error.
            _lastPersistUtc = now;
        }
    }

    private void SaveUnlocked()
    {
        Directory.CreateDirectory(_dataDirectory);
        AppPaths.WriteAtomic(
            StorePath,
            JsonSerializer.Serialize(new TokenFile { Tokens = _tokens }, JsonOptions),
            UnixFileMode.UserRead | UnixFileMode.UserWrite);
        _lastPersistUtc = UtcNow();
        _diskStamp = ReadStamp();
        _unsavedRevocations.Clear();
    }

    private sealed class TokenFile
    {
        public int Version { get; set; } = 1;
        public List<TokenRecord> Tokens { get; set; } = new();
    }

    private sealed class TokenRecord
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Hash { get; set; } = "";
        public DateTime CreatedUtc { get; set; }
        public DateTime? ExpiresUtc { get; set; }
        public List<string> AllowedSources { get; set; } = new();

        /// <summary>Read-only unless it says otherwise — which is also what a file from before this field means.</summary>
        public string Access { get; set; } = AccessRead;
        public DateTime? LastUsedUtc { get; set; }
        public string? LastUsedFrom { get; set; }
        public DateTime? LastRefusedUtc { get; set; }
        public string? LastRefusedFrom { get; set; }
        public string? LastRefusedWhy { get; set; }
        public DateTime? LastActionUtc { get; set; }
        public string? LastAction { get; set; }

        /// <summary>When it was first seen on plain HTTP. Never cleared — only revoking answers it.</summary>
        public DateTime? ExposedUtc { get; set; }
        public string? ExposedFrom { get; set; }

        [JsonIgnore] public DateTime WindowStartUtc { get; set; }
        [JsonIgnore] public int WindowCount { get; set; }
    }
}

public enum ApiTokenOutcome
{
    Rejected,
    RateLimited,
    Accepted
}

/// <param name="Note">For the operator's audit log only — never sent to the caller.</param>
public readonly record struct ApiTokenVerdict(ApiTokenOutcome Outcome, ApiTokenInfo? Token, TimeSpan RetryAfter,
    string? Note = null)
{
    public static readonly ApiTokenVerdict Rejected = new(ApiTokenOutcome.Rejected, null, TimeSpan.Zero);
}

public sealed class ApiTokenInfo
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public DateTime CreatedUtc { get; init; }
    public DateTime? ExpiresUtc { get; init; }
    public bool Expired { get; init; }
    public bool CanControl { get; init; }
    public string AllowedSources { get; init; } = "";
    public DateTime? LastUsedUtc { get; init; }
    public string? LastUsedFrom { get; init; }
    public DateTime? LastRefusedUtc { get; init; }
    public string? LastRefusedFrom { get; init; }
    public string? LastRefusedWhy { get; init; }
    public DateTime? LastActionUtc { get; init; }
    public string? LastAction { get; init; }
    public DateTime? ExposedUtc { get; init; }
    public string? ExposedFrom { get; init; }
}
