namespace NetworkSentinel.Services;

/// <summary>
/// Per-client-IP lockout for the web console's password endpoints.
/// A fixed delay on a wrong password only slows one connection at a time — a remote
/// attacker can run hundreds in parallel. This caps total attempts per source instead.
/// </summary>
public sealed class LoginThrottle
{
    /// <summary>Failures allowed before the first lockout.</summary>
    public const int MaxFailures = 5;

    /// <summary>Failures older than this stop counting.</summary>
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(15);

    /// <summary>Lockout doubles with each further failure, up to this.</summary>
    private static readonly TimeSpan MaxLockout = TimeSpan.FromHours(1);

    private static readonly TimeSpan FirstLockout = TimeSpan.FromMinutes(1);

    private const int MaxTrackedClients = 4096;

    private sealed class Entry
    {
        public int Failures;
        public DateTime LastFailureUtc;
        public DateTime LockedUntilUtc;
    }

    private readonly Dictionary<string, Entry> _clients = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>True while <paramref name="client"/> is locked out; <paramref name="retryAfter"/> is the wait left.</summary>
    public bool IsLocked(string client, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        var key = Key(client);

        lock (_gate)
        {
            if (!_clients.TryGetValue(key, out var entry))
                return false;

            var now = DateTime.UtcNow;
            if (entry.LockedUntilUtc > now)
            {
                retryAfter = entry.LockedUntilUtc - now;
                return true;
            }

            // Window expired with no further failures — forget this client.
            if (now - entry.LastFailureUtc > FailureWindow)
                _clients.Remove(key);

            return false;
        }
    }

    /// <summary>Record a wrong password. Returns the lockout now in force (zero if still under the limit).</summary>
    public TimeSpan RecordFailure(string client)
    {
        var key = Key(client);
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            Prune(now);

            if (!_clients.TryGetValue(key, out var entry))
            {
                entry = new Entry();
                _clients[key] = entry;
            }

            if (now - entry.LastFailureUtc > FailureWindow)
                entry.Failures = 0;

            entry.Failures++;
            entry.LastFailureUtc = now;

            if (entry.Failures < MaxFailures)
                return TimeSpan.Zero;

            var steps = entry.Failures - MaxFailures;
            var lockout = TimeSpan.FromTicks(Math.Min(
                FirstLockout.Ticks * (long)Math.Pow(2, Math.Min(steps, 8)),
                MaxLockout.Ticks));
            entry.LockedUntilUtc = now + lockout;
            return lockout;
        }
    }

    /// <summary>Clear the failure history for a client after a successful sign-in.</summary>
    public void RecordSuccess(string client)
    {
        lock (_gate)
        {
            _clients.Remove(Key(client));
        }
    }

    public static string Describe(TimeSpan retryAfter)
    {
        var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
        if (seconds < 90)
            return $"{seconds} second{(seconds == 1 ? "" : "s")}";
        var minutes = (int)Math.Ceiling(retryAfter.TotalMinutes);
        return $"{minutes} minute{(minutes == 1 ? "" : "s")}";
    }

    private static string Key(string? client)
        => string.IsNullOrWhiteSpace(client) ? "unknown" : client.Trim();

    /// <summary>Bound memory so a spray from many source addresses cannot grow the table without limit.</summary>
    private void Prune(DateTime now)
    {
        if (_clients.Count < MaxTrackedClients)
            return;

        var stale = _clients
            .Where(kv => kv.Value.LockedUntilUtc <= now && now - kv.Value.LastFailureUtc > FailureWindow)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in stale)
            _clients.Remove(key);

        // Still full of live entries: drop the oldest so new clients can still be tracked.
        if (_clients.Count >= MaxTrackedClients)
        {
            foreach (var key in _clients.OrderBy(kv => kv.Value.LastFailureUtc)
                         .Take(_clients.Count - MaxTrackedClients + 1)
                         .Select(kv => kv.Key)
                         .ToList())
                _clients.Remove(key);
        }
    }
}
