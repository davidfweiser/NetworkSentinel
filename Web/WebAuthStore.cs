using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetworkSentinel.Services;

namespace NetworkSentinel.Web;

/// <summary>
/// Master password + session tokens for the headless web UI.
/// Password is stored as PBKDF2-SHA256; sessions live only in process memory.
/// </summary>
public sealed class WebAuthStore
{
    public const string CookieName = "ns_session";
    public const int MinPasswordLength = 8;
    private const int SaltSize = 32;
    private const int KeySize = 32;
    private const int Iterations = 200_000;
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(12);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly object _fileGate = new();
    private readonly ConcurrentDictionary<string, DateTime> _sessions = new(StringComparer.Ordinal);
    private readonly string _dataDirectory;
    private AuthFile? _auth;

    public WebAuthStore() : this(AppPaths.DataDirectory)
    {
    }

    /// <summary>Used by `--set-master-password` to target a specific user's data directory instead of the current process's own.</summary>
    public WebAuthStore(string dataDirectory)
    {
        _dataDirectory = dataDirectory;
        Load();
    }

    public bool IsConfigured
    {
        get
        {
            lock (_fileGate)
                return _auth != null && !string.IsNullOrEmpty(_auth.Hash) && !string.IsNullOrEmpty(_auth.Salt);
        }
    }

    private string AuthPath => Path.Combine(_dataDirectory, "web-master.json");

    public bool TrySetup(string password, string confirm, out string message)
    {
        if (IsConfigured)
        {
            message = "Master password is already set. Use login.";
            return false;
        }

        if (!ValidateNewPassword(password, confirm, out message))
            return false;

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = HashPassword(password, salt, Iterations);

        lock (_fileGate)
        {
            if (_auth != null)
            {
                message = "Master password is already set. Use login.";
                return false;
            }

            _auth = new AuthFile
            {
                Version = 1,
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash),
                Iterations = Iterations,
                CreatedUtc = DateTime.UtcNow
            };
            SaveUnlocked();
        }

        message = "Master password created. You are signed in.";
        return true;
    }

    /// <summary>
    /// Force-set the master password from a trusted local context (CLI), bypassing the
    /// "already configured" guard the browser setup flow uses. Used by
    /// `--set-master-password` when the web UI isn't reachable to set it there.
    /// </summary>
    public bool SetPassword(string password, string confirm, out string message)
    {
        if (!ValidateNewPassword(password, confirm, out message))
            return false;

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = HashPassword(password, salt, Iterations);

        lock (_fileGate)
        {
            var createdUtc = _auth?.CreatedUtc ?? DateTime.UtcNow;
            _auth = new AuthFile
            {
                Version = 1,
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash),
                Iterations = Iterations,
                CreatedUtc = createdUtc,
                ChangedUtc = DateTime.UtcNow
            };
            SaveUnlocked();
        }

        _sessions.Clear();
        message = "Master password set.";
        return true;
    }

    public bool VerifyPassword(string password)
    {
        AuthFile? auth;
        lock (_fileGate)
            auth = _auth;

        if (auth == null || string.IsNullOrEmpty(auth.Hash) || string.IsNullOrEmpty(auth.Salt))
            return false;

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(auth.Salt);
            expected = Convert.FromBase64String(auth.Hash);
        }
        catch
        {
            return false;
        }

        var iterations = auth.Iterations > 0 ? auth.Iterations : Iterations;
        var actual = HashPassword(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Replace the master password after verifying the current one.
    /// Stores only a new PBKDF2-SHA256 hash + random salt (never plaintext).
    /// Other sessions are revoked so only the caller's session remains valid.
    /// </summary>
    public bool TryChangePassword(string currentPassword, string newPassword, string confirm, string? keepSessionToken, out string message)
    {
        if (!IsConfigured)
        {
            message = "Master password is not set yet.";
            return false;
        }

        if (!VerifyPassword(currentPassword))
        {
            message = "Current master password is incorrect.";
            return false;
        }

        if (!ValidateNewPassword(newPassword, confirm, out message))
            return false;

        if (string.Equals(currentPassword, newPassword, StringComparison.Ordinal))
        {
            message = "New password must be different from the current password.";
            return false;
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = HashPassword(newPassword, salt, Iterations);

        lock (_fileGate)
        {
            if (_auth == null)
            {
                message = "Master password is not set yet.";
                return false;
            }

            _auth = new AuthFile
            {
                Version = 1,
                Salt = Convert.ToBase64String(salt),
                Hash = Convert.ToBase64String(hash),
                Iterations = Iterations,
                CreatedUtc = _auth.CreatedUtc,
                ChangedUtc = DateTime.UtcNow
            };
            SaveUnlocked();
        }

        // Invalidate other browser sessions after a password change.
        foreach (var key in _sessions.Keys)
        {
            if (!string.Equals(key, keepSessionToken, StringComparison.Ordinal))
                _sessions.TryRemove(key, out _);
        }

        message = "Master password updated.";
        return true;
    }

    public string CreateSession()
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        _sessions[token] = DateTime.UtcNow + SessionLifetime;
        return token;
    }

    public bool IsSessionValid(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        if (!_sessions.TryGetValue(token, out var expires))
            return false;

        if (DateTime.UtcNow > expires)
        {
            _sessions.TryRemove(token, out _);
            return false;
        }

        // Sliding expiry while the tab is in use.
        _sessions[token] = DateTime.UtcNow + SessionLifetime;
        return true;
    }

    public void RevokeSession(string? token)
    {
        if (!string.IsNullOrWhiteSpace(token))
            _sessions.TryRemove(token, out _);
    }

    public static bool ValidateNewPassword(string password, string confirm, out string message)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
        {
            message = $"Password must be at least {MinPasswordLength} characters.";
            return false;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            message = "Passwords do not match.";
            return false;
        }

        message = "";
        return true;
    }

    private static byte[] HashPassword(string password, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            KeySize);
    }

    private void Load()
    {
        try
        {
            var path = AuthPath;
            if (!File.Exists(path))
                return;

            var json = File.ReadAllText(path);
            var file = JsonSerializer.Deserialize<AuthFile>(json, JsonOptions);
            if (file != null && !string.IsNullOrEmpty(file.Hash) && !string.IsNullOrEmpty(file.Salt))
                _auth = file;
        }
        catch
        {
            _auth = null;
        }
    }

    private void SaveUnlocked()
    {
        Directory.CreateDirectory(_dataDirectory);
        var path = AuthPath;
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_auth, JsonOptions));
        try
        {
            // Owner read/write only when the OS supports it (Linux).
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // best-effort
        }

        File.Move(tmp, path, overwrite: true);
        try
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch
        {
            // best-effort
        }
    }

    private sealed class AuthFile
    {
        public int Version { get; set; } = 1;
        public string Salt { get; set; } = "";
        public string Hash { get; set; } = "";
        public int Iterations { get; set; } = 200_000;
        public DateTime CreatedUtc { get; set; }
        public DateTime? ChangedUtc { get; set; }
    }
}
