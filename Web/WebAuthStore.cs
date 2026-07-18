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
    private AuthFile? _auth;

    public WebAuthStore()
    {
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

    private static string AuthPath => Path.Combine(AppPaths.DataDirectory, "web-master.json");

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
        Directory.CreateDirectory(AppPaths.DataDirectory);
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
    }
}
