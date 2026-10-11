using NetworkSentinel.Services;

namespace NetworkSentinel.Web;

/// <summary>
/// One line for every security-relevant thing an API token did or had done to it:
/// minted, revoked, refused, locked out, sent in the clear, and each control action.
///
/// The journal gets the same line, and for the systemd service that would be enough.
/// The file is for every other way this console is started — from a terminal, its
/// output goes with the terminal — and for the question that is asked days later:
/// which token removed that rule, and from where.
/// </summary>
public sealed class ApiAuditLog
{
    /// <summary>The file is rotated once past this, keeping one previous generation.</summary>
    public const long MaxBytes = 1024 * 1024;

    private const int MaxEntryLength = 600;

    private readonly object _gate = new();
    private readonly string _directory;
    private readonly bool _echo;

    public ApiAuditLog() : this(Path.Combine(AppPaths.DataDirectory, "logs"))
    {
    }

    /// <param name="echo">Also write each entry to stdout, which is the journal under systemd.</param>
    public ApiAuditLog(string directory, bool echo = true)
    {
        _directory = directory;
        _echo = echo;
    }

    public string FilePath => Path.Combine(_directory, "api-audit.log");

    public void Write(string entry)
    {
        var line = SingleLine(entry, MaxEntryLength);
        if (_echo)
            Console.WriteLine($"Token API: {line}");

        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(_directory);
                var path = FilePath;

                var info = new FileInfo(path);
                if (info.Exists && info.Length > MaxBytes)
                    File.Move(path, path + ".1", overwrite: true);

                var options = new FileStreamOptions
                {
                    Mode = FileMode.Append,
                    Access = FileAccess.Write,
                    Share = FileShare.Read
                };
                // Names tokens, callers and rules: owner-only from the moment it exists.
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

                using var stream = new FileStream(path, options);
                using var writer = new StreamWriter(stream);
                writer.WriteLine($"{DateTime.UtcNow:o} {line}");
            }
        }
        catch
        {
            // The request this describes has already been decided. A full disk must not
            // turn a refusal into an error page, or an allowed action into a failed one.
        }
    }

    /// <summary>
    /// Caller-supplied text on its way into a log: one line, bounded, no control
    /// characters — so a crafted action name cannot forge an entry of its own.
    /// </summary>
    public static string SingleLine(string? text, int max)
    {
        var flat = new string((text ?? "").Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();
        return flat.Length <= max ? flat : flat[..max] + "…";
    }
}
