namespace NetworkSentinel.Services;

/// <summary>XDG-friendly data directory for settings, allowlist, logs.</summary>
public static class AppPaths
{
    public static string DataDirectory
    {
        get
        {
            // Prefer XDG_DATA_HOME, then ~/.local/share, then LocalApplicationData.
            var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
            string baseDir;
            if (!string.IsNullOrWhiteSpace(xdg))
            {
                baseDir = xdg;
            }
            else
            {
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (!string.IsNullOrWhiteSpace(home))
                    baseDir = Path.Combine(home, ".local", "share");
                else
                    baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            }

            var dir = Path.Combine(baseDir, "NetworkSentinel");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>
    /// Writes a file via a temp sibling + rename, so a crash mid-write can never leave
    /// a truncated file. That matters here because every JSON store in the app treats
    /// an unparsable file as empty — a torn settings.json or firewall ledger silently
    /// discarded real state (for the ledger: while the kernel rules lived on as
    /// orphans). The rename is atomic on the same filesystem, which a sibling path
    /// guarantees.
    /// </summary>
    /// <param name="unixMode">
    /// Optional owner-only style permissions, applied at creation so the bytes are
    /// never on disk under the default umask — not even in the temp file, which is
    /// what actually holds them. settings.json carries the TLS key password and the
    /// webhook URL, and a kill between write and chmod used to leave those readable
    /// by every local user.
    /// </param>
    public static void WriteAtomic(string path, string contents, UnixFileMode? unixMode = null)
    {
        // Unique per write. A fixed "<path>.tmp" is shared by every concurrent writer
        // of the same store — the firewall ledger has three (expiry sweep, startup
        // reconcile, auto-block) — so one writer published another's bytes, or lost
        // the race and threw into a swallowing catch, dropping a just-created block.
        var tmp = $"{path}.{Environment.ProcessId}.{Interlocked.Increment(ref _tmpSequence)}.tmp";

        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None
            };
            if (unixMode.HasValue && !OperatingSystem.IsWindows())
                options.UnixCreateMode = unixMode.Value;

            using (var stream = new FileStream(tmp, options))
            using (var writer = new StreamWriter(stream))
                writer.Write(contents);

            // Rename keeps the inode, so the mode set at creation carries over.
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* nothing useful to do */ }
            throw;
        }
    }

    private static int _tmpSequence;
}
