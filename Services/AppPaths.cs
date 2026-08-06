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
    /// Optional owner-only style permissions, applied to the temp file before the
    /// rename so the target never exists with looser permissions.
    /// </param>
    public static void WriteAtomic(string path, string contents, UnixFileMode? unixMode = null)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, contents);
        if (unixMode.HasValue && !OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, unixMode.Value);
        File.Move(tmp, path, overwrite: true);
    }
}
