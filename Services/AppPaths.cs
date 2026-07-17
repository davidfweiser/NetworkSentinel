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
}
