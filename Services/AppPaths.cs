using System.IO;

namespace NetworkSentinel.Services;

/// <summary>
/// App data directory for settings, allowlist, web master password, and logs.
/// Windows: %LocalAppData%\NetworkSentinel
/// </summary>
public static class AppPaths
{
    public static string DataDirectory
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetworkSentinel");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}
