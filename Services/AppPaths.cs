using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace NetworkSentinel.Services;

/// <summary>
/// App data directory for settings, allowlist, web master password, and logs.
///
/// Machine-wide: %ProgramData%\NetworkSentinel — shared by the desktop GUI (your user),
/// the TUI, and the headless web service (which runs as SYSTEM). A per-user folder here
/// caused split-brain state: rules the GUI unblocked were re-blocked by the web service
/// because each context had its own settings/suppress list.
///
/// Falls back to %LocalAppData%\NetworkSentinel if ProgramData is not writable.
/// </summary>
public static class AppPaths
{
    private static string? _resolved;
    private static readonly object Gate = new();

    public static string DataDirectory
    {
        get
        {
            if (_resolved != null)
                return _resolved;

            lock (Gate)
            {
                _resolved ??= ResolveDataDirectory();
                return _resolved;
            }
        }
    }

    private static string ResolveDataDirectory()
    {
        var machineWide = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "NetworkSentinel");
        var perUser = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetworkSentinel");

        if (TryPrepareDirectory(machineWide))
        {
            TryGrantUsersModify(machineWide);
            MigrateLegacyFiles(perUser, machineWide);
            return machineWide;
        }

        Directory.CreateDirectory(perUser);
        return perUser;
    }

    private static bool TryPrepareDirectory(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, $".write-test-{Environment.ProcessId}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Best-effort: let non-elevated users update files SYSTEM/admin created (and vice versa),
    /// so all app contexts share one settings/suppress/allowlist state.
    /// </summary>
    private static void TryGrantUsersModify(string dir)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            var info = new DirectoryInfo(dir);
            var security = info.GetAccessControl();
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        catch
        {
            // Not elevated / not permitted — reads still work; writes fall back per-file.
        }
    }

    /// <summary>Copy files from the old per-user folder that don't exist machine-wide yet.</summary>
    private static void MigrateLegacyFiles(string legacyDir, string targetDir)
    {
        try
        {
            if (!Directory.Exists(legacyDir))
                return;

            foreach (var source in Directory.EnumerateFiles(legacyDir))
            {
                var target = Path.Combine(targetDir, Path.GetFileName(source));
                if (!File.Exists(target))
                    File.Copy(source, target);
            }
        }
        catch
        {
            // best-effort — fresh defaults are acceptable
        }
    }
}
