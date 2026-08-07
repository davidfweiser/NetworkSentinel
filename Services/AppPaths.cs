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

    /// <summary>
    /// Test-only redirect for the data directory, set before anything reads it.
    /// The POSIX build gets this for free by honouring XDG_DATA_HOME; Windows resolves
    /// %ProgramData% through the shell, which no environment variable overrides, so
    /// without a seam the suite would persist settings and allowlists over the real
    /// installation's. Deliberately <c>internal</c>: an environment-variable override
    /// would let anything that can set one relocate the state of a service running as
    /// SYSTEM.
    /// </summary>
    internal static string? DataDirectoryOverride { get; set; }

    public static string DataDirectory
    {
        get
        {
            if (DataDirectoryOverride is { } overridden)
            {
                Directory.CreateDirectory(overridden);
                return overridden;
            }

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

    /// <summary>
    /// Writes a file via a temp sibling + rename, so a crash mid-write can never leave
    /// a truncated file. That matters here because every JSON store in the app treats
    /// an unparsable file as empty — a torn settings.json or firewall ledger silently
    /// discarded real state (for the ledger: while the firewall rules lived on as
    /// orphans). The rename is atomic on the same volume, which a sibling path
    /// guarantees.
    /// </summary>
    /// <param name="unixMode">
    /// Owner-only style permissions for the sibling repo's POSIX build. Ignored on
    /// Windows, where access to these files is governed by the inherited ACL on the
    /// data directory instead (see <see cref="TryGrantUsersModify"/>); the parameter
    /// exists so shared callers compile unchanged on both platforms.
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

            ReplaceWithRetry(tmp, path);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* nothing useful to do */ }
            throw;
        }
    }

    /// <summary>
    /// Publishes the temp file over the target, retrying the transient failures
    /// Windows produces here.
    ///
    /// POSIX <c>rename(2)</c> over an existing file always succeeds, so the sibling
    /// build can move once and be done. The Windows equivalent fails with a sharing
    /// violation when another writer is replacing the same target at that instant, or
    /// when a scanner/indexer has it open for a moment — and this app really does have
    /// concurrent writers (the expiry sweep, the startup reconcile and auto-block all
    /// write the ledger; each frontend saves settings). Without the retry, most writers
    /// in a burst threw into a caller that swallows exceptions, silently dropping the
    /// state they meant to persist.
    ///
    /// Last writer still wins, exactly as before — this only stops a losing racer from
    /// failing outright.
    /// </summary>
    private static void ReplaceWithRetry(string tmp, string path)
    {
        const int attempts = 12;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(tmp, path, overwrite: true);
                return;
            }
            catch (Exception ex) when (attempt < attempts &&
                                       (ex is IOException || ex is UnauthorizedAccessException))
            {
                Thread.Sleep(15);
            }
        }
    }

    private static int _tmpSequence;

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
