using System.Runtime.CompilerServices;
using NetworkSentinel.Services;

namespace NetworkSentinel.Tests;

/// <summary>
/// Points AppPaths at a throwaway directory before any test touches it, so services
/// that persist state (settings, suppressions, the allowlist seed file) never write
/// into the real %ProgramData% installation.
/// </summary>
internal static class TestEnv
{
    [ModuleInitializer]
    internal static void Init()
    {
        var dir = Path.Combine(Path.GetTempPath(), "networksentinel-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        AppPaths.DataDirectoryOverride = dir;
    }

    /// <summary>
    /// A repo-relative file's absolute path, or null when the suite is running from
    /// somewhere the source tree is not reachable (a published test bundle). Callers
    /// skip rather than fail on null: a test that asserts on a shipped file is worth
    /// having where the file is there, and is not a reason to fail where it is not.
    /// </summary>
    internal static string? RepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }
}
