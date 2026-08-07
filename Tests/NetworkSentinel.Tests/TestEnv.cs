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
}
