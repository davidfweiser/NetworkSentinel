using System.Runtime.CompilerServices;

namespace NetworkSentinel.Tests;

/// <summary>
/// Points XDG_DATA_HOME at a throwaway directory before any test touches
/// AppPaths, so services that persist state (settings, suppressions, the
/// allowlist seed file) never write into the real user profile.
/// </summary>
internal static class TestEnv
{
    [ModuleInitializer]
    internal static void Init()
    {
        var dir = Path.Combine(Path.GetTempPath(), "networksentinel-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        Environment.SetEnvironmentVariable("XDG_DATA_HOME", dir);
    }
}
