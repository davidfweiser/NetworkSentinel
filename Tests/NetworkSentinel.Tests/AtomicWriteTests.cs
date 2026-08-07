using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class AtomicWriteTests
{
    private static string TempTarget([System.Runtime.CompilerServices.CallerMemberName] string name = "")
        => Path.Combine(AppPaths.DataDirectory, $"atomic-{name}-{Guid.NewGuid():N}.json");

    /// <summary>
    /// Temp siblings of <paramref name="path"/>, excluding the target. Enumerated
    /// rather than globbed: a "name.*" pattern also matches the extensionless form,
    /// so it would count the target itself.
    /// </summary>
    private static string[] LeftoverTempFiles(string path)
        => Directory.GetFiles(AppPaths.DataDirectory)
            .Where(f => f.StartsWith(path + ".", StringComparison.Ordinal))
            .ToArray();

    [Fact]
    public void WritesContentAndLeavesNoTempBehind()
    {
        var path = TempTarget();
        AppPaths.WriteAtomic(path, "{\"a\":1}");

        Assert.Equal("{\"a\":1}", File.ReadAllText(path));
        Assert.Empty(LeftoverTempFiles(path));
    }

    [Fact]
    public void SecretsAreOwnerOnlyFromCreation()
    {
        if (OperatingSystem.IsWindows()) return;

        var path = TempTarget();
        AppPaths.WriteAtomic(path, "pfx-password", UnixFileMode.UserRead | UnixFileMode.UserWrite);

        // The rename preserves the mode the temp file was created with, so the bytes
        // are never on disk group/world-readable — not even under the temp name.
        var mode = File.GetUnixFileMode(path);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }

    [Fact]
    public void ConcurrentWritersDoNotClobberEachOther()
    {
        var path = TempTarget();
        var failures = 0;

        // A fixed "<path>.tmp" made these collide: one writer published the other's
        // bytes, or lost the File.Move and threw.
        Parallel.For(0, 24, i =>
        {
            try
            {
                AppPaths.WriteAtomic(path, $"{{\"writer\":{i}}}");
            }
            catch
            {
                Interlocked.Increment(ref failures);
            }
        });

        Assert.Equal(0, failures);
        Assert.StartsWith("{\"writer\":", File.ReadAllText(path));
        Assert.Empty(LeftoverTempFiles(path));
    }
}
