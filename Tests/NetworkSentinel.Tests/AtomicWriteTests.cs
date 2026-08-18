using System.Collections.Concurrent;
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
    public void UnixModeIsAcceptedAndIgnoredOnWindows()
    {
        // The parameter exists so shared callers (AppSettings.Save) compile unchanged
        // against both builds; here it must simply not disturb the write. File
        // permissions on this platform come from the data directory's inherited ACL.
        var path = TempTarget();
        AppPaths.WriteAtomic(path, "pfx-password", UnixFileMode.UserRead | UnixFileMode.UserWrite);

        Assert.Equal("pfx-password", File.ReadAllText(path));
        Assert.Empty(LeftoverTempFiles(path));
    }

    [Fact]
    public void ConcurrentWritersDoNotClobberEachOther()
    {
        var path = TempTarget();

        // The failures are collected rather than counted: "expected 0, actual 2" says
        // nothing about which of publish, replace or cleanup gave way, and this test
        // guards a path whose whole job is to swallow nothing silently.
        var failures = new ConcurrentBag<string>();

        // A fixed "<path>.tmp" made these collide: one writer published the other's
        // bytes, or lost the File.Move and threw.
        //
        // Dedicated threads released together, not Parallel.For: the pool ramps up
        // gradually, so how much contention the writers actually saw came down to
        // scheduling. Against the flat 15 ms × 12 backoff this was written for, that
        // made the test a coin flip — it neither reliably caught the bug nor reliably
        // passed once the bug was gone. Parking every writer on one gate and opening
        // it makes the collision the point of the test rather than a hope.
        const int writers = 32;
        using var ready = new CountdownEvent(writers);
        using var go = new ManualResetEventSlim(false);
        var threads = new List<Thread>(writers);

        for (var i = 0; i < writers; i++)
        {
            var writer = i;
            var thread = new Thread(() =>
            {
                ready.Signal();
                go.Wait();
                try
                {
                    AppPaths.WriteAtomic(path, $"{{\"writer\":{writer}}}");
                }
                catch (Exception ex)
                {
                    failures.Add($"{ex.GetType().Name}: {ex.Message}");
                }
            })
            { IsBackground = true };

            threads.Add(thread);
            thread.Start();
        }

        ready.Wait();                       // every writer is parked on the gate
        go.Set();                           // and now they all go at once
        foreach (var thread in threads)
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "a writer never finished");

        Assert.True(failures.IsEmpty,
            $"{failures.Count} of {writers} writers threw:{Environment.NewLine}" +
            string.Join(Environment.NewLine, failures.Distinct()));
        Assert.StartsWith("{\"writer\":", File.ReadAllText(path));
        Assert.Empty(LeftoverTempFiles(path));
    }

    [Fact]
    public void APermanentlyHeldTargetFailsInsteadOfHanging()
    {
        // The retry is bounded by a deadline rather than an attempt count, so the one
        // thing that has to be pinned is that the deadline is really reached: a file
        // another process holds open for good must make the write throw, not wedge the
        // background loop that called it.
        var path = TempTarget();
        File.WriteAllText(path, "{\"held\":true}");

        // FileShare.None is what a scanner or another writer looks like at the instant
        // MoveFileEx tries to replace the target.
        using var hold = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var started = System.Diagnostics.Stopwatch.StartNew();
        Assert.ThrowsAny<Exception>(() => AppPaths.WriteAtomic(path, "{\"new\":true}"));
        started.Stop();

        // Bounded, and not by luck: comfortably longer than the old 165 ms budget and
        // comfortably shorter than a caller that never returns.
        Assert.InRange(started.Elapsed.TotalSeconds, 0.5, 20);

        // The held file is untouched, and the failed write left no temp sibling behind.
        Assert.Empty(LeftoverTempFiles(path));
    }
}
