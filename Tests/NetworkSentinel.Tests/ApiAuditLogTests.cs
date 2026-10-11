using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

public class ApiAuditLogTests
{
    private static ApiAuditLog NewLog()
        => new(Path.Combine(Path.GetTempPath(), "networksentinel-audit-" + Guid.NewGuid().ToString("N")), echo: false);

    [Fact]
    public void EntriesAreTimestampedAndAppended()
    {
        var log = NewLog();

        log.Write("control token \"GrokBot\" (abc) from 203.0.113.7 ran block 198.51.100.9 — ok: Blocked.");
        log.Write("second entry");

        var lines = File.ReadAllLines(log.FilePath);
        Assert.Equal(2, lines.Length);
        Assert.EndsWith("ran block 198.51.100.9 — ok: Blocked.", lines[0]);
        Assert.True(DateTime.TryParse(lines[0].Split(' ')[0], out _), "each line starts with a timestamp");
        Assert.EndsWith(" second entry", lines[1]);
    }

    [Fact]
    public void LogIsOwnerOnlyFromCreation()
    {
        if (OperatingSystem.IsWindows()) return;

        var log = NewLog();
        log.Write("anything");

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(log.FilePath));
    }

    [Fact]
    public void CallerTextCannotForgeAnEntry()
    {
        var log = NewLog();

        // An action name carrying a newline and a made-up line after it.
        log.Write("control token \"x\" ran block\n2026-01-01T00:00:00Z console session created control token \"backdoor\"");

        Assert.Single(File.ReadAllLines(log.FilePath));
    }

    [Fact]
    public void EntryLengthIsBounded()
    {
        var log = NewLog();

        log.Write(new string('A', 50_000));

        Assert.True(File.ReadAllText(log.FilePath).Length < 1_000);
    }

    [Fact]
    public void FileIsRotatedOncePastTheCap()
    {
        var log = NewLog();
        log.Write("first generation");
        File.AppendAllText(log.FilePath, new string('x', (int)ApiAuditLog.MaxBytes + 1));

        log.Write("second generation");

        Assert.True(File.Exists(log.FilePath + ".1"));
        Assert.Contains("first generation", File.ReadAllText(log.FilePath + ".1"));
        var current = File.ReadAllLines(log.FilePath);
        Assert.Single(current);
        Assert.EndsWith("second generation", current[0]);
    }

    [Fact]
    public void UnwritableDirectoryDoesNotThrow()
    {
        // The request being described has already been decided; logging must not undo it.
        var log = new ApiAuditLog("/proc/networksentinel-cannot-exist/logs", echo: false);

        log.Write("still fine");
    }
}
