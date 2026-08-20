using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// How Network Sentinel decides that sudo, pkexec, nft, ufw or iptables is
/// installed.
///
/// This used to be a <c>which</c> subprocess, and both of its failure modes were
/// reported to the operator as a missing sudo. <c>which</c> is no longer installed
/// by default on Fedora or Debian trixie, so on those hosts every probe answered
/// "missing" and the Firewall Config page refused to write a rule on a machine
/// that had pkexec and sudo both. And a desktop session's PATH omits the sbin
/// directories on Debian and its derivatives, where nft, iptables and ufw all
/// live, so the backend probe found none of them on a host running UFW.
/// </summary>
public class ExecutableResolutionTests
{
    [Fact]
    public void SearchPathAlwaysCoversTheSbinDirectories()
    {
        var dirs = FirewallService.ExecutableSearchPath().ToList();

        // Present whether or not this process's PATH lists them — that is the point.
        Assert.Contains("/usr/sbin", dirs);
        Assert.Contains("/sbin", dirs);
        Assert.Contains("/usr/local/sbin", dirs);
    }

    [Fact]
    public void SearchPathYieldsEachDirectoryOnce()
    {
        var dirs = FirewallService.ExecutableSearchPath().ToList();

        Assert.Equal(dirs.Count, dirs.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ResolvesAnInstalledCommandToAnAbsolutePath()
    {
        var resolved = FirewallService.ResolveExecutable("sh");

        Assert.NotNull(resolved);
        Assert.True(Path.IsPathRooted(resolved!));
        Assert.True(File.Exists(resolved));
    }

    [Fact]
    public void ReportsAnUninstalledCommandAsMissing()
    {
        Assert.Null(FirewallService.ResolveExecutable("networksentinel-no-such-tool"));
        Assert.False(FirewallService.ReadCommandExists("networksentinel-no-such-tool"));
    }

    [Fact]
    public void FindsACommandThatOnlyExistsUnderSbin()
    {
        // The Debian desktop case: the tool is installed, PATH does not name its
        // directory, and the app still has to find it.
        if (OperatingSystem.IsWindows()) return;   // Unix modes are the thing under test

        var root = Path.Combine(Path.GetTempPath(), "ns-resolve-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var tool = Path.Combine(root, "ns-fake-nft");
            File.WriteAllText(tool, "#!/bin/sh\nexit 0\n");
            File.SetUnixFileMode(tool,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            Assert.True(FirewallService.IsExecutableFile(tool));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void AFileWithoutAnExecuteBitIsNotACommand()
    {
        if (OperatingSystem.IsWindows()) return;   // Unix modes are the thing under test

        var path = Path.Combine(Path.GetTempPath(), "ns-plain-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, "not a program");
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            // Resolving on File.Exists alone would run this as if it were the tool.
            Assert.False(FirewallService.IsExecutableFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ADirectoryNamedLikeTheToolIsNotTheTool()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-dir-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.False(FirewallService.IsExecutableFile(dir));
        }
        finally
        {
            Directory.Delete(dir);
        }
    }

    /// <summary>
    /// An absolute path is taken as given — callers pass one when they already
    /// resolved it, and re-searching PATH for a name containing a slash is wrong.
    /// </summary>
    [Fact]
    public void AnAbsolutePathIsPassedThrough()
    {
        Assert.Equal("/usr/sbin/nft", FirewallService.ResolveExecutable("/usr/sbin/nft"));
    }
}
