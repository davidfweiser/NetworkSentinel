using NetworkSentinel.Services;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// `NetworkSentinel --set-master-password` writes, elevated, into a data directory that
/// ordinary accounts can also write to. Nothing planted there may redirect that write.
/// </summary>
public class MasterPasswordFileTests
{
    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-auth-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void AFilePlantedUnderTheOldTempNameIsNotWrittenThrough()
    {
        var dir = NewDir();
        try
        {
            // The store used to write "<file>.tmp" and rename it. Whatever sat under
            // that name — a link above all — was opened and overwritten.
            var planted = Path.Combine(dir, "web-master.json.tmp");
            File.WriteAllText(planted, "original");

            var store = new WebAuthStore(dir);
            Assert.True(store.SetPassword("correct horse", "correct horse", out _));

            Assert.Equal("original", File.ReadAllText(planted));
            Assert.True(new WebAuthStore(dir).IsConfigured);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AJunctionedDataDirectoryIsFound()
    {
        var parent = NewDir();
        var elsewhere = NewDir();
        try
        {
            var link = Path.Combine(parent, "NetworkSentinel");
            try
            {
                Directory.CreateSymbolicLink(link, elsewhere);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Creating a symbolic link needs Administrator or Developer Mode; the
                // check itself is the same attribute test either way.
                return;
            }

            Assert.True(Program.IsLink(link));
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
            Directory.Delete(elsewhere, recursive: true);
        }
    }

    [Fact]
    public void PlainDirectoriesPass()
    {
        var parent = NewDir();
        try
        {
            var dataDir = Path.Combine(parent, "NetworkSentinel");
            Assert.False(Program.IsLink(dataDir));          // nothing there yet
            Directory.CreateDirectory(dataDir);
            Assert.False(Program.IsLink(dataDir));          // a real directory
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    // ---- What the elevated process runs ------------------------------------------

    [Fact]
    public void SystemToolsAreAbsolutePathsInsideTheSystemDirectory()
    {
        var netsh = SystemTools.Netsh;
        Assert.NotNull(netsh);
        Assert.True(Path.IsPathFullyQualified(netsh!));
        Assert.StartsWith(Environment.SystemDirectory, netsh, StringComparison.OrdinalIgnoreCase);

        // PowerShell and WireGuard may be absent; when present they are never a bare name.
        foreach (var tool in new[] { SystemTools.PowerShell, SystemTools.WireGuard })
            if (tool != null)
                Assert.True(Path.IsPathFullyQualified(tool));
    }

    [Fact]
    public void TheCurrentDirectoryIsNeverConsulted()
    {
        // A tool dropped where the app happens to be started from must not be what an
        // elevated process is handed to run.
        var dir = NewDir();
        var original = Environment.CurrentDirectory;
        try
        {
            File.WriteAllText(Path.Combine(dir, "ns-planted-tool.exe"), "");
            Environment.CurrentDirectory = dir;

            Assert.Null(SystemTools.InDirectory(Environment.SystemDirectory, "ns-planted-tool.exe"));
            Assert.Null(SystemTools.InDirectory("", "ns-planted-tool.exe"));
            Assert.Null(SystemTools.InDirectory(".", "ns-planted-tool.exe"));
        }
        finally
        {
            Environment.CurrentDirectory = original;
            Directory.Delete(dir, recursive: true);
        }
    }
}
