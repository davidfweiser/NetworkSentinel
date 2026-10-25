using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// `sudo networksentinel --set-master-password` writes, as root, into a directory the
/// service user owns. Nothing that user can plant there may redirect root's write.
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
    public void APlantedTempLinkIsNotFollowed()
    {
        if (OperatingSystem.IsWindows()) return;

        var dir = NewDir();
        try
        {
            var victim = Path.Combine(dir, "victim");
            File.WriteAllText(victim, "original");
            File.CreateSymbolicLink(Path.Combine(dir, "web-master.json.tmp"), victim);

            var store = new WebAuthStore(dir);
            Assert.True(store.SetPassword("correct horse", "correct horse", out _));

            Assert.Equal("original", File.ReadAllText(victim));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void TheHashFileIsOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) return;

        var dir = NewDir();
        try
        {
            var store = new WebAuthStore(dir);
            Assert.True(store.SetPassword("correct horse", "correct horse", out _));

            var mode = File.GetUnixFileMode(Path.Combine(dir, "web-master.json"));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ASymlinkedDataDirectoryIsFound()
    {
        if (OperatingSystem.IsWindows()) return;

        var home = NewDir();
        try
        {
            Directory.CreateDirectory(Path.Combine(home, ".local"));
            var elsewhere = NewDir();
            Directory.CreateSymbolicLink(Path.Combine(home, ".local", "share"), elsewhere);
            var dataDir = Path.Combine(home, ".local", "share", "NetworkSentinel");

            Assert.Equal(Path.Combine(home, ".local", "share"), Program.FindSymlinkUnder(home, dataDir));
            Directory.Delete(elsewhere, recursive: true);
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }

    [Fact]
    public void PlainDirectoriesPass()
    {
        var home = NewDir();
        try
        {
            var dataDir = Path.Combine(home, ".local", "share", "NetworkSentinel");
            Assert.Null(Program.FindSymlinkUnder(home, dataDir));          // nothing there yet
            Directory.CreateDirectory(dataDir);
            Assert.Null(Program.FindSymlinkUnder(home, dataDir));          // real directories
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }
}

/// <summary>A damaged state file must fail closed, never fall back to "nothing set up yet".</summary>
public class DamagedStateFileTests
{
    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-damaged-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("{}")]
    public void ADamagedPasswordFileDoesNotReopenSetup(string contents)
    {
        var dir = NewDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "web-master.json"), contents);
            var store = new WebAuthStore(dir);

            Assert.NotNull(store.LoadError);
            Assert.True(store.IsConfigured);
            Assert.False(store.TrySetup("attacker-password", "attacker-password", out var message));
            Assert.Contains("--set-master-password", message);
            Assert.False(store.VerifyPassword("attacker-password"));
            Assert.Equal(contents, File.ReadAllText(Path.Combine(dir, "web-master.json")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void TheCliResetRepairsADamagedPasswordFile()
    {
        var dir = NewDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "web-master.json"), "{ not json");
            var store = new WebAuthStore(dir);

            Assert.True(store.SetPassword("correct horse", "correct horse", out _));
            Assert.Null(store.LoadError);
            Assert.True(store.VerifyPassword("correct horse"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ADamagedSettingsFileIsKeptAndReported()
    {
        var dir = NewDir();
        try
        {
            var path = Path.Combine(dir, "settings.json");
            const string broken = """{ "WebHttpsOnly": true, "MonitorPollMs": "1000" }""";
            File.WriteAllText(path, broken);

            var settings = NetworkSentinel.Services.AppSettings.Load(path);
            // A restart loop over the same damaged file must not pile up copies.
            NetworkSentinel.Services.AppSettings.Load(path);

            Assert.NotNull(settings.LoadError);
            var backup = Assert.Single(Directory.GetFiles(dir, "settings.json.corrupt-*"));
            Assert.Equal(broken, File.ReadAllText(backup));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AGoodSettingsFileLoadsWithoutError()
    {
        var dir = NewDir();
        try
        {
            var path = Path.Combine(dir, "settings.json");
            File.WriteAllText(path, """{ "WebHttpsOnly": true, "MonitorPollMs": 1000 }""");

            var settings = NetworkSentinel.Services.AppSettings.Load(path);

            Assert.Null(settings.LoadError);
            Assert.True(settings.WebHttpsOnly);
            Assert.DoesNotContain("LoadError", System.Text.Json.JsonSerializer.Serialize(settings));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
