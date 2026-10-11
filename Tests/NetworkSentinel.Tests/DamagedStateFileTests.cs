using System.Security.AccessControl;
using System.Security.Principal;
using NetworkSentinel.Services;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

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

            var settings = AppSettings.Load(path);
            // A restart loop over the same damaged file must not pile up copies.
            AppSettings.Load(path);

            Assert.NotNull(settings.LoadError);
            var backup = Assert.Single(Directory.GetFiles(dir, "settings.json.corrupt-*"));
            Assert.Equal(broken, File.ReadAllText(backup));

            // And the defaults now in memory must not be saved over the original.
            settings.Save();
            Assert.Single(Directory.GetFiles(dir, "settings.json.corrupt-*"));
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

            var settings = AppSettings.Load(path);

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

/// <summary>
/// The setup code is written where an administrator can read it, in a directory
/// ordinary accounts can also write to. The file must not inherit that openness.
/// </summary>
public class SetupCodeFileTests
{
    private static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ns-setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void TheCodeIsWrittenAndReadableOnlyByAdministratorsSystemAndTheWriter()
    {
        var dir = NewDir();
        try
        {
            var path = SetupCodeFile.TryWrite(dir, "ABCD-1234");

            Assert.NotNull(path);
            Assert.StartsWith("ABCD-1234", File.ReadAllText(path!));

            var security = new FileInfo(path!).GetAccessControl();
            Assert.True(security.AreAccessRulesProtected);

            var allowed = new[]
            {
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                WindowsIdentity.GetCurrent().User!
            };
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>().ToList();
            Assert.NotEmpty(rules);
            Assert.All(rules, r => Assert.Contains((SecurityIdentifier)r.IdentityReference, allowed));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AFilePlantedUnderTheNameIsReplacedNotWrittenInto()
    {
        var dir = NewDir();
        try
        {
            // A planted file would keep the access list its author gave it.
            var planted = SetupCodeFile.PathIn(dir);
            File.WriteAllText(planted, "planted");

            var path = SetupCodeFile.TryWrite(dir, "ABCD-1234");

            Assert.NotNull(path);
            Assert.True(new FileInfo(path!).GetAccessControl().AreAccessRulesProtected);
            Assert.DoesNotContain("planted", File.ReadAllText(path!));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void DeletingRemovesIt()
    {
        var dir = NewDir();
        try
        {
            SetupCodeFile.TryWrite(dir, "ABCD-1234");
            SetupCodeFile.TryDelete(dir);
            Assert.False(File.Exists(SetupCodeFile.PathIn(dir)));

            SetupCodeFile.TryDelete(dir);   // nothing there: still quiet
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
