using System.Text.Json;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The user allowlist file is edited from two places: the app (domains and IPs)
/// and by hand (CIDR ranges and notes, which the app has no editor for). A save
/// from the app must not throw away what only a hand edit can put there.
/// </summary>
public class AllowlistPersistenceTests
{
    private static string TempFile(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), "ns-allowlist-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void AddingADomainKeepsHandWrittenCidrsAndNotes()
    {
        var path = TempFile("""
            {
              "version": 1,
              "domains": [],
              "ips": [],
              "cidrs": [ "198.51.100.0/24", "2001:db8::/48" ],
              "notes": "office ranges"
            }
            """);
        try
        {
            var allowlist = new AllowlistService(path);
            Assert.True(allowlist.TryAddDomain("added.example.invalid", out _));

            var saved = JsonSerializer.Deserialize<AllowlistFile>(File.ReadAllText(path))!;
            Assert.Equal(new[] { "198.51.100.0/24", "2001:db8::/48" }, saved.Cidrs);
            Assert.Equal("office ranges", saved.Notes);
            Assert.Contains("added.example.invalid", saved.Domains!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AFileThatDoesNotParseIsNotOverwritten()
    {
        const string broken = """{ "cidrs": [ "198.51.100.0/24" ], oops """;
        var path = TempFile(broken);
        try
        {
            var allowlist = new AllowlistService(path);
            allowlist.TryAddDomain("added.example.invalid", out _);

            Assert.Equal(broken, File.ReadAllText(path));
            Assert.Contains("could not be read", allowlist.StatusText);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
