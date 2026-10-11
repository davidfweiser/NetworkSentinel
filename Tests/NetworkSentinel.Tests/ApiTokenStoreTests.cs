using System.Net;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

public class ApiTokenStoreTests
{
    private static readonly IPAddress Bot = IPAddress.Parse("203.0.113.7");

    private static string NewDataDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "networksentinel-tokens-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string StoreFile(string dir) => Path.Combine(dir, "web-api-tokens.json");

    private static string Create(ApiTokenStore store, string name = "GrokBot", int days = 0, string? sources = null,
        bool control = false)
    {
        Assert.True(store.TryCreate(name, days, sources, control, out var token, out var message), message);
        return token;
    }

    [Fact]
    public void CreatedTokenIsAcceptedAndCarriesItsName()
    {
        var store = new ApiTokenStore(NewDataDir());
        var token = Create(store);

        Assert.StartsWith(ApiTokenStore.TokenPrefix, token);

        var verdict = store.Verify(token, Bot);
        Assert.Equal(ApiTokenOutcome.Accepted, verdict.Outcome);
        Assert.Equal("GrokBot", verdict.Token!.Name);
    }

    [Fact]
    public void OnlyAHashReachesTheDisk()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir));
        // By position, not by the last '_': the secret is base64url and can contain one,
        // which would leave a fragment short enough to turn up in the file by chance.
        var secret = token[(ApiTokenStore.TokenPrefix.Length + 13)..];
        Assert.Equal(43, secret.Length);

        var onDisk = File.ReadAllText(StoreFile(dir));

        // The id is public (it is how a token is named for revocation); the secret
        // half is what must never be recoverable from the file.
        Assert.DoesNotContain(token, onDisk);
        Assert.DoesNotContain(secret, onDisk);
    }

    [Fact]
    public void StoreFileIsOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) return;

        var dir = NewDataDir();
        Create(new ApiTokenStore(dir));

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(StoreFile(dir)));
    }

    [Fact]
    public void TokenSurvivesARestart()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir));

        Assert.Equal(ApiTokenOutcome.Accepted, new ApiTokenStore(dir).Verify(token, Bot).Outcome);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nsm_")]
    [InlineData("not-a-token")]
    [InlineData("nsm_000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void GarbageIsRejected(string? presented)
    {
        var store = new ApiTokenStore(NewDataDir());
        Create(store);

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(presented, Bot).Outcome);
    }

    [Fact]
    public void RightIdWithWrongSecretIsRejected()
    {
        var store = new ApiTokenStore(NewDataDir());
        var token = Create(store);

        // Same id, one character of the secret changed.
        var last = token[^1] == 'A' ? 'B' : 'A';
        var forged = token[..^1] + last;

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(forged, Bot).Outcome);
    }

    [Fact]
    public void OneTokenDoesNotOpenAnother()
    {
        var store = new ApiTokenStore(NewDataDir());
        var first = Create(store, "first");
        var second = Create(store, "second");

        // First token's id spliced onto the second token's secret.
        var firstId = first.Substring(ApiTokenStore.TokenPrefix.Length, 12);
        var secondSecret = second[(ApiTokenStore.TokenPrefix.Length + 13)..];
        var spliced = $"{ApiTokenStore.TokenPrefix}{firstId}_{secondSecret}";

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(spliced, Bot).Outcome);
    }

    [Fact]
    public void RevokedTokenStopsWorkingAtOnceAndStaysRevoked()
    {
        var dir = NewDataDir();
        var store = new ApiTokenStore(dir);
        var token = Create(store);
        var id = store.List().Single().Id;

        Assert.True(store.Revoke(id, out _));

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, Bot).Outcome);
        Assert.Equal(ApiTokenOutcome.Rejected, new ApiTokenStore(dir).Verify(token, Bot).Outcome);
        Assert.False(store.Revoke(id, out _));
    }

    [Fact]
    public void ExpiredTokenIsRejectedAndTheOperatorIsToldWhy()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var store = new ApiTokenStore(NewDataDir()) { UtcNow = () => now };
        var token = Create(store, days: 30);

        now = now.AddDays(29);
        Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, Bot).Outcome);

        now = now.AddDays(2);
        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, Bot).Outcome);

        var row = store.List().Single();
        Assert.True(row.Expired);
        Assert.Contains("expired", row.LastRefusedWhy);
    }

    [Fact]
    public void PinnedTokenIsRefusedFromAnyOtherAddress()
    {
        var store = new ApiTokenStore(NewDataDir());
        var token = Create(store, sources: "203.0.113.7, 10.8.0.0/24");

        Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, Bot).Outcome);
        Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, IPAddress.Parse("10.8.0.200")).Outcome);
        // What a dual-stack socket reports for the same IPv4 peer.
        Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, IPAddress.Parse("::ffff:203.0.113.7")).Outcome);

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, IPAddress.Parse("203.0.113.8")).Outcome);
        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, IPAddress.Parse("10.8.1.1")).Outcome);
        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, null).Outcome);

        // The caller is told nothing; the token's own row is where the reason goes.
        var row = store.List().Single();
        Assert.Contains("allowed sources", row.LastRefusedWhy);
        Assert.Equal("203.0.113.7", row.LastUsedFrom);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.255.1.2", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/25", "192.168.1.127", true)]
    [InlineData("192.168.1.0/25", "192.168.1.128", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("2001:db8::/32", "2001:db9::5", false)]
    [InlineData("2001:db8::/32", "10.0.0.1", false)]
    [InlineData("0.0.0.0/0", "198.51.100.9", true)]
    public void SourceRangesMatchOnThePrefixOnly(string allowed, string remote, bool expected)
    {
        Assert.Equal(expected, ApiTokenStore.SourceAllowed(new[] { allowed }, IPAddress.Parse(remote)));
    }

    [Fact]
    public void RunawayPollerIsRateLimitedThenLetBackIn()
    {
        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var store = new ApiTokenStore(NewDataDir()) { UtcNow = () => now };
        var token = Create(store);

        for (var i = 0; i < ApiTokenStore.RequestsPerMinute; i++)
            Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, Bot).Outcome);

        var limited = store.Verify(token, Bot);
        Assert.Equal(ApiTokenOutcome.RateLimited, limited.Outcome);
        Assert.True(limited.RetryAfter > TimeSpan.Zero);

        now = now.AddMinutes(1);
        Assert.Equal(ApiTokenOutcome.Accepted, store.Verify(token, Bot).Outcome);
    }

    [Theory]
    [InlineData("", 0, null)]
    [InlineData("   ", 0, null)]
    [InlineData("bad\nname", 0, null)]
    [InlineData("ok", -1, null)]
    [InlineData("ok", 99999, null)]
    [InlineData("ok", 0, "not-an-address")]
    [InlineData("ok", 0, "10.0.0.0/99")]
    public void BadInputCreatesNothing(string name, int days, string? sources)
    {
        var dir = NewDataDir();
        var store = new ApiTokenStore(dir);

        Assert.False(store.TryCreate(name, days, sources, control: false, out var token, out _));
        Assert.Equal("", token);
        Assert.Empty(store.List());
        Assert.False(File.Exists(StoreFile(dir)));
    }

    [Fact]
    public void NamesAreUniqueAndTheCountIsBounded()
    {
        var store = new ApiTokenStore(NewDataDir());
        Create(store, "GrokBot");

        Assert.False(store.TryCreate("grokbot", 0, null, control: false, out _, out _));

        for (var i = 1; i < ApiTokenStore.MaxTokens; i++)
            Create(store, $"bot-{i}");

        Assert.False(store.TryCreate("one-too-many", 0, null, control: false, out _, out _));
        Assert.Equal(ApiTokenStore.MaxTokens, store.List().Count);
    }

    [Fact]
    public void TokensAreReadOnlyUnlessCreatedWithControl()
    {
        var store = new ApiTokenStore(NewDataDir());
        var reader = Create(store, "reader");
        var operatorToken = Create(store, "operator", sources: "203.0.113.7", control: true);

        Assert.False(store.Verify(reader, Bot).Token!.CanControl);
        Assert.True(store.Verify(operatorToken, Bot).Token!.CanControl);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("any")]
    public void ControlTokenMustBePinned(string? sources)
    {
        var dir = NewDataDir();
        var store = new ApiTokenStore(dir);

        // Firewall control that is valid from any address is the thing this refuses to mint.
        Assert.False(store.TryCreate("operator", 30, sources, control: true, out var token, out var message));
        Assert.Equal("", token);
        Assert.Contains("addresses", message);
        Assert.Empty(store.List());
    }

    [Fact]
    public void ControlTokenIsUselessFromAnotherAddress()
    {
        var store = new ApiTokenStore(NewDataDir());
        var token = Create(store, "operator", sources: "203.0.113.7", control: true);

        Assert.Equal(ApiTokenOutcome.Rejected, store.Verify(token, IPAddress.Parse("198.51.100.9")).Outcome);
    }

    [Fact]
    public void AccessSurvivesARestartAndAnUnknownValueMeansReadOnly()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir), "operator", sources: "203.0.113.7", control: true);

        Assert.True(new ApiTokenStore(dir).Verify(token, Bot).Token!.CanControl);

        // A hand-edited access level must not be read generously.
        var json = File.ReadAllText(StoreFile(dir));
        Assert.Contains("\"Access\": \"control\"", json);
        File.WriteAllText(StoreFile(dir), json.Replace("\"Access\": \"control\"", "\"Access\": \"Control \""));

        Assert.False(new ApiTokenStore(dir).Verify(token, Bot).Token!.CanControl);
    }

    [Fact]
    public void TokenFromBeforeAccessLevelsIsReadOnly()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir), "legacy");

        // What 0.7.17's first store wrote: no Access field at all.
        var json = File.ReadAllText(StoreFile(dir));
        var lines = json.Split('\n').Where(l => !l.Contains("\"Access\"")).ToArray();
        File.WriteAllText(StoreFile(dir), string.Join('\n', lines));

        var verdict = new ApiTokenStore(dir).Verify(token, Bot);
        Assert.Equal(ApiTokenOutcome.Accepted, verdict.Outcome);
        Assert.False(verdict.Token!.CanControl);
    }

    [Fact]
    public void LastActionIsKeptForTheOperator()
    {
        var store = new ApiTokenStore(NewDataDir());
        Create(store, "operator", sources: "203.0.113.7", control: true);
        var id = store.List().Single().Id;

        store.NoteAction(id, "block 198.51.100.9");

        var row = store.List().Single();
        Assert.Equal("block 198.51.100.9", row.LastAction);
        Assert.NotNull(row.LastActionUtc);
    }

    [Fact]
    public void DamagedStoreFailsClosed()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir));

        File.WriteAllText(StoreFile(dir), "{ this is not json");

        var reloaded = new ApiTokenStore(dir);
        Assert.Empty(reloaded.List());
        Assert.Equal(ApiTokenOutcome.Rejected, reloaded.Verify(token, Bot).Outcome);
    }

    [Fact]
    public void TamperedHashIsATokenNobodyHolds()
    {
        var dir = NewDataDir();
        var token = Create(new ApiTokenStore(dir));

        // An empty or truncated hash must not turn into "matches anything".
        var json = File.ReadAllText(StoreFile(dir));
        var start = json.IndexOf("\"Hash\": \"", StringComparison.Ordinal) + "\"Hash\": \"".Length;
        var end = json.IndexOf('"', start);
        File.WriteAllText(StoreFile(dir), json[..start] + "00" + json[end..]);

        var reloaded = new ApiTokenStore(dir);
        Assert.Equal(ApiTokenOutcome.Rejected, reloaded.Verify(token, Bot).Outcome);
        Assert.Equal(ApiTokenOutcome.Rejected, reloaded.Verify("", Bot).Outcome);
    }
}
