using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The handoff from the setup script back to the app, which exists only on this build.
///
/// An elevated child cannot have its output redirected, so setup reports what it built
/// by writing one JSON object to a file the app named. That file is the only way the
/// switch learns the resolver's address and credentials — and every way it can be
/// wrong is silent. A result parsed as success with an empty URL leaves a switch lit
/// over nothing; a password dropped in the parse leaves a resolver the app cannot
/// authenticate to, which reports as "the resolver rejected the credentials" about an
/// install that in fact worked.
/// </summary>
public class DnsFilterSetupTests
{
    [Fact]
    public void CompleteResult_IsAdoptedWhole()
    {
        const string json = """
        {"ok":true,"url":"http://10.8.0.1:3000","username":"admin","password":"s3cret","message":"DNS filtering is on."}
        """;

        var result = DnsFilterSetup.ParseResult(json);

        Assert.NotNull(result);
        Assert.True(result!.Ok);
        Assert.Equal("http://10.8.0.1:3000", result.Url);
        Assert.Equal("admin", result.Username);
        Assert.Equal("s3cret", result.Password);
        Assert.Equal("DNS filtering is on.", result.Message);
    }

    /// <summary>
    /// The URL goes through the same normalizer the settings field does. The script
    /// composes it from a detected address, and a switch is not the place to discover
    /// that the two disagree about what a port is.
    /// </summary>
    [Theory]
    [InlineData("10.8.0.1:3000", "http://10.8.0.1:3000")]
    [InlineData("http://10.8.0.1", "http://10.8.0.1:3000")]
    [InlineData("http://10.8.0.1:3000/", "http://10.8.0.1:3000")]
    public void Url_IsNormalizedLikeTheSettingsField(string reported, string expected)
    {
        var result = DnsFilterSetup.ParseResult($"{{\"ok\":true,\"url\":\"{reported}\"}}");

        Assert.NotNull(result);
        Assert.Equal(expected, result!.Url);
    }

    /// <summary>
    /// A failure carries a sentence and no credentials. The switch shows that sentence
    /// and reverts, so an empty message here would revert the switch silently — the one
    /// outcome the whole result-file arrangement exists to avoid.
    /// </summary>
    [Fact]
    public void FailureResult_KeepsItsMessageAndClaimsNothing()
    {
        const string json = """
        {"ok":false,"message":"aborted - free port 53 first"}
        """;

        var result = DnsFilterSetup.ParseResult(json);

        Assert.NotNull(result);
        Assert.False(result!.Ok);
        Assert.Equal("aborted - free port 53 first", result.Message);
        Assert.Equal("", result.Url);
        Assert.Equal("", result.Password);
    }

    /// <summary>
    /// "ok" must be the literal true. A script that wrote a string, a number or nothing
    /// at all has not said the install succeeded, and anything other than true being
    /// read as success would turn a half-finished run into a configured switch.
    /// </summary>
    [Theory]
    [InlineData("""{"ok":"true","url":"http://10.8.0.1:3000"}""")]
    [InlineData("""{"ok":1,"url":"http://10.8.0.1:3000"}""")]
    [InlineData("""{"ok":null,"url":"http://10.8.0.1:3000"}""")]
    [InlineData("""{"url":"http://10.8.0.1:3000"}""")]
    public void AnythingButLiteralTrue_IsNotSuccess(string json)
    {
        var result = DnsFilterSetup.ParseResult(json);

        Assert.NotNull(result);
        Assert.False(result!.Ok);
    }

    /// <summary>
    /// Unreadable is distinct from failed: null tells the caller the script reported
    /// nothing usable, which is what a declined UAC prompt looks like, and that gets a
    /// different sentence from a script that ran and refused.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("\"a string\"")]
    [InlineData("{\"ok\":true")]
    public void UnreadableResult_IsNullRatherThanAFailure(string json)
    {
        Assert.Null(DnsFilterSetup.ParseResult(json));
    }

    /// <summary>
    /// Missing fields default to empty rather than throwing. The caller already treats
    /// an empty URL as "nothing to point at", and a parse that threw would surface as
    /// an unhandled exception out of a settings toggle.
    /// </summary>
    [Fact]
    public void MissingFields_ComeBackEmpty()
    {
        var result = DnsFilterSetup.ParseResult("""{"ok":true}""");

        Assert.NotNull(result);
        Assert.True(result!.Ok);
        Assert.Equal("", result.Url);
        Assert.Equal("", result.Username);
        Assert.Equal("", result.Password);
        Assert.Equal("", result.Message);
    }

    /// <summary>
    /// A password is whatever the script generated, including base64url's - and _ and
    /// any JSON escaping on the way through. It is used verbatim in an Authorization
    /// header, so a mangled one authenticates against nothing.
    /// </summary>
    [Fact]
    public void GeneratedPassword_SurvivesVerbatim()
    {
        const string password = "aB3-_xY9zQ7w-Kd2LmN4pR6s";
        var result = DnsFilterSetup.ParseResult(
            $$"""{"ok":true,"url":"http://10.8.0.1:3000","username":"admin","password":"{{password}}"}""");

        Assert.NotNull(result);
        Assert.Equal(password, result!.Password);
    }

    /// <summary>
    /// The plan text is what the operator agrees to before anything is installed, so it
    /// has to name the parts that are not obviously reversible. A confirmation that
    /// said only "set up DNS filtering?" would be consent to something else.
    /// </summary>
    [Fact]
    public void PlanText_NamesWhatItWillChange()
    {
        var plan = DnsFilterSetup.DescribePlan();

        Assert.Contains("service", plan);
        Assert.Contains("53", plan);
        Assert.Contains("firewall", plan, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("resolver", plan);
        Assert.Contains("backed up", plan, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Administrator", plan);
    }
}
