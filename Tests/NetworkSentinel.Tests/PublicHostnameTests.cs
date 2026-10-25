using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class PublicHostnameTests
{
    [Theory]
    [InlineData("sentinel.example.com", "sentinel.example.com")]
    [InlineData("  Sentinel.Example.COM  ", "sentinel.example.com")]      // trimmed and lowercased
    [InlineData("https://sentinel.example.com/", "sentinel.example.com")] // pasted from a browser
    [InlineData("http://sentinel.example.com", "sentinel.example.com")]
    [InlineData("sentinel.example.com:18443", "sentinel.example.com")]    // port belongs to the port field
    [InlineData("https://sentinel.example.com:18443/settings", "sentinel.example.com")]
    [InlineData("sentinel.example.com.", "sentinel.example.com")]         // fully qualified, trailing dot
    [InlineData("myhost.duckdns.org", "myhost.duckdns.org")]              // a duckdns name is just a name
    public void Normalizes(string input, string expected)
        => Assert.Equal(expected, AppSettings.NormalizeHostname(input));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("host name")]        // spaces are not a hostname
    [InlineData("host_name")]
    [InlineData("2001:db8::1")]      // an address, not a name the certificate can cover
    [InlineData("https://")]
    public void RejectsWhatIsNotAHostname(string input)
        => Assert.Equal("", AppSettings.NormalizeHostname(input));

    [Fact]
    public void ExplicitHostnameWinsOverDuckDns()
    {
        var settings = new AppSettings { WebPublicHostname = "sentinel.example.com" };
        Assert.Equal("sentinel.example.com", settings.PublicHostnameOr("myhost.duckdns.org"));
    }

    [Fact]
    public void FallsBackToDuckDnsWhenUnset()
    {
        var settings = new AppSettings();
        Assert.Equal("myhost.duckdns.org", settings.PublicHostnameOr("myhost.duckdns.org"));
    }

    [Fact]
    public void EmptyWhenNeitherIsConfigured()
    {
        var settings = new AppSettings();
        Assert.Equal("", settings.PublicHostnameOr(""));
    }
}
