using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class IpNormalizationTests
{
    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4")]
    [InlineData("  1.2.3.4  ", "1.2.3.4")]
    [InlineData("1.2.3.4:443", "1.2.3.4")]                    // trailing port stripped
    [InlineData("[2001:db8::1]", "2001:db8::1")]              // bracketed IPv6
    [InlineData("fe80::1%eth0", "fe80::1")]                   // zone id dropped
    [InlineData("fe80::1%5", "fe80::1")]
    [InlineData("::ffff:1.2.3.4", "1.2.3.4")]                 // IPv4-mapped collapses to IPv4
    [InlineData("2001:DB8::A", "2001:db8::a")]                // canonical lowercase form
    public void Normalizes(string input, string expected)
    {
        Assert.True(FirewallService.TryNormalizeIp(input, out var normalized, out _));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("999.1.1.1")]
    public void RejectsInvalid(string input)
    {
        Assert.False(FirewallService.TryNormalizeIp(input, out _, out var error));
        Assert.NotEqual("", error);
    }

    [Fact]
    public void ZoneSpellingsCompareEqual()
    {
        Assert.True(FirewallService.TryNormalizeIp("fe80::1%eth0", out var a, out _));
        Assert.True(FirewallService.TryNormalizeIp("fe80::1", out var b, out _));
        Assert.Equal(a, b);
    }
}
