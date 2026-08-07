using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// CGNAT sits in a gap the two gates treat differently: never auto-blocked, but
/// blockable on purpose. Closing that gap in both directions once meant an operator
/// could not stop a hostile tailnet peer from inside the app at all.
/// </summary>
public class BlockableAddressTests
{
    [Theory]
    [InlineData("100.64.0.1")]
    [InlineData("100.127.255.255")]
    [InlineData("::ffff:100.64.0.1")]
    public void CarrierGradeNatIsRecognised(string ip)
        => Assert.True(GeoIpService.IsCarrierGradeNat(ip));

    [Theory]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("garbage")]
    public void NonCarrierGradeIsNot(string ip)
        => Assert.False(GeoIpService.IsCarrierGradeNat(ip));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.5")]
    [InlineData("169.254.1.1")]
    [InlineData("224.0.0.251")]
    [InlineData("fe80::1")]
    public void LanAndFriendsAreNeverBlockable(string ip)
        => Assert.True(FirewallService.IsNeverBlockable(ip));

    [Theory]
    [InlineData("100.64.0.1")]   // manual block allowed — auto-block still refuses
    [InlineData("203.0.113.7")]
    [InlineData("8.8.8.8")]
    public void PublicAndCarrierGradeAreBlockable(string ip)
        => Assert.False(FirewallService.IsNeverBlockable(ip));

    [Fact]
    public void CarrierGradeStaysOutOfAutoBlock()
    {
        // The auto-block gate is the wider IsPrivateOrLocal, deliberately.
        Assert.True(FirewallService.IsPrivateOrLocal("100.64.0.1"));
        Assert.False(FirewallService.IsNeverBlockable("100.64.0.1"));
    }
}
