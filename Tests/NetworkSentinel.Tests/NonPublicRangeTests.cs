using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class NonPublicRangeTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.10.10")]        // link-local
    [InlineData("100.64.0.1")]           // CGNAT lower bound (Tailscale, VPN tunnels)
    [InlineData("100.127.255.255")]      // CGNAT upper bound
    [InlineData("224.0.0.251")]          // multicast (mDNS)
    [InlineData("255.255.255.255")]      // broadcast
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]              // unique local
    [InlineData("ff02::fb")]             // IPv6 multicast
    [InlineData("::ffff:192.168.1.1")]   // IPv4-mapped private
    public void NonPublic(string ip) => Assert.True(GeoIpService.IsNonPublic(ip));

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("100.63.255.255")]       // just below the CGNAT /10
    [InlineData("100.128.0.0")]          // just above the CGNAT /10
    [InlineData("203.0.113.7")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.8.8")]       // IPv4-mapped public stays public
    public void Public(string ip) => Assert.False(GeoIpService.IsNonPublic(ip));

    [Fact]
    public void UnparsableIsTreatedAsNonPublic() => Assert.True(GeoIpService.IsNonPublic("garbage"));
}
