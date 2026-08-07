using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class ParsingTests
{
    [Fact]
    public void HoneypotPortsParseAndDeduplicate()
    {
        var ports = HoneypotService.ParsePorts(" 2323, 3389 ,2323, nonsense, 70000, 0, 5900 ");
        Assert.Equal(new[] { 2323, 3389, 5900 }, ports);
    }

    [Fact]
    public void HoneypotPortsEmptyInput()
    {
        Assert.Empty(HoneypotService.ParsePorts(null));
        Assert.Empty(HoneypotService.ParsePorts(""));
    }

    [Theory]
    [InlineData("NetworkSentinel-IP-1.2.3.4-In", "1.2.3.4")]
    [InlineData("NetworkSentinel-IP-2001_db8__1-Out", "2001:db8::1")]
    public void ExtractsIpFromManagedRuleName(string ruleName, string expected)
    {
        Assert.True(FirewallService.TryExtractIpFromManagedRule(ruleName, null, out var ip));
        Assert.Equal(expected, ip);
    }

    [Fact]
    public void RejectsForeignRuleName()
    {
        Assert.False(FirewallService.TryExtractIpFromManagedRule("ufw-allow-ssh", null, out _));
    }

    [Fact]
    public void OwnLoopbackAddressIsRecognized()
    {
        // The loopback pseudo-interface carries 127.0.0.1 on any Windows host.
        Assert.True(LocalAddresses.IsOwnAddress("127.0.0.1"));
        Assert.False(LocalAddresses.IsOwnAddress("203.0.113.99"));
        Assert.False(LocalAddresses.IsOwnAddress("not-an-ip"));
    }
}
