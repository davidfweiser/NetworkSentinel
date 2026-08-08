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

    /// <summary>
    /// `wg show all dump` is what feeds both the peer alerts and the never-block tunnel
    /// shield, so a field-index slip here would silently protect nothing. The dump also
    /// prints the interface private key and each peer's preshared key — neither may
    /// survive the parse.
    /// </summary>
    [Fact]
    public void ParsesWgDumpWithoutCarryingKeyMaterial()
    {
        const string privateKey = "4Nx1QF2wV0mR7yT8u9IoPaSdFgHjKlZxCvBnMqWeRt0=";
        const string presharedKey = "zX9cV8bN7mL6kJ5hG4fD3sA2pO1iU0yT9rE8wQ7aS6=";
        var dump = string.Join('\n',
            // Device line: iface, private key, public key, listen port, fwmark.
            string.Join('\t', "wg0", privateKey, "SrVeRpUbLiCkEy0000000000000000000000000000=", "51820", "off"),
            // Peer lines: iface, public key, preshared key, endpoint, allowed ips,
            // handshake, rx, tx, keepalive.
            string.Join('\t', "wg0", "PeErOnE0000000000000000000000000000000000=", presharedKey,
                "198.51.100.4:51820", "10.8.0.2/32", "1786000000", "1024", "2048", "25"),
            string.Join('\t', "wg0", "PeErTwO0000000000000000000000000000000000=", "(none)",
                "(none)", "10.8.0.3/32", "0", "0", "0", "off"));

        var peers = WireGuardMonitor.ParseDump(dump);

        Assert.Equal(2, peers.Count);
        Assert.Equal("198.51.100.4", peers[0].EndpointIp);
        Assert.Equal("10.8.0.2/32", peers[0].AllowedIps);
        Assert.Equal(1024, peers[0].TransferRx);
        Assert.Equal(2048, peers[0].TransferTx);
        Assert.NotNull(peers[0].LastHandshake);

        // A peer that has never connected has no endpoint to shield.
        Assert.Equal("", peers[1].EndpointIp);
        Assert.Null(peers[1].LastHandshake);

        var everything = string.Join('\n', peers.Select(p =>
            $"{p.Interface}|{p.PublicKey}|{p.Endpoint}|{p.EndpointIp}|{p.AllowedIps}"));
        Assert.DoesNotContain(privateKey, everything);
        Assert.DoesNotContain(presharedKey, everything);
    }

    [Fact]
    public void OwnLoopbackAddressIsRecognized()
    {
        // lo carries 127.0.0.1 on any Linux host this suite runs on.
        Assert.True(LocalAddresses.IsOwnAddress("127.0.0.1"));
        Assert.False(LocalAddresses.IsOwnAddress("203.0.113.99"));
        Assert.False(LocalAddresses.IsOwnAddress("not-an-ip"));
    }
}
