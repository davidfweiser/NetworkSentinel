using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The shield that keeps auto-block from severing a WireGuard tunnel. Every case here
/// is a way a VPN gateway used to lose its own clients: peer monitoring switched off,
/// a peer that roamed, a tunnel that had already dropped, a restart.
/// </summary>
public class WireGuardEndpointGuardTests
{
    [Fact]
    public void RememberedEndpointIsProtected()
    {
        var guard = new WireGuardEndpointGuard();

        Assert.False(guard.IsProtected("203.0.113.7"));
        guard.Remember("203.0.113.7");
        Assert.True(guard.IsProtected("203.0.113.7"));
    }

    [Fact]
    public void ProtectionIgnoresPortSuffixAndCasing()
    {
        var guard = new WireGuardEndpointGuard();
        guard.Remember("203.0.113.8:51820");

        Assert.True(guard.IsProtected("203.0.113.8"));

        guard.Remember("[2001:DB8::5]:51820");
        Assert.True(guard.IsProtected("2001:db8::5"));
    }

    [Fact]
    public void GarbageIsNotProtected()
    {
        var guard = new WireGuardEndpointGuard();
        guard.Remember("not-an-address");
        guard.Remember(null);
        guard.Remember("");

        Assert.False(guard.IsProtected("not-an-address"));
        // Not Assert.Empty: the state file is shared with the other cases in this class.
        Assert.DoesNotContain("not-an-address", guard.Endpoints);
    }

    [Fact]
    public void EndpointsSurviveARestart()
    {
        // The window that matters: the tunnel is already down, so `wg` reports no
        // endpoint, and a fresh process must still refuse to block the address that
        // would bring it back.
        var guard = new WireGuardEndpointGuard();
        guard.Remember("203.0.113.9");
        guard.Stop();   // flushes the state file

        var restarted = new WireGuardEndpointGuard();
        Assert.True(restarted.IsProtected("203.0.113.9"));
    }

    [Theory]
    [InlineData("Endpoint = 198.51.100.4:51820", "198.51.100.4")]
    [InlineData("endpoint=198.51.100.5:51820", "198.51.100.5")]
    [InlineData("Endpoint = [2001:db8::1]:51820", "2001:db8::1")]
    [InlineData("Endpoint = 198.51.100.6:51820  # home", "198.51.100.6")]
    public void ParsesEndpointsFromConfig(string line, string expected)
    {
        var conf = "[Interface]\nPrivateKey = SECRET\nAddress = 10.8.0.2/24\n\n[Peer]\n" + line + "\n";
        Assert.Equal(new[] { expected }, WireGuardEndpointGuard.ParseConfigEndpoints(conf));
    }

    [Fact]
    public void ConfigHostnamesAreNotResolved()
    {
        // Resolving would let whoever answers DNS write their own address into a
        // never-block list. The live `wg` dump reports the resolved address anyway.
        var conf = "[Peer]\nEndpoint = vpn.example.org:51820\n";
        Assert.Empty(WireGuardEndpointGuard.ParseConfigEndpoints(conf));
    }

    [Fact]
    public void ConfigParsingReadsNothingButEndpoints()
    {
        // A wg-quick config holds private and preshared keys; nothing but Endpoint is read.
        var conf = string.Join('\n',
            "[Interface]",
            "PrivateKey = 4Nx1QF2wV0mR7yT8u9IoPaSdFgHjKlZxCvBnMqWeRt0=",
            "ListenPort = 51820",
            "[Peer]",
            "PublicKey = mQ1nB2vC3xZ4aS5dF6gH7jK8lP9oI0uY1tR2eW3qA4=",
            "PresharedKey = zX9cV8bN7mL6kJ5hG4fD3sA2pO1iU0yT9rE8wQ7aS6=",
            "AllowedIPs = 10.8.0.3/32",
            "# Endpoint = 192.0.2.99:51820",
            "Endpoint = 198.51.100.7:51820");

        Assert.Equal(new[] { "198.51.100.7" }, WireGuardEndpointGuard.ParseConfigEndpoints(conf));
    }

    [Fact]
    public void SamplingIsSafeWithoutWireGuardOrRoot()
    {
        // CI has no tunnel and no CAP_NET_ADMIN: the pass must not throw, and must not
        // silently drop what it already knows.
        var guard = new WireGuardEndpointGuard();
        guard.Remember("203.0.113.20");

        guard.SampleOnce();

        Assert.True(guard.IsProtected("203.0.113.20"));
        Assert.False(string.IsNullOrWhiteSpace(guard.Status));
    }
}
