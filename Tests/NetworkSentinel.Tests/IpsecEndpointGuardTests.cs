using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The shield that keeps auto-block from severing an IPSec tunnel. The case behind it is
/// a site-to-site link: the peer is another site's router at a fixed public address, so a
/// heuristic that flags it and a firewall rule that follows take the tunnel down for both
/// ends at once — and from this end nothing looks wrong afterwards.
///
/// Two failure directions are covered here, and the second matters as much as the first:
/// the guard must learn the peer from every source a live or dead tunnel leaves behind,
/// and it must never learn a *subnet*, because these config files routinely carry
/// 0.0.0.0/0 and a shield that swallowed one would disable auto-block entirely.
/// </summary>
public class IpsecEndpointGuardTests
{
    [Fact]
    public void RememberedPeerIsProtected()
    {
        var guard = new IpsecEndpointGuard();

        Assert.False(guard.IsProtected("198.51.100.70"));
        guard.Remember("198.51.100.70");
        Assert.True(guard.IsProtected("198.51.100.70"));
    }

    [Fact]
    public void ProtectionIgnoresCasingAndUnspecifiedAddresses()
    {
        var guard = new IpsecEndpointGuard();

        guard.Remember("[2001:DB8::70]");
        Assert.True(guard.IsProtected("2001:db8::70"));

        // A wildcard SA or a %any config yields these; they are not peers.
        guard.Remember("0.0.0.0");
        guard.Remember("::");
        Assert.False(guard.IsProtected("0.0.0.0"));
        Assert.False(guard.IsProtected("::"));
    }

    [Fact]
    public void PeersSurviveARestart()
    {
        // The window that matters: the tunnel has already dropped, so the kernel reports
        // no SA, and a fresh process must still refuse to block the address that would
        // bring it back.
        var guard = new IpsecEndpointGuard();
        guard.Remember("198.51.100.71");
        guard.Stop();   // flushes the state file

        var restarted = new IpsecEndpointGuard();
        Assert.True(restarted.IsProtected("198.51.100.71"));
    }

    [Fact]
    public void ParsesBothEndsOfAnSaFromXfrmState()
    {
        // Real `ip xfrm state` output, trimmed. The key material on the following lines
        // is never read — only the "src … dst …" header is.
        var output = string.Join('\n',
            "src 203.0.113.4 dst 198.51.100.72",
            "\tproto esp spi 0xc1a2b3c4 reqid 1 mode tunnel",
            "\treplay-window 32 flag af-unspec",
            "\tauth-trunc hmac(sha256) 0x0011223344556677 128",
            "\tenc cbc(aes) 0x8899aabbccddeeff",
            "\tsel src 0.0.0.0/0 dst 0.0.0.0/0",
            "src 198.51.100.72 dst 203.0.113.4",
            "\tproto esp spi 0xd4c3b2a1 reqid 1 mode tunnel");

        var peers = IpsecEndpointGuard.ParseXfrmState(output);

        Assert.Contains("198.51.100.72", peers);
        Assert.Contains("203.0.113.4", peers);
        // The selector line carries 0.0.0.0/0 on both sides; taking it would shield the
        // entire internet from auto-block.
        Assert.DoesNotContain("0.0.0.0", peers);
    }

    [Fact]
    public void ParsesPeersFromSwanctlAndIpsecStatus()
    {
        var swanctl = string.Join('\n',
            "site-to-site: #1, ESTABLISHED, IKEv2, 1f2e3d4c5b6a7988_i* 8877665544332211_r",
            "  local  'CN=gateway' @ 203.0.113.4[500]",
            "  remote 'CN=branch'  @ 198.51.100.73[500]",
            "  AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384",
            "  net-net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256",
            "    local  10.0.0.0/24",
            "    remote 10.9.0.0/24");

        var fromSwanctl = IpsecEndpointGuard.ParseSaStatus(swanctl);
        Assert.Contains("198.51.100.73", fromSwanctl);
        Assert.Contains("203.0.113.4", fromSwanctl);
        // Tunnel subnets are not endpoints.
        Assert.DoesNotContain("10.9.0.0", fromSwanctl);

        var legacy = string.Join('\n',
            "Security Associations (1 up, 0 connecting):",
            "  site-to-site[1]: ESTABLISHED 41 minutes ago, 203.0.113.4[500]...198.51.100.74[500]",
            "  site-to-site{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c1a2b3c4_i d4c3b2a1_o");

        var fromLegacy = IpsecEndpointGuard.ParseSaStatus(legacy);
        Assert.Contains("198.51.100.74", fromLegacy);
        Assert.Contains("203.0.113.4", fromLegacy);
    }

    [Fact]
    public void ConnectionNamesAreNotMistakenForAddresses()
    {
        // "[1]" is a bracketed number just like a port, so the scan walks back into the
        // connection name. IPAddress.TryParse would read a trailing "123" as 0.0.0.123,
        // which is why the parser insists the text round-trips.
        var status = string.Join('\n',
            "  tunnel123[1]: ESTABLISHED 2 minutes ago",
            "  deadbeef[2]: CONNECTING");

        Assert.Empty(IpsecEndpointGuard.ParseSaStatus(status));
    }

    [Fact]
    public void ParsesPeersFromIpsecConf()
    {
        var conf = string.Join('\n',
            "conn site-to-site",
            "    left=203.0.113.4",
            "    leftsubnet=10.0.0.0/24",
            "    right=198.51.100.75",
            "    rightsubnet=0.0.0.0/0",
            "    rightsourceip=10.9.0.1",
            "    authby=secret",
            "    auto=start");

        var peers = IpsecEndpointGuard.ParseConfigPeers(conf);

        Assert.Contains("198.51.100.75", peers);
        Assert.Contains("203.0.113.4", peers);
        // rightsubnet=0.0.0.0/0 is the one that would be catastrophic, and rightsourceip
        // is an inner tunnel address rather than an endpoint. Neither key is read.
        Assert.DoesNotContain("0.0.0.0", peers);
        Assert.DoesNotContain("10.9.0.1", peers);
        Assert.DoesNotContain("10.0.0.0", peers);
    }

    [Fact]
    public void ParsesPeerListFromSwanctlConf()
    {
        var conf = string.Join('\n',
            "connections {",
            "    site-to-site {",
            "        local_addrs  = 203.0.113.4",
            "        remote_addrs = 198.51.100.76, 198.51.100.77",
            "        children {",
            "            net-net {",
            "                local_ts  = 10.0.0.0/24",
            "                remote_ts = 0.0.0.0/0",
            "            }",
            "        }",
            "    }",
            "}");

        var peers = IpsecEndpointGuard.ParseConfigPeers(conf);

        Assert.Contains("198.51.100.76", peers);
        Assert.Contains("198.51.100.77", peers);
        Assert.Contains("203.0.113.4", peers);
        // Traffic selectors are subnets, not endpoints.
        Assert.DoesNotContain("0.0.0.0", peers);
        Assert.DoesNotContain("10.0.0.0", peers);
    }

    [Fact]
    public void WildcardsHostnamesAndSecretsAreNotRead()
    {
        var conf = string.Join('\n',
            "conn roadwarrior",
            "    right=%any",
            "    left=vpn.example.org",
            "    # right=192.0.2.99",
            "    rightid=@branch.example.org",
            "    leftcert=gateway.pem");

        // %any names no address; a hostname is deliberately not resolved, because whoever
        // answers DNS could otherwise write themselves into a never-block list.
        Assert.Empty(IpsecEndpointGuard.ParseConfigPeers(conf));
    }

    [Fact]
    public void SamplingIsSafeWithoutIpsecOrRoot()
    {
        // CI has no tunnel and no CAP_NET_ADMIN: the pass must not throw, and must not
        // silently drop what it already knows.
        var guard = new IpsecEndpointGuard();
        guard.Remember("198.51.100.78");

        guard.SampleOnce();

        Assert.True(guard.IsProtected("198.51.100.78"));
        Assert.False(string.IsNullOrWhiteSpace(guard.Status));
    }
}
