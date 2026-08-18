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
/// and it must never learn a *subnet*, because a connection-security rule routinely
/// carries 0.0.0.0/0 and a shield that swallowed one would disable auto-block entirely.
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

        // A wildcard SA or an "any" endpoint yields these; they are not peers.
        guard.Remember("0.0.0.0");
        guard.Remember("::");
        Assert.False(guard.IsProtected("0.0.0.0"));
        Assert.False(guard.IsProtected("::"));
    }

    [Fact]
    public void PeersSurviveARestart()
    {
        // The window that matters: the tunnel has already dropped, so there is no SA to
        // read, and a fresh process must still refuse to block the address that would
        // bring it back.
        var guard = new IpsecEndpointGuard();
        guard.Remember("198.51.100.71");
        guard.Stop();   // flushes the state file

        var restarted = new IpsecEndpointGuard();
        Assert.True(restarted.IsProtected("198.51.100.71"));
    }

    [Fact]
    public void ParsesBothEndsOfALiveSecurityAssociation()
    {
        // `netsh advfirewall monitor show mmsa`, trimmed. Which end is the peer depends on
        // who initiated, and this host's own address is refused by the prevention engine
        // independently, so both are kept.
        var output = string.Join('\n',
            "Main Mode SA at 08/18/2026 09:14:03",
            "----------------------------------------------------------------------",
            "Local IP Address:                     203.0.113.4",
            "Remote IP Address:                    198.51.100.72",
            "Auth1:                                ComputerCert",
            "Encryption:                           AES-CBC 128",
            "Integrity:                            SHA-256",
            "");

        var peers = IpsecEndpointGuard.ParseAddresses(output);

        Assert.Contains("198.51.100.72", peers);
        Assert.Contains("203.0.113.4", peers);
    }

    [Fact]
    public void ParsesEndpointsFromAConnectionSecurityRule()
    {
        // The Windows analogue of reading ipsec.conf: the rule names the far end whether or
        // not a tunnel is established.
        var output = string.Join('\n',
            "Rule Name:                            Branch office tunnel",
            "----------------------------------------------------------------------",
            "Enabled:                              Yes",
            "Profiles:                             Domain,Private,Public",
            "Endpoint1:                            203.0.113.4",
            "Endpoint2:                            198.51.100.73",
            "Mode:                                 Tunnel",
            "Action:                               RequireInRequireOut",
            "");

        var peers = IpsecEndpointGuard.ParseAddresses(output);

        Assert.Contains("198.51.100.73", peers);
        Assert.Contains("203.0.113.4", peers);
    }

    [Fact]
    public void SelectorsAndPoolsAreNeverTakenAsEndpoints()
    {
        // The catastrophic case: a tunnel rule's remote endpoint can be a whole subnet, and
        // 0.0.0.0/0 in a never-block list would disable auto-block for the entire internet.
        var output = string.Join('\n',
            "Endpoint1:                            10.0.0.0/24",
            "Endpoint2:                            0.0.0.0/0",
            "Remote Tunnel Endpoint:               198.51.100.1-198.51.100.9",
            "Port:                                 500");

        Assert.Empty(IpsecEndpointGuard.ParseAddresses(output));
    }

    [Fact]
    public void ARuleNameIsNeverMistakenForAnAddress()
    {
        // A rule name is operator-chosen text and can be anything, so the name line is
        // skipped outright. Elsewhere, IPAddress.TryParse would read a bare "123" as
        // 0.0.0.123, which is why the parser insists the text round-trips.
        var output = string.Join('\n',
            "Rule Name:                            198.51.100.90",
            "Auth1:                                ComputerCert",
            "Key Lifetime:                         480min,0sess",
            "Version:                              2");

        Assert.Empty(IpsecEndpointGuard.ParseAddresses(output));
    }

    [Fact]
    public void ParsesTheDestinationOfAnRrasDemandDialInterface()
    {
        // router.pbk: an RRAS site-to-site interface. PhoneNumber is the far end.
        var pbk = string.Join('\n',
            "[Branch office]",
            "Encoding=1",
            "Type=2",
            "VpnStrategy=7",
            "PhoneNumber=198.51.100.75",
            "IpAddress=10.9.0.1",
            "IpDnsAddress=10.9.0.53",
            "Device=WAN Miniport (IKEv2)");

        var peers = IpsecEndpointGuard.ParsePhonebookPeers(pbk);

        Assert.Contains("198.51.100.75", peers);
        // The inner tunnel address and the tunnelled DNS server are not endpoints — and
        // being private, they would never be auto-blocked anyway.
        Assert.DoesNotContain("10.9.0.1", peers);
        Assert.DoesNotContain("10.9.0.53", peers);
    }

    [Fact]
    public void HostnamesAndPoolsInAPhonebookContributeNothing()
    {
        var pbk = string.Join('\n',
            "[Work VPN]",
            "PhoneNumber=vpn.example.org",
            "[Range]",
            "PhoneNumber=198.51.100.1-198.51.100.9");

        // A hostname is deliberately not resolved, because whoever answers DNS could
        // otherwise write their own address into a never-block list.
        Assert.Empty(IpsecEndpointGuard.ParsePhonebookPeers(pbk));
    }

    [Fact]
    public void AnElevationRefusalIsNotReadAsAnEmptyResult()
    {
        // netsh prints this on stdout and still exits 0, so an unelevated run would
        // otherwise parse to "no addresses" and the guard would report that this host has
        // no IPSec — the exact silence it exists to avoid.
        const string refusal = "The requested operation requires elevation (Run as administrator).";

        Assert.Empty(IpsecEndpointGuard.ParseAddresses(refusal));
        Assert.Contains("elevation", refusal, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SamplingIsSafeWithoutIpsecOrAdministrator()
    {
        // CI has no tunnel and no elevation: the pass must not throw, and must not
        // silently drop what it already knows.
        var guard = new IpsecEndpointGuard();
        guard.Remember("198.51.100.78");

        guard.SampleOnce();

        Assert.True(guard.IsProtected("198.51.100.78"));
        Assert.False(string.IsNullOrWhiteSpace(guard.Status));

        // Never "no IPSec configuration" from a run that could not look. The unelevated
        // path says so, and says why it is not alarming: a process that cannot read the
        // tunnel state cannot write a firewall rule either.
        Assert.DoesNotContain("No IPSec configuration on this host", guard.Status);
    }
}
