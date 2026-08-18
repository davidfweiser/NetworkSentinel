using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The host firewall scan: what UFW, nftables, iptables and ss actually print,
/// and what the Firewall Config view makes of it.
///
/// Every fixture below is real output, because the whole point of the scan is
/// that the page shows the firewall the machine has rather than the ledger this
/// app keeps. A parser that only handles output we invented would put us back
/// where we started, with a confident list that is not the firewall.
/// </summary>
public class HostFirewallScanTests
{
    // ── ufw status verbose ───────────────────────────────────────────────

    private const string UfwStatus = """
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
3306/tcp                   ALLOW IN    10.0.0.0/8
Anywhere                   DENY IN     203.0.113.44
53                         ALLOW OUT   Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
""";

    [Fact]
    public void UfwStatus_ReadsStatusAndDefaultPolicies()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);

        Assert.True(scan.Enabled);
        Assert.Equal("Enabled", scan.Status);
        Assert.Equal("Drop", scan.DefaultInbound);
        Assert.Equal("Accept", scan.DefaultOutbound);
    }

    [Fact]
    public void UfwStatus_SplitsRulesByDirection()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);

        Assert.Equal(5, scan.Inbound.Count);
        Assert.Single(scan.Outbound);
        Assert.Equal("53", scan.Outbound[0].LocalPorts);
    }

    [Fact]
    public void UfwStatus_ReadsPortProtocolAndSource()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);
        var mysql = scan.Inbound.Single(r => r.LocalPorts == "3306");

        Assert.Equal("TCP", mysql.Protocol);
        Assert.Equal("10.0.0.0/8", mysql.RemoteAddresses);
        Assert.False(mysql.IsBlock);
    }

    [Fact]
    public void UfwStatus_MultiPortRuleKeepsBothPorts()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);
        var web = scan.Inbound.Single(r => r.LocalPorts.Contains("443"));

        Assert.Equal("80, 443", web.LocalPorts);
        Assert.Equal("TCP", web.Protocol);
    }

    [Fact]
    public void UfwStatus_DenyRuleIsABlock()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);
        var deny = scan.Inbound.Single(r => r.RemoteAddresses == "203.0.113.44");

        Assert.True(deny.IsBlock);
        Assert.Equal("Block", deny.ActionText);
        // "Anywhere" in the To column is every port, not a port called Anywhere.
        Assert.Equal("", deny.LocalPorts);
    }

    [Fact]
    public void UfwStatus_V6TwinIsKeptSeparately()
    {
        var scan = HostFirewallScanner.ParseUfwStatus(UfwStatus);
        var v6 = scan.Inbound.Single(r => r.RemoteAddresses == "All IPv6");

        Assert.Equal("22", v6.LocalPorts);
        Assert.Equal("ip6", v6.Family);
    }

    [Fact]
    public void UfwStatus_InactiveFirewallStillReportsDefaults()
    {
        var scan = HostFirewallScanner.ParseUfwStatus("Status: inactive\n");

        Assert.False(scan.Enabled);
        Assert.Equal("Disabled", scan.Status);
        Assert.Empty(scan.Inbound);
    }

    // ── /etc/ufw/user.rules ──────────────────────────────────────────────

    private const string UfwUserRules = """
*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### deny tcp 23 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 23 -j DROP

### tuple ### allow udp 53 0.0.0.0/0 any 0.0.0.0/0 out
-A ufw-user-output -p udp --dport 53 -j ACCEPT
COMMIT
""";

    [Fact]
    public void UfwUserRules_ParsedWhenStatusNeedsRootWeDoNotHave()
    {
        var scan = HostFirewallScanner.ParseUfwUserRules(UfwUserRules);

        Assert.Equal(2, scan.Inbound.Count);
        Assert.Single(scan.Outbound);
    }

    [Fact]
    public void UfwUserRules_TupleCommentSuppliesTheVerdict()
    {
        var scan = HostFirewallScanner.ParseUfwUserRules(UfwUserRules);

        Assert.False(scan.Inbound.Single(r => r.LocalPorts == "22").IsBlock);
        Assert.True(scan.Inbound.Single(r => r.LocalPorts == "23").IsBlock);
    }

    [Fact]
    public void UfwUserRules_OutputChainIsOutbound()
    {
        var scan = HostFirewallScanner.ParseUfwUserRules(UfwUserRules);

        Assert.Equal(FirewallDirection.Outbound, scan.Outbound[0].Direction);
        Assert.Equal("UDP", scan.Outbound[0].Protocol);
    }

    // ── nft -j list ruleset ──────────────────────────────────────────────

    private const string NftJson = """
{"nftables":[
 {"metainfo":{"version":"1.0.6","json_schema_version":1}},
 {"table":{"family":"inet","name":"filter","handle":1}},
 {"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
 {"chain":{"family":"inet","table":"filter","name":"output","handle":2,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
 {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
   {"counter":{"packets":0,"bytes":0}},
   {"accept":null}]}},
 {"rule":{"family":"inet","table":"filter","chain":"input","handle":7,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"203.0.113.44"}},
   {"comment":"NetworkSentinel-IP-203.0.113.44-In"},
   {"drop":null}]}},
 {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[60000,61000]}}},
   {"accept":null}]}},
 {"rule":{"family":"inet","table":"filter","chain":"output","handle":11,"expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[25,465]}}},
   {"drop":null}]}}
]}
""";

    [Fact]
    public void NftJson_ReadsChainPoliciesAsDefaults()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;

        Assert.Equal("Drop", scan.DefaultInbound);
        Assert.Equal("Accept", scan.DefaultOutbound);
    }

    [Fact]
    public void NftJson_ReadsPortProtocolAndVerdict()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;
        var ssh = scan.Inbound.Single(r => r.LocalPorts == "22");

        Assert.Equal("TCP", ssh.Protocol);
        Assert.False(ssh.IsBlock);
        Assert.Equal("4", ssh.Handle);
    }

    [Fact]
    public void NftJson_KeepsTheHandleADeleteNeeds()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;
        var block = scan.Inbound.Single(r => r.RemoteAddresses == "203.0.113.44");

        Assert.Equal("7", block.Handle);
        Assert.Equal("inet", block.Family);
        Assert.Equal("filter", block.Table);
        Assert.Equal("input", block.Chain);
        Assert.True(block.IsBlock);
    }

    [Fact]
    public void NftJson_RendersAPortRange()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;

        Assert.Contains(scan.Inbound, r => r.LocalPorts == "60000-61000" && r.Protocol == "UDP");
    }

    [Fact]
    public void NftJson_RendersAPortSet()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;

        Assert.Equal("25, 465", scan.Outbound.Single().LocalPorts);
    }

    [Fact]
    public void NftJson_CommentBecomesTheLabel()
    {
        var scan = HostFirewallScanner.ParseNftJson(NftJson)!;
        var block = scan.Inbound.Single(r => r.RemoteAddresses == "203.0.113.44");

        Assert.Equal("NetworkSentinel-IP-203.0.113.44-In", block.LabelText);
    }

    [Fact]
    public void NftJson_SkipsUfwPlumbingChains()
    {
        const string json = """
{"nftables":[
 {"chain":{"family":"inet","table":"filter","name":"ufw-track-input","handle":3,"type":"filter"}},
 {"rule":{"family":"inet","table":"filter","chain":"ufw-track-input","handle":5,"expr":[{"accept":null}]}}
]}
""";
        var scan = HostFirewallScanner.ParseNftJson(json)!;

        Assert.Empty(scan.Inbound);
        Assert.Empty(scan.Outbound);
    }

    [Fact]
    public void NftJson_SkipsAJumpIntoUfwsOwnChains()
    {
        const string json = """
{"nftables":[
 {"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
 {"rule":{"family":"inet","table":"filter","chain":"input","handle":2,"expr":[{"jump":{"target":"ufw-before-input"}}]}}
]}
""";
        var scan = HostFirewallScanner.ParseNftJson(json)!;

        Assert.Empty(scan.Inbound);
    }

    // ── iptables -S ──────────────────────────────────────────────────────

    private const string IptablesSave = """
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 203.0.113.44/32 -j DROP
-A INPUT -p tcp -m multiport --dports 80,443 -m comment --comment "web" -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
""";

    [Fact]
    public void IptablesSave_ReadsPoliciesAndRules()
    {
        var scan = HostFirewallScanner.ParseIptablesSave(IptablesSave);

        Assert.Equal("Drop", scan.DefaultInbound);
        Assert.Equal("Accept", scan.DefaultOutbound);
        Assert.Equal(3, scan.Inbound.Count);
        Assert.Single(scan.Outbound);
    }

    [Fact]
    public void IptablesSave_ReadsMultiportAndComment()
    {
        var scan = HostFirewallScanner.ParseIptablesSave(IptablesSave);
        var web = scan.Inbound.Single(r => r.LabelText == "web");

        Assert.Equal("80, 443", web.LocalPorts);
        Assert.Equal("TCP", web.Protocol);
    }

    [Fact]
    public void IptablesSave_ReadsASourceBlock()
    {
        var scan = HostFirewallScanner.ParseIptablesSave(IptablesSave);
        var block = scan.Inbound.Single(r => r.RemoteAddresses == "203.0.113.44/32");

        Assert.True(block.IsBlock);
    }

    // ── ss -tulpnH ───────────────────────────────────────────────────────

    private const string SsOutput = """
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511          127.0.0.1:3306     0.0.0.0:*    users:(("mariadbd",pid=1140,fd=20))
tcp   LISTEN 0      4096            [::]:18765         [::]:*    users:(("NetworkSentinel",pid=2201,fd=9))
udp   UNCONN 0      0            0.0.0.0:51820      0.0.0.0:*
""";

    [Fact]
    public void Ss_ReadsProcessAddressAndPort()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);

        Assert.Equal(4, listeners.Count);
        var ssh = listeners.Single(l => l.Port == "22");
        Assert.Equal("sshd", ssh.Process);
        Assert.Equal("0.0.0.0", ssh.Address);
        Assert.Equal("TCP", ssh.Protocol);
    }

    [Fact]
    public void Ss_ReadsAnIpv6BindAddress()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);
        var console = listeners.Single(l => l.Port == "18765");

        Assert.Equal("::", console.Address);
    }

    [Fact]
    public void Ss_ASocketWithNoProcessColumnStillCounts()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);
        var wireguard = listeners.Single(l => l.Port == "51820");

        Assert.Equal("UDP", wireguard.Protocol);
        Assert.Equal("—", wireguard.Process);
    }

    // ── Coverage ─────────────────────────────────────────────────────────

    [Fact]
    public void Coverage_MarksAnAdmittedPortOpen()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);
        var inbound = HostFirewallScanner.ParseUfwStatus(UfwStatus).Inbound;

        HostFirewallScanner.AnnotateCoverage(listeners, inbound, firewallEnabled: true);

        Assert.Equal("Open", listeners.Single(l => l.Port == "22").Covered);
    }

    [Fact]
    public void Coverage_MarksALoopbackSocketLocalOnly()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);
        var inbound = HostFirewallScanner.ParseUfwStatus(UfwStatus).Inbound;

        HostFirewallScanner.AnnotateCoverage(listeners, inbound, firewallEnabled: true);

        // MariaDB binds 127.0.0.1, so the 3306 allow rule above is beside the point.
        Assert.Equal("Local only", listeners.Single(l => l.Port == "3306").Covered);
    }

    [Fact]
    public void Coverage_MarksAnUnadmittedListenerNotAllowed()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);
        var inbound = HostFirewallScanner.ParseUfwStatus(UfwStatus).Inbound;

        HostFirewallScanner.AnnotateCoverage(listeners, inbound, firewallEnabled: true);

        // Nothing in the rule set admits 18765 — the console is listening into a
        // closed door, which is exactly what this column exists to say.
        Assert.Equal("Not allowed", listeners.Single(l => l.Port == "18765").Covered);
    }

    [Fact]
    public void Coverage_MarksASourceScopedRuleRestricted()
    {
        var listeners = HostFirewallScanner.ParseSs("tcp LISTEN 0 511 0.0.0.0:3306 0.0.0.0:* users:((\"mariadbd\",pid=1,fd=1))");
        var inbound = HostFirewallScanner.ParseUfwStatus(UfwStatus).Inbound;

        HostFirewallScanner.AnnotateCoverage(listeners, inbound, firewallEnabled: true);

        // 3306 is allowed, but only from 10.0.0.0/8.
        Assert.Equal("Restricted", listeners[0].Covered);
    }

    [Fact]
    public void Coverage_SaysSoWhenThereIsNoFirewall()
    {
        var listeners = HostFirewallScanner.ParseSs(SsOutput);

        HostFirewallScanner.AnnotateCoverage(listeners, Array.Empty<FirewallRuleInfo>(), firewallEnabled: false);

        Assert.Equal("No firewall", listeners.Single(l => l.Port == "22").Covered);
    }

    // ── Folding ──────────────────────────────────────────────────────────

    [Fact]
    public void Dedupe_DropsTheSameRuleSeenThroughTwoBackends()
    {
        // iptables-nft and nft both report the ruleset; the same rule must not
        // appear twice just because two tools were asked about it.
        var viaNft = HostFirewallScanner.ParseNftJson(NftJson)!.Inbound;
        var again = HostFirewallScanner.ParseNftJson(NftJson)!.Inbound;

        var folded = HostFirewallScanner.Dedupe(viaNft.Concat(again));

        Assert.Equal(viaNft.Count, folded.Count);
    }

    [Fact]
    public void Plumbing_UfwHelperChainsAreNotListedAsRules()
    {
        var scan = HostFirewallScanner.ParseIptablesSave("-A ufw-before-input -p tcp --dport 22 -j ACCEPT");

        // The parser keeps it — UFW's own chains are read so their rules can be
        // shown — and the fold drops it as plumbing.
        Assert.All(scan.Inbound, r => Assert.True(HostFirewallScanner.IsPlumbing(r)));
    }

    [Fact]
    public void Plumbing_ABareInputAcceptIsNoise()
    {
        var rule = HostFirewallScanner.ParseIptablesLine("-A INPUT -j ACCEPT", "iptables", "ip", "iptables");

        Assert.NotNull(rule);
        Assert.True(HostFirewallScanner.IsPlumbing(rule!));
    }

    [Fact]
    public void Plumbing_ARealRuleIsNotNoise()
    {
        var rule = HostFirewallScanner.ParseIptablesLine(
            "-A INPUT -p tcp --dport 22 -j ACCEPT", "iptables", "ip", "iptables");

        Assert.NotNull(rule);
        Assert.False(HostFirewallScanner.IsPlumbing(rule!));
    }
}
