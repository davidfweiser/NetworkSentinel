using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The Firewall Config rule pipeline: what the operator types, what nftables or
/// iptables is asked to load, and what the console refuses to write in the first
/// place.
/// </summary>
public class FirewallRuleSpecTests
{
    private static FirewallRuleSpec Spec(
        string action = FirewallRuleSpecs.ActionBlock,
        string direction = FirewallRuleSpecs.DirectionInbound,
        string protocol = "TCP",
        string ports = "22",
        string addresses = "",
        string label = "") => new()
    {
        Action = action,
        Direction = direction,
        Protocol = protocol,
        PortRange = ports,
        Addresses = addresses,
        Label = label
    };

    private static FirewallRuleInfo Rule(FirewallRuleSpec spec)
        => FirewallRuleSpecs.ToRule(spec, "NetworkSentinel-Rule-test");

    private static string OneNft(FirewallRuleSpec spec)
        => Assert.Single(FirewallRuleSpecs.BuildNftMatches(Rule(spec))).Match;

    private static string OneIptables(FirewallRuleSpec spec)
        => Assert.Single(FirewallRuleSpecs.BuildIptablesMatches(Rule(spec))).Match;

    // ── Ports ────────────────────────────────────────────────────────────

    [Fact]
    public void PortListAndRangeBecomeCanonicalTokens()
    {
        Assert.True(FirewallRuleSpecs.TryParsePorts("80, 443", out var list, out _));
        Assert.Equal(new[] { "80", "443" }, list);

        // The canonical token spells a range with a colon; the form takes the
        // friendlier dash, and each backend renderer converts back.
        Assert.True(FirewallRuleSpecs.TryParsePorts("8000-8001", out var range, out _));
        Assert.Equal(new[] { "8000:8001" }, range);
    }

    [Fact]
    public void EmptyPortFieldMeansEveryPort()
    {
        Assert.True(FirewallRuleSpecs.TryParsePorts("", out var ports, out _));
        Assert.Empty(ports);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("443-80")]
    public void BadPortsAreRejectedWithAReason(string text)
    {
        Assert.False(FirewallRuleSpecs.TryParsePorts(text, out _, out var error));
        Assert.NotEqual("", error);
    }

    // ── Addresses ────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("any")]
    [InlineData("All IPv4, All IPv6")]
    [InlineData("0.0.0.0/0")]
    public void AnyAddressParsesToAnEmptyList(string text)
    {
        Assert.True(FirewallRuleSpecs.TryParseAddresses(text, out var addresses, out _));
        Assert.Empty(addresses);
    }

    [Fact]
    public void AddressesAndNetworksSurviveNormalization()
    {
        Assert.True(FirewallRuleSpecs.TryParseAddresses("10.0.0.0/8, 203.0.113.5", out var addresses, out _));
        Assert.Equal(new[] { "10.0.0.0/8", "203.0.113.5" }, addresses);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.1/abc")]
    public void BadAddressesAreRejected(string text)
    {
        Assert.False(FirewallRuleSpecs.TryParseAddresses(text, out _, out var error));
        Assert.NotEqual("", error);
    }

    [Theory]
    [InlineData("2001:db8::1", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("203.0.113.5", false)]
    [InlineData("10.0.0.0/8", false)]
    public void AddressFamilyIsReadFromTheToken(string token, bool isV6)
        => Assert.Equal(isV6, FirewallRuleSpecs.IsV6Address(token));

    // ── Labels ───────────────────────────────────────────────────────────

    [Fact]
    public void BlankLabelIsMintedFromTheService()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(ports: "22"));
        Assert.Equal("block-inbound-ssh", spec.Label);
    }

    [Fact]
    public void MintedLabelFallsBackToThePortNumber()
    {
        var spec = FirewallRuleSpecs.Normalize(
            Spec(action: FirewallRuleSpecs.ActionAllow,
                 direction: FirewallRuleSpecs.DirectionOutbound, ports: "9999"));
        Assert.Equal("allow-outbound-9999", spec.Label);
    }

    [Fact]
    public void OperatorLabelIsKeptButStrippedOfWhitespaceAndPunctuation()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(label: "office VPN (only)"));
        Assert.Equal("office-VPN-only", spec.Label);
    }

    // ── Validation ───────────────────────────────────────────────────────

    [Fact]
    public void AValidRulePassesValidation()
        => Assert.Equal("", FirewallRuleSpecs.Validate(FirewallRuleSpecs.Normalize(Spec())));

    [Fact]
    public void AllowEverythingIsRefused()
    {
        // Protocol Any, no port, no address: an accept rule that matches all traffic.
        var spec = FirewallRuleSpecs.Normalize(
            Spec(action: FirewallRuleSpecs.ActionAllow, protocol: "Any", ports: "", addresses: ""));
        Assert.Contains("allow all traffic", FirewallRuleSpecs.Validate(spec));
    }

    [Fact]
    public void BlockEverythingIsAllowedButFlaggedAsCatchAll()
    {
        // The same shape as a block is legitimate (and drastic) — it validates, and
        // the view model confirms it with the operator instead.
        var spec = FirewallRuleSpecs.Normalize(Spec(protocol: "Any", ports: "", addresses: ""));
        Assert.Equal("", FirewallRuleSpecs.Validate(spec));
        Assert.True(FirewallRuleSpecs.IsCatchAll(spec));
    }

    [Fact]
    public void IcmpWithPortsIsRefused()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(protocol: "ICMP", ports: "22"));
        Assert.Contains("ICMP has no ports", FirewallRuleSpecs.Validate(spec));
    }

    [Fact]
    public void PortRangeCoverageIsInclusive()
    {
        var spec = FirewallRuleSpecs.Normalize(Spec(ports: "20-25"));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 22));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 20));
        Assert.True(FirewallRuleSpecs.CoversPort(spec, 25));
        Assert.False(FirewallRuleSpecs.CoversPort(spec, 26));

        // No port range at all means every port, SSH included.
        Assert.True(FirewallRuleSpecs.CoversPort(FirewallRuleSpecs.Normalize(Spec(ports: "")), 22));
    }

    // ── nftables rendering ───────────────────────────────────────────────

    [Fact]
    public void InboundBlockFiltersOnTheSourceAndTheLocalPort()
        => Assert.Equal("ip saddr 203.0.113.5 tcp dport 22", OneNft(Spec(addresses: "203.0.113.5")));

    [Fact]
    public void OutboundRuleFiltersOnTheDestinationAndTheRemotePort()
    {
        // "Outbound to port 443" means the service being reached, which is what UFW's
        // `allow out … port 443` does — not the local source port.
        Assert.Equal("ip daddr 198.51.100.7 tcp dport 443", OneNft(Spec(
            action: FirewallRuleSpecs.ActionAllow,
            direction: FirewallRuleSpecs.DirectionOutbound,
            ports: "443",
            addresses: "198.51.100.7")));
    }

    [Fact]
    public void ListsAreBracedAndSingleValuesAreNot()
        => Assert.Equal(
            "ip saddr { 10.0.0.0/8, 192.168.1.5 } tcp dport { 80, 443 }",
            OneNft(Spec(ports: "80, 443", addresses: "10.0.0.0/8, 192.168.1.5")));

    [Fact]
    public void AnyProtocolAndAnyAddressDropTheirClauses()
        => Assert.Equal("", OneNft(Spec(protocol: "Any", ports: "", addresses: "")));

    [Fact]
    public void IcmpRuleCarriesNoPortClause()
    {
        // With no address to pin the family, an inet-table rule has to name both ICMPs.
        Assert.Equal("meta l4proto { icmp, icmpv6 }", OneNft(Spec(protocol: "ICMP", ports: "")));
        Assert.Equal("ip saddr 203.0.113.5 meta l4proto icmp",
            OneNft(Spec(protocol: "ICMP", ports: "", addresses: "203.0.113.5")));
        Assert.Equal("ip6 saddr 2001:db8::1 meta l4proto icmpv6",
            OneNft(Spec(protocol: "ICMP", ports: "", addresses: "2001:db8::1")));
    }

    [Fact]
    public void RangesUseNftDashSyntaxInTheRule()
        => Assert.Contains("dport 8000-8001", OneNft(Spec(ports: "8000-8001")));

    [Fact]
    public void MixedAddressFamiliesSplitIntoOneRulePerFamily()
    {
        // Neither backend matches a v4 and a v6 address in the same rule.
        var matches = FirewallRuleSpecs.BuildNftMatches(Rule(Spec(addresses: "203.0.113.5, 2001:db8::1")));

        Assert.Equal(2, matches.Count);
        Assert.Equal("ip saddr 203.0.113.5 tcp dport 22", matches[0].Match);
        Assert.Equal("ip6 saddr 2001:db8::1 tcp dport 22", matches[1].Match);
    }

    [Fact]
    public void PortsUnderProtocolAnySplitIntoTcpAndUdp()
    {
        // A port match without a protocol is not expressible in iptables, so "Any
        // protocol, port 5353" becomes the two rules the operator meant.
        var matches = FirewallRuleSpecs.BuildNftMatches(Rule(Spec(protocol: "Any", ports: "5353")));

        Assert.Equal(new[] { "tcp dport 5353", "udp dport 5353" }, matches.Select(m => m.Match));
    }

    // ── iptables rendering ───────────────────────────────────────────────

    [Fact]
    public void IptablesInboundRuleMatchesTheSource()
        => Assert.Equal("-p tcp -s 203.0.113.5 --dport 22", OneIptables(Spec(addresses: "203.0.113.5")));

    [Fact]
    public void IptablesOutboundRuleMatchesTheDestination()
        => Assert.Equal("-p tcp -d 198.51.100.7 --dport 443", OneIptables(Spec(
            direction: FirewallRuleSpecs.DirectionOutbound, ports: "443", addresses: "198.51.100.7")));

    [Fact]
    public void IptablesUsesMultiportForListsAndRanges()
    {
        Assert.Equal("-p tcp -m multiport --dports 80,443", OneIptables(Spec(ports: "80, 443")));
        Assert.Equal("-p tcp -m multiport --dports 8000:8001", OneIptables(Spec(ports: "8000-8001")));
    }

    [Fact]
    public void IptablesSplitsAnAddressListIntoOneRuleEach()
    {
        // iptables takes a single address per rule, and a v6 address has to go to
        // ip6tables or it is rejected outright.
        var matches = FirewallRuleSpecs.BuildIptablesMatches(
            Rule(Spec(addresses: "203.0.113.5, 198.51.100.7, 2001:db8::1")));

        Assert.Equal(3, matches.Count);
        Assert.Equal(new[] { false, false, true }, matches.Select(m => m.IsV6));
        Assert.Equal("-p tcp -s 2001:db8::1 --dport 22", matches[2].Match);
    }

    [Fact]
    public void IptablesIcmpPicksTheFamilysProtocolName()
    {
        Assert.Equal("-p icmp", OneIptables(Spec(protocol: "ICMP", ports: "")));
        Assert.Equal("-p icmpv6 -s 2001:db8::1",
            OneIptables(Spec(protocol: "ICMP", ports: "", addresses: "2001:db8::1")));
    }

    [Fact]
    public void IptablesAnyProtocolAndAnyAddressRenderAnEmptyBody()
        => Assert.Equal("", OneIptables(Spec(protocol: "Any", ports: "", addresses: "")));

    // ── Round trip ───────────────────────────────────────────────────────

    [Fact]
    public void EditingARuleRecoversTheFormItWasWrittenFrom()
    {
        var original = FirewallRuleSpecs.Normalize(Spec(
            action: FirewallRuleSpecs.ActionAllow,
            direction: FirewallRuleSpecs.DirectionOutbound,
            protocol: "UDP",
            ports: "51820",
            addresses: "198.51.100.7",
            label: "wireguard-peer"));

        var restored = FirewallRuleSpecs.FromRule(Rule(original));

        Assert.Equal(original.Label, restored.Label);
        Assert.Equal(original.Action, restored.Action);
        Assert.Equal(original.Direction, restored.Direction);
        Assert.Equal(original.Protocol, restored.Protocol);
        Assert.Equal(original.PortRange, restored.PortRange);
        Assert.Equal(original.Addresses, restored.Addresses);
    }

    // ── Precedence ───────────────────────────────────────────────────────

    [Fact]
    public void AppMintedBlocksAreWrittenAheadOfConfigRules()
    {
        // The chains are first-match-wins and rules are added one at a time, so
        // ledger order decides nothing: a config Allow written today would sit
        // ahead of a block auto-block appends tomorrow. Inserting app blocks at the
        // head and appending config rules is what keeps the Allow from reopening an
        // address auto-block just shut.
        Assert.Equal("insert", FirewallService.NftAddVerb(FirewallRuleKind.IpBlock));
        Assert.Equal("insert", FirewallService.NftAddVerb(FirewallRuleKind.PortBlock));
        Assert.Equal("add", FirewallService.NftAddVerb(FirewallRuleKind.Custom));

        Assert.Equal("-I INPUT 1", FirewallService.IptablesChainClause(FirewallRuleKind.IpBlock, "INPUT"));
        Assert.Equal("-I OUTPUT 1", FirewallService.IptablesChainClause(FirewallRuleKind.PortBlock, "OUTPUT"));
        Assert.Equal("-A INPUT", FirewallService.IptablesChainClause(FirewallRuleKind.Custom, "INPUT"));
    }

    // ── Validate-before-normalise ────────────────────────────────────────

    [Fact]
    public void AnUnparseablePortRangeIsRejectedRatherThanTurnedIntoEveryPort()
    {
        // Normalize re-renders the port field from what parsed and drops what did
        // not, and an empty port field means EVERY port. Validating the normalized
        // spec therefore accepted "block 443-80" and armed a catch-all block.
        var typed = Spec(ports: "443-80");

        Assert.False(FirewallRuleSpecs.TryPrepare(typed, out _, out var error));
        Assert.Contains("starts after it ends", error);

        // The shape of the bug, pinned so it cannot come back: normalising first
        // really does produce a catch-all that passes validation.
        var normalizedFirst = FirewallRuleSpecs.Normalize(typed);
        Assert.Equal("", normalizedFirst.PortRange);
        Assert.True(FirewallRuleSpecs.IsCatchAll(normalizedFirst));
        Assert.Equal("", FirewallRuleSpecs.Validate(normalizedFirst));
    }

    [Fact]
    public void AnUnparseableAddressIsRejectedRatherThanWidenedToEveryAddress()
    {
        Assert.False(FirewallRuleSpecs.TryPrepare(Spec(addresses: "not-an-ip"), out _, out var error));
        Assert.Contains("Invalid address", error);
    }

    [Fact]
    public void TryPrepareReturnsTheCanonicalFormWhenTheInputIsGood()
    {
        Assert.True(FirewallRuleSpecs.TryPrepare(
            Spec(action: "block", protocol: "tcp", ports: "8000-8001"), out var spec, out var error));

        Assert.Equal("", error);
        Assert.Equal(FirewallRuleSpecs.ActionBlock, spec.Action);
        Assert.Equal("TCP", spec.Protocol);
        Assert.Equal("8000-8001", spec.PortRange);
        Assert.False(FirewallRuleSpecs.IsCatchAll(spec));
    }

    [Fact]
    public void ConfigRulesCarryTheirOwnKindAndOrigin()
    {
        var rule = Rule(Spec(label: "allow-https", action: FirewallRuleSpecs.ActionAllow, ports: "443"));

        Assert.Equal(FirewallRuleKind.Custom, rule.Kind);
        Assert.True(rule.IsCustom);
        Assert.Equal("Firewall config", rule.OriginText);
        Assert.Equal("allow-https", rule.LabelText);
        Assert.Equal("Allow", rule.ActionText);
        Assert.Equal(FirewallRuleSpecs.AnyAddressText, rule.AddressListText);
    }
}

/// <summary>
/// Managed iptables rules are deleted by their full specification, read back from
/// <c>iptables -S</c>, never by a line number that can shift between list and delete.
/// </summary>
public class IptablesDeleteSpecTests
{
    private const string Listing = """
-P INPUT ACCEPT
-A INPUT -j ufw-before-input
-A INPUT -s 203.0.113.9/32 -m comment --comment NetworkSentinel-IP-203_0_113_9-In -j DROP
-A INPUT -p tcp -m tcp --dport 22 -m comment --comment NetworkSentinel-Rule-SSH -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -m comment --comment NetworkSentinel-Rule-SSH-2 -j ACCEPT
-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -m limit --limit 50/sec -m comment --comment NetworkSentinel-ProbeLog -j LOG --log-prefix "NS-PROBE "
-A OUTPUT -d 203.0.113.9/32 -m comment --comment NetworkSentinel-IP-203_0_113_9-Out -j DROP
""";

    [Fact]
    public void BuildsADeleteFromTheListedSpec()
    {
        var spec = Assert.Single(FirewallService.IptablesDeleteSpecs(Listing, "INPUT", "NetworkSentinel-IP-203_0_113_9-In"));
        Assert.Equal(
            new[] { "-D", "INPUT", "-s", "203.0.113.9/32", "-m", "comment", "--comment", "NetworkSentinel-IP-203_0_113_9-In", "-j", "DROP" },
            spec);
    }

    [Fact]
    public void MatchesTheWholeCommentOnly()
    {
        var spec = Assert.Single(FirewallService.IptablesDeleteSpecs(Listing, "INPUT", "NetworkSentinel-Rule-SSH"));
        Assert.Contains("22", spec);
        Assert.DoesNotContain("2222", spec);
    }

    [Fact]
    public void LooksOnlyInTheNamedChain()
    {
        Assert.Empty(FirewallService.IptablesDeleteSpecs(Listing, "INPUT", "NetworkSentinel-IP-203_0_113_9-Out"));
        Assert.Single(FirewallService.IptablesDeleteSpecs(Listing, "OUTPUT", "NetworkSentinel-IP-203_0_113_9-Out"));
    }

    [Fact]
    public void KeepsAQuotedValueWithASpaceAsOneArgument()
    {
        var spec = Assert.Single(FirewallService.IptablesDeleteSpecs(Listing, "INPUT", "NetworkSentinel-ProbeLog"));
        Assert.Equal("NS-PROBE ", spec[^1]);
        Assert.Equal("--log-prefix", spec[^2]);
    }

    [Fact]
    public void SplitsEscapedQuotes()
        => Assert.Equal(new[] { "-A", "X", "--comment", "say \"hi\"", "" },
            FirewallService.SplitIptablesLine("-A X --comment \"say \\\"hi\\\"\" \"\""));
}
