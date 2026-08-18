using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The Firewall Config rule pipeline: what the operator types, what netsh is asked
/// to write, what comes back out of the firewall's own rule dump, and what the
/// console refuses to write in the first place.
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

    private static string OneNetsh(FirewallRuleSpec spec)
        => Assert.Single(FirewallRuleSpecs.BuildNetshMatches(Rule(spec))).Match;

    // ── Ports ────────────────────────────────────────────────────────────

    [Fact]
    public void PortListAndRangeBecomeCanonicalTokens()
    {
        Assert.True(FirewallRuleSpecs.TryParsePorts("80, 443", out var list, out _));
        Assert.Equal(new[] { "80", "443" }, list);

        // The canonical token spells a range with a colon; the form takes the
        // friendlier dash, and the renderer converts back.
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

    [Fact]
    public void ALabelSurvivesBeingTurnedIntoARuleNameAndBack()
    {
        // The rule name is the only place the label is kept — there is no ledger
        // beside the firewall — so CleanLabel may not pass anything that the rule
        // name's own sanitising would rewrite, or the label would come back changed.
        var label = FirewallRuleSpecs.CleanLabel("office VPN (only): site-to-site #1");
        var name = "NetworkSentinel-Rule-" + label;

        Assert.Equal(label, name["NetworkSentinel-Rule-".Length..]);
        Assert.Matches("^[A-Za-z0-9_.-]+$", label);
    }

    // ── Validation ───────────────────────────────────────────────────────

    [Fact]
    public void AValidRulePassesValidation()
        => Assert.Equal("", FirewallRuleSpecs.Validate(FirewallRuleSpecs.Normalize(Spec())));

    [Fact]
    public void AllowEverythingIsRefused()
    {
        // Protocol Any, no port, no address: an allow rule that matches all traffic.
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

    // ── netsh rendering ──────────────────────────────────────────────────

    [Fact]
    public void InboundBlockFiltersOnTheSourceAndTheLocalPort()
        => Assert.Equal("protocol=tcp localport=22 remoteip=203.0.113.5",
            OneNetsh(Spec(addresses: "203.0.113.5")));

    [Fact]
    public void OutboundRuleFiltersOnTheDestinationAndTheRemotePort()
    {
        // "Outbound to port 443" means the service being reached, not the local
        // source port — netsh spells that remoteport.
        Assert.Equal("protocol=tcp remoteport=443 remoteip=198.51.100.7", OneNetsh(Spec(
            action: FirewallRuleSpecs.ActionAllow,
            direction: FirewallRuleSpecs.DirectionOutbound,
            ports: "443",
            addresses: "198.51.100.7")));
    }

    [Fact]
    public void ListsGoIntoOneRuleAsCommaSeparatedValues()
        => Assert.Equal(
            "protocol=tcp localport=80,443 remoteip=10.0.0.0/8,192.168.1.5",
            OneNetsh(Spec(ports: "80, 443", addresses: "10.0.0.0/8, 192.168.1.5")));

    [Fact]
    public void AnyProtocolAndAnyAddressDropTheirClauses()
        => Assert.Equal("protocol=any", OneNetsh(Spec(protocol: "Any", ports: "", addresses: "")));

    [Fact]
    public void RangesUseTheDashSyntaxInTheRule()
        => Assert.Contains("localport=8000-8001", OneNetsh(Spec(ports: "8000-8001")));

    [Fact]
    public void MixedAddressFamiliesStayInOneRule()
    {
        // Unlike iptables, a Windows Firewall rule holds IPv4 and IPv6 addresses
        // together, so a mixed list needs no split.
        Assert.Equal("protocol=tcp localport=22 remoteip=203.0.113.5,2001:db8::1",
            OneNetsh(Spec(addresses: "203.0.113.5, 2001:db8::1")));
    }

    [Fact]
    public void PortsUnderProtocolAnySplitIntoTcpAndUdp()
    {
        // netsh refuses a port keyword unless the protocol is tcp or udp, so "Any
        // protocol, port 5353" becomes the two rules the operator meant.
        var matches = FirewallRuleSpecs.BuildNetshMatches(Rule(Spec(protocol: "Any", ports: "5353")));

        Assert.Equal(
            new[] { "protocol=tcp localport=5353", "protocol=udp localport=5353" },
            matches.Select(m => m.Match));
    }

    [Fact]
    public void IcmpCarriesNoPortClauseAndNamesTheFamily()
    {
        // netsh has no family-agnostic ICMP, so a rule with no address to pin the
        // family has to cover both.
        var both = FirewallRuleSpecs.BuildNetshMatches(Rule(Spec(protocol: "ICMP", ports: "")));
        Assert.Equal(new[] { "protocol=icmpv4", "protocol=icmpv6" }, both.Select(m => m.Match));

        Assert.Equal("protocol=icmpv4 remoteip=203.0.113.5",
            OneNetsh(Spec(protocol: "ICMP", ports: "", addresses: "203.0.113.5")));
        Assert.Equal("protocol=icmpv6 remoteip=2001:db8::1",
            OneNetsh(Spec(protocol: "ICMP", ports: "", addresses: "2001:db8::1")));
    }

    [Fact]
    public void IcmpSplitsAMixedAddressListByFamily()
    {
        // The address list has to follow the protocol it belongs to: a v6 address on
        // an icmpv4 rule would sit there matching nothing.
        var matches = FirewallRuleSpecs.BuildNetshMatches(
            Rule(Spec(protocol: "ICMP", ports: "", addresses: "203.0.113.5, 2001:db8::1")));

        Assert.Equal(
            new[] { "protocol=icmpv4 remoteip=203.0.113.5", "protocol=icmpv6 remoteip=2001:db8::1" },
            matches.Select(m => m.Match));
    }

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

    // ── Reading the rules back out of the firewall ───────────────────────

    private static string Dump(params string[] lines) => string.Join("\r\n", lines);

    private static string[] RuleBlock(
        string name, string direction, string protocol, string localPort,
        string remotePort, string remoteIp, string action) => new[]
    {
        $"Rule Name:                            {name}",
        "----------------------------------------------------------------------",
        "Enabled:                              Yes",
        $"Direction:                            {direction}",
        "Profiles:                             Domain,Private,Public",
        "LocalIP:                              Any",
        $"RemoteIP:                             {remoteIp}",
        $"Protocol:                             {protocol}",
        $"LocalPort:                            {localPort}",
        $"RemotePort:                           {remotePort}",
        "Edge traversal:                       No",
        $"Action:                               {action}",
        ""
    };

    [Fact]
    public void AConfigRuleComesBackAsTheSpecItWasWrittenFrom()
    {
        var parsed = Assert.Single(FirewallService.ParseNetshRules(Dump(RuleBlock(
            "NetworkSentinel-Rule-block-inbound-ssh", "In", "TCP", "22", "Any",
            "10.0.0.0/255.0.0.0,192.168.1.5/255.255.255.255", "Block"))));

        Assert.Equal(FirewallRuleKind.Custom, parsed.Kind);
        Assert.Equal("block-inbound-ssh", parsed.Label);
        Assert.True(parsed.IsBlock);
        Assert.Equal(FirewallDirection.Inbound, parsed.Direction);
        Assert.Equal("22", parsed.LocalPorts);

        // netsh writes a mask where the operator typed a prefix, and a full-length
        // mask on a single host; both have to come back the way they were typed or
        // Edit hands the form something it cannot parse.
        Assert.Equal("10.0.0.0/8, 192.168.1.5", parsed.RemoteAddresses);
    }

    [Fact]
    public void AnOutboundConfigRuleReadsItsPortFromTheRemoteSide()
    {
        var parsed = Assert.Single(FirewallService.ParseNetshRules(Dump(RuleBlock(
            "NetworkSentinel-Rule-allow-outbound-https", "Out", "TCP", "Any", "443",
            "198.51.100.7", "Allow"))));

        Assert.Equal("443", parsed.LocalPorts);
        Assert.False(parsed.IsBlock);
        Assert.Equal(FirewallDirection.Outbound, parsed.Direction);
    }

    [Fact]
    public void AnAppMintedBlockStillReadsItsPortFromTheLocalSide()
    {
        // The legacy port blocks match the local port in both directions, so the
        // config rules' direction-dependent reading must not touch them.
        var parsed = Assert.Single(FirewallService.ParseNetshRules(Dump(RuleBlock(
            "NetworkSentinel-Port-TCP-445-Out", "Out", "TCP", "445", "Any", "Any", "Block"))));

        Assert.Equal(FirewallRuleKind.PortBlock, parsed.Kind);
        Assert.Equal("445", parsed.LocalPorts);
    }

    [Fact]
    public void TheTwoHalvesOfAnAnyProtocolRuleFoldBackIntoOne()
    {
        // netsh will not take a port with protocol=any, so the rule was written as a
        // TCP half and a UDP half under one name. The operator wrote one rule and
        // has to get one rule back.
        var rules = FirewallService.MergeConfigFragments(FirewallService.ParseNetshRules(Dump(
            RuleBlock("NetworkSentinel-Rule-block-inbound-5353", "In", "TCP", "5353", "Any", "Any", "Block")
                .Concat(RuleBlock("NetworkSentinel-Rule-block-inbound-5353", "In", "UDP", "5353", "Any", "Any", "Block"))
                .ToArray())));

        var merged = Assert.Single(rules);
        Assert.Equal(FirewallRuleSpecs.ProtocolAny, merged.Protocol);
        Assert.Equal("5353", merged.LocalPorts);
    }

    [Fact]
    public void TheTwoIcmpFamiliesFoldBackIntoOneIcmpRule()
    {
        var rules = FirewallService.MergeConfigFragments(FirewallService.ParseNetshRules(Dump(
            RuleBlock("NetworkSentinel-Rule-block-inbound-icmp", "In", "ICMPv4", "Any", "Any", "203.0.113.5", "Block")
                .Concat(RuleBlock("NetworkSentinel-Rule-block-inbound-icmp", "In", "ICMPv6", "Any", "Any", "2001:db8::1", "Block"))
                .ToArray())));

        var merged = Assert.Single(rules);
        Assert.Equal("ICMP", merged.Protocol);
        Assert.Equal("203.0.113.5, 2001:db8::1", merged.RemoteAddresses);
        Assert.Equal("", merged.LocalPorts);
    }

    [Fact]
    public void AWrappedAddressListIsReadToItsEnd()
    {
        // netsh breaks a long list onto indented continuation lines. Reading only the
        // first line would drop addresses from the rule the Edit button shows, and
        // saving it back would silently narrow the rule.
        var parsed = Assert.Single(FirewallService.ParseNetshRules(Dump(
            "Rule Name:                            NetworkSentinel-Rule-block-inbound-ssh",
            "Enabled:                              Yes",
            "Direction:                            In",
            "RemoteIP:                             203.0.113.5/255.255.255.255,",
            "                                      198.51.100.7/255.255.255.255,",
            "                                      2001:db8::1/128",
            "Protocol:                             TCP",
            "LocalPort:                            22",
            "RemotePort:                           Any",
            "Action:                               Block")));

        Assert.Equal("203.0.113.5, 198.51.100.7, 2001:db8::1", parsed.RemoteAddresses);
    }

    [Fact]
    public void ARuleLabelledLikeAnAppRuleIsStillAConfigRule()
    {
        // The app's own rules are recognised by "-IP-" and "-Port-" anywhere in the
        // name, and an operator is free to label a rule "block-IP-scanner". Getting
        // this wrong would show a config rule as an auto-block and offer Unblock on it.
        var parsed = Assert.Single(FirewallService.ParseNetshRules(Dump(RuleBlock(
            "NetworkSentinel-Rule-block-IP-scanner", "In", "TCP", "22", "Any", "203.0.113.5", "Block"))));

        Assert.Equal(FirewallRuleKind.Custom, parsed.Kind);
        Assert.Equal("block-IP-scanner", parsed.Label);
    }

    // ── Precedence ───────────────────────────────────────────────────────

    [Fact]
    public void ABlockRuleOutranksAnAllowRuleWhicheverWasWrittenFirst()
    {
        // Windows Firewall groups rules by type and evaluates blocks before allows,
        // so unlike the nft/iptables build there is no chain order to manage: an
        // operator's Allow rule cannot reopen an address auto-block just shut.
        // The one rule type that would outrank a block is an authenticated bypass,
        // and the Firewall Config view has no way to author one.
        var written = FirewallRuleSpecs.BuildNetshMatches(Rule(Spec(
            action: FirewallRuleSpecs.ActionAllow, addresses: "203.0.113.5")));

        Assert.DoesNotContain(written, m =>
            m.Match.Contains("security=", StringComparison.OrdinalIgnoreCase) ||
            m.Match.Contains("bypass", StringComparison.OrdinalIgnoreCase));
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
