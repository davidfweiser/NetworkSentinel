using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The UFW write path: exactly which <c>ufw</c> commands a rule turns into, and
/// which numbered rows a delete takes out.
///
/// The argv is asserted verbatim because it is the whole contract. A rule that
/// looks right in the list but was written with the wrong clause is worse than
/// one that failed loudly — it reads as enforced and is not.
/// </summary>
public class UfwWriterTests
{
    private static FirewallRuleSpec Spec(
        string action = FirewallRuleSpecs.ActionAllow,
        string direction = FirewallRuleSpecs.DirectionInbound,
        string protocol = "TCP",
        string ports = "22",
        string addresses = "",
        string label = "allow-inbound-ssh") => new()
    {
        Action = action,
        Direction = direction,
        Protocol = protocol,
        PortRange = ports,
        Addresses = addresses,
        Label = label
    };

    [Fact]
    public void Allow_InboundTcpPort_IsOneUfwCommand()
    {
        var commands = UfwWriter.BuildAddCommands(Spec());

        Assert.Equal(new[]
        {
            "allow", "in", "proto", "tcp", "from", "any",
            "to", "any", "port", "22", "comment", "allow-inbound-ssh"
        }, Assert.Single(commands));
    }

    [Fact]
    public void Block_BecomesUfwDeny()
    {
        var commands = UfwWriter.BuildAddCommands(
            Spec(action: FirewallRuleSpecs.ActionBlock, ports: "23", label: "block-inbound-telnet"));

        Assert.Contains("deny", Assert.Single(commands));
    }

    [Fact]
    public void Outbound_UsesTheOutSide()
    {
        var commands = UfwWriter.BuildAddCommands(
            Spec(direction: FirewallRuleSpecs.DirectionOutbound, protocol: "UDP", ports: "53", label: "allow-outbound-dns"));

        var argv = Assert.Single(commands);
        Assert.Equal("out", argv[1]);   // [verb, side, …]
        Assert.Contains("udp", argv);
    }

    [Fact]
    public void NamedSource_ReplacesAny()
    {
        var commands = UfwWriter.BuildAddCommands(Spec(ports: "3306", addresses: "10.0.0.0/8", label: "allow-inbound-mysql"));

        var argv = Assert.Single(commands);
        var from = Array.IndexOf(argv, "from");
        Assert.Equal("10.0.0.0/8", argv[from + 1]);
    }

    [Fact]
    public void SeveralAddressesAndPorts_BecomeOneCommandEach()
    {
        // UFW takes one source and one port per invocation, so the cross product
        // is the rule — four commands, not one that quietly drops three of them.
        var commands = UfwWriter.BuildAddCommands(
            Spec(ports: "80, 443", addresses: "10.0.0.0/8, 192.168.1.5", label: "allow-inbound-web"));

        Assert.Equal(4, commands.Count);
    }

    [Fact]
    public void PortRange_KeepsUfwsColonForm()
    {
        var commands = UfwWriter.BuildAddCommands(Spec(ports: "8000-8001", label: "allow-inbound-dev"));

        Assert.Contains("8000:8001", Assert.Single(commands));
    }

    [Fact]
    public void Icmp_CarriesNoPortClause()
    {
        // `ufw ... proto icmp ... port N` is rejected outright by UFW.
        var commands = UfwWriter.BuildAddCommands(Spec(protocol: "ICMP", ports: "", label: "allow-inbound-icmp"));

        var argv = Assert.Single(commands);
        Assert.Contains("icmp", argv);
        Assert.DoesNotContain("port", argv);
    }

    [Fact]
    public void ProtocolAny_LeavesTheProtoClauseOff()
    {
        // No proto clause is how UFW says "tcp and udp", which is what Any means.
        var commands = UfwWriter.BuildAddCommands(
            Spec(protocol: FirewallRuleSpecs.ProtocolAny, ports: "5000", label: "allow-inbound-dev"));

        var argv = Assert.Single(commands);
        Assert.DoesNotContain("proto", argv);
        Assert.Contains("5000", argv);
    }

    [Fact]
    public void DeleteFallback_IsTheAddCommandWithoutItsComment()
    {
        var commands = UfwWriter.BuildDeleteCommands(Spec());

        Assert.Equal(new[]
        {
            "--force", "delete", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "22"
        }, Assert.Single(commands));
    }

    // ── ufw status numbered ──────────────────────────────────────────────

    private const string Numbered = """
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] 3306/tcp                   ALLOW IN    10.0.0.0/8
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
""";

    [Fact]
    public void Numbered_ParsesEveryRow()
    {
        var rows = UfwWriter.ParseNumbered(Numbered);

        Assert.Equal(4, rows.Count);
        Assert.Equal(1, rows[0].Number);
        Assert.Equal("22", rows[0].Rule.LocalPorts);
    }

    [Fact]
    public void Numbered_ARowStampedIpv4MatchesOnlyTheIpv4Twin()
    {
        // `ufw status` lists an "anywhere" rule as two rows, and the scan stamps
        // each with the family it came from. Deleting the row the operator clicked
        // must take that row, not both — the list showed them separately.
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = HostFirewallScanner.ParseUfwStatusLine("22/tcp  ALLOW IN  Anywhere")!;

        Assert.Equal("All IPv4", target.RemoteAddresses);
        Assert.Equal(new[] { 1 }, UfwWriter.MatchNumbers(target, rows));
    }

    [Fact]
    public void Numbered_ARuleCoveringBothFamiliesTakesBothTwins()
    {
        // A rule described as covering everything — the form's "All IPv4, All IPv6"
        // — is both rows. Deleting one and leaving the other still admits the
        // traffic, and looks from the list like the delete worked.
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = FirewallRuleSpecs.ToRule(Spec(), "NetworkSentinel-Rule-ssh");

        Assert.Equal(FirewallRuleSpecs.AnyAddressText, target.AddressListText);
        Assert.Equal(new[] { 1, 4 }, UfwWriter.MatchNumbers(target, rows));
    }

    [Fact]
    public void Numbered_ASourceScopedRuleMatchesOnlyItself()
    {
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = HostFirewallScanner.ParseUfwStatusLine("3306/tcp  ALLOW IN  10.0.0.0/8")!;

        Assert.Equal(new[] { 3 }, UfwWriter.MatchNumbers(target, rows));
    }

    [Fact]
    public void Numbered_AV6OnlyTargetLeavesTheV4RowAlone()
    {
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = HostFirewallScanner.ParseUfwStatusLine("22/tcp (v6)  ALLOW IN  Anywhere (v6)")!;

        Assert.Equal(new[] { 4 }, UfwWriter.MatchNumbers(target, rows));
    }

    [Fact]
    public void Numbered_ARuleThatIsNotThereMatchesNothing()
    {
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = HostFirewallScanner.ParseUfwStatusLine("9999/tcp  ALLOW IN  Anywhere")!;

        Assert.Empty(UfwWriter.MatchNumbers(target, rows));
    }

    [Fact]
    public void Numbered_ADifferentActionIsADifferentRule()
    {
        var rows = UfwWriter.ParseNumbered(Numbered);
        var target = HostFirewallScanner.ParseUfwStatusLine("22/tcp  DENY IN  Anywhere")!;

        Assert.Empty(UfwWriter.MatchNumbers(target, rows));
    }

    /// <summary>
    /// UFW takes <c>--force</c> only on enable, disable, reset and delete. An add
    /// carrying it is answered with "ERROR: Invalid syntax", so every rule written
    /// on a UFW host was rejected — the Firewall Config page could add nothing at all.
    /// </summary>
    [Fact]
    public void AddCommands_DoNotPassForce()
    {
        foreach (var argv in UfwWriter.BuildAddCommands(Spec(ports: "22", label: "allow-inbound-ssh")))
        {
            Assert.DoesNotContain("--force", argv);
            Assert.True(argv[0] is "allow" or "deny", $"argv must start at the verb, got '{argv[0]}'");
        }
    }

    /// <summary>
    /// <c>ufw delete</c> wants the rule spelled the way it was added, verb included.
    /// Dropping the verb produced <c>ufw --force delete in proto tcp …</c>, which UFW
    /// rejects — so the fallback delete never removed a rule.
    /// </summary>
    [Fact]
    public void DeleteCommands_KeepTheVerbAfterDelete()
    {
        foreach (var argv in UfwWriter.BuildDeleteCommands(Spec(ports: "22", label: "allow-inbound-ssh")))
        {
            Assert.Equal("--force", argv[0]);
            Assert.Equal("delete", argv[1]);
            Assert.True(argv[2] is "allow" or "deny", $"delete must name the verb, got '{argv[2]}'");
        }
    }

    /// <summary>A deny rule round-trips as a deny delete, not an allow delete.</summary>
    [Fact]
    public void DeleteCommands_CarryTheOriginalVerb()
    {
        var argv = Assert.Single(UfwWriter.BuildDeleteCommands(
            Spec(action: FirewallRuleSpecs.ActionBlock, ports: "23", label: "block-inbound-telnet")));

        Assert.Equal(
            new[] { "--force", "delete", "deny", "in", "proto", "tcp", "from", "any", "to", "any", "port", "23" },
            argv);
    }
}
