using NetworkSentinel.Services;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The one Firewall Config rule the web console refuses to write. The desktop app
/// can ask the operator to confirm cutting the machine off the network; over the
/// web the confirmation would travel down the very connection being cut, so there
/// would be no one left to answer — and the page going dark mid-request is
/// indistinguishable from a crash.
/// </summary>
public class ConsoleSelfBlockTests
{
    private const int HttpPort = 18765;
    private const int HttpsPort = 18443;

    private static string? Reason(
        string ports = "",
        string addresses = "",
        string action = FirewallRuleSpecs.ActionBlock,
        string direction = FirewallRuleSpecs.DirectionInbound,
        int? https = null)
        => WebApp.ConsoleSelfBlockReason(
            new FirewallRuleSpec
            {
                Action = action,
                Direction = direction,
                Protocol = "TCP",
                PortRange = ports,
                Addresses = addresses
            },
            HttpPort,
            https);

    [Fact]
    public void ACatchAllInboundBlockIsRefused()
    {
        var reason = Reason();
        Assert.NotNull(reason);
        Assert.Contains("every inbound connection on every port", reason);
    }

    [Fact]
    public void BlockingTheConsolesOwnPortIsRefused()
    {
        var reason = Reason(ports: HttpPort.ToString());
        Assert.NotNull(reason);
        Assert.Contains($"port {HttpPort}", reason);
    }

    [Fact]
    public void ARangeThatSwallowsTheConsolesPortIsRefused()
    {
        // The port does not have to be named for the rule to close it.
        var reason = Reason(ports: $"{HttpPort - 5}-{HttpPort + 5}");
        Assert.NotNull(reason);
        Assert.Contains($"port {HttpPort}", reason);
    }

    [Fact]
    public void TheHttpsPortIsOnlyGuardedWhenTlsIsServing()
    {
        // With TLS off nothing is listening there, so the rule cuts nothing.
        Assert.Null(Reason(ports: HttpsPort.ToString()));

        var reason = Reason(ports: HttpsPort.ToString(), https: HttpsPort);
        Assert.NotNull(reason);
        Assert.Contains($"port {HttpsPort}", reason);
    }

    [Fact]
    public void ARuleScopedToNamedSourcesIsAllowedThrough()
    {
        // The Firewall tab's Block IP button already blocks a chosen address on
        // every port, so refusing the same thing here would be an inconsistency
        // rather than a safeguard.
        Assert.Null(Reason(addresses: "203.0.113.5"));
        Assert.Null(Reason(ports: HttpPort.ToString(), addresses: "203.0.113.5"));
    }

    [Fact]
    public void AnAllowRuleOnTheConsolesPortIsNotASelfBlock()
        => Assert.Null(Reason(ports: HttpPort.ToString(), action: FirewallRuleSpecs.ActionAllow));

    [Fact]
    public void AnOutboundRuleIsNotASelfBlock()
    {
        // Outbound rules match what this host reaches, not what reaches it, so the
        // console's own inbound port is not at stake.
        Assert.Null(Reason(direction: FirewallRuleSpecs.DirectionOutbound));
        Assert.Null(Reason(ports: HttpPort.ToString(), direction: FirewallRuleSpecs.DirectionOutbound));
    }

    [Fact]
    public void AnUnrelatedInboundBlockIsAllowedThrough()
        => Assert.Null(Reason(ports: "445"));
}
