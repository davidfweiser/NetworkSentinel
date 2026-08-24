using NetworkSentinel.Models;
using NetworkSentinel.Native;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// What counts as a resolver this host is meant to use. The allowlist feeds this decision,
/// so a resolver already listed among the never-block sites does not also have to be typed
/// into Approved resolvers to stop reading as a hijack.
/// </summary>
public class DnsHygieneApprovalTests
{
    private static ConntrackFlow Query(string destination, int port = 53, string source = "192.168.1.50") =>
        new()
        {
            Protocol = "udp",
            SourceAddress = source,
            SourcePort = 41234,
            DestinationAddress = destination,
            DestinationPort = port
        };

    private static DnsHygieneMonitor Started(string approved, params string[] allowlisted)
    {
        var monitor = new DnsHygieneMonitor { ApprovedResolvers = approved };
        if (allowlisted.Length > 0)
        {
            monitor.IsAddressAllowlisted = (string ip, out string reason) =>
            {
                reason = "Allowlisted domain dns.quad9.net";
                return allowlisted.Contains(ip);
            };
        }
        monitor.Start();
        return monitor;
    }

    [Fact]
    public void AllowlistedResolverIsNotReportedAsUnapproved()
    {
        using var monitor = Started("10.8.0.1", "9.9.9.9");

        monitor.ObserveFlow(Query("9.9.9.9"), DateTime.Now);

        var events = monitor.DrainPending();
        Assert.DoesNotContain(events, e => e.Method.Contains("unapproved resolver"));
    }

    [Fact]
    public void AllowlistedResolverStillReportsThePlaintextQuery()
    {
        using var monitor = Started("10.8.0.1", "9.9.9.9");

        monitor.ObserveFlow(Query("9.9.9.9"), DateTime.Now);

        // Trusting who answers says nothing about whether the question was readable in transit.
        var plaintext = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatLevel.Medium, plaintext.Level);
        Assert.Contains("plaintext egress", plaintext.Method);
        Assert.Contains("Allowlisted domain dns.quad9.net", plaintext.Detail);
    }

    [Fact]
    public void ResolverOnNeitherListIsStillReported()
    {
        using var monitor = Started("10.8.0.1", "9.9.9.9");

        monitor.ObserveFlow(Query("8.8.8.8"), DateTime.Now);

        var unapproved = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatLevel.High, unapproved.Level);
        Assert.Contains("unapproved resolver", unapproved.Method);
    }

    [Fact]
    public void ApprovedListStaysTheArmingSwitch()
    {
        // Nothing typed into Approved resolvers means the check is unconfigured. Arming it off
        // the allowlist instead would flag every host on first use, since the allowlist ships
        // populated — so an empty approved list still means "do not judge the destination".
        using var monitor = Started("", "9.9.9.9");

        monitor.ObserveFlow(Query("8.8.8.8"), DateTime.Now);

        var events = monitor.DrainPending();
        Assert.DoesNotContain(events, e => e.Method.Contains("unapproved resolver"));
    }

    [Fact]
    public void AllowlistFailureDoesNotSilenceTheCheck()
    {
        using var monitor = new DnsHygieneMonitor { ApprovedResolvers = "10.8.0.1" };
        monitor.IsAddressAllowlisted = (string ip, out string reason) => throw new InvalidOperationException();
        monitor.Start();

        monitor.ObserveFlow(Query("8.8.8.8"), DateTime.Now);

        Assert.Contains(monitor.DrainPending(), e => e.Method.Contains("unapproved resolver"));
    }

    [Fact]
    public void AllowlistDoesNotMakeHttpsCountAsEncryptedDns()
    {
        // Every HTTPS connection to a trusted site would otherwise register as DoH, and the
        // fallback detector would never fire again.
        using var monitor = Started("10.8.0.1", "9.9.9.9");

        monitor.ObserveFlow(Query("9.9.9.9", port: 443), DateTime.Now);

        Assert.Equal(0L, monitor.Counters.Encrypted);
    }

    [Fact]
    public void ApprovedResolverOnHttpsStillCountsAsDoH()
    {
        using var monitor = Started("10.8.0.1", "9.9.9.9");

        monitor.ObserveFlow(Query("10.8.0.1", port: 443), DateTime.Now);

        Assert.Equal(1L, monitor.Counters.Encrypted);
    }
}
