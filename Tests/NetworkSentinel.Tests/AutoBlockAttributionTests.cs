using NetworkSentinel.Models;
using NetworkSentinel.Native;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Auto-block acts on the address a threat names. These tests pin down that an
/// attacker cannot choose that address by forging the source of packets that never
/// complete a handshake. (The Linux build also guards against an address smuggled
/// into a logged sshd username; the Windows logon monitor reads the address from a
/// structured Security-log field, so there is no free text to inject into.)
/// </summary>
public class AutoBlockAttributionTests
{
    // ---- Half-open TCP sessions -------------------------------------------------

    private static NetworkConnection Conn(string remote, int remotePort, int localPort, TcpConnectionState state)
        => new()
        {
            Protocol = "TCP",
            LocalAddress = "192.0.2.10",
            LocalPort = localPort,
            RemoteAddress = remote,
            RemotePort = remotePort,
            State = state
        };

    private static readonly IReadOnlySet<int> Listening = new HashSet<int> { 3389 };
    private static readonly IReadOnlySet<int> NoUdp = new HashSet<int>();
    private static readonly IReadOnlyDictionary<string, RemoteHost> NoHosts = new Dictionary<string, RemoteHost>();

    [Fact]
    public void ForgedSynsToRdpAlertButAreNotBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var snapshot = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.50", 40000 + i, 3389, TcpConnectionState.SynReceived))
            .ToList();

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var rdp = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Equal(ThreatLevel.Critical, rdp.Level);
        Assert.NotNull(rdp.AutoBlockHoldReason);
    }

    [Fact]
    public void CompletedHandshakesAreBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var snapshot = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.51", 40000 + i, 3389, TcpConnectionState.Established))
            .ToList();

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var rdp = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Null(rdp.AutoBlockHoldReason);
    }

    [Fact]
    public void HalfOpenSessionsThatLaterCompleteBecomeBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var half = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.52", 40000 + i, 3389, TcpConnectionState.SynReceived))
            .ToList();
        var first = detector.Analyze(half, NoHosts, Listening, NoUdp, now);
        Assert.All(first, t => Assert.NotNull(t.AutoBlockHoldReason));

        // Same sockets, a poll later, past the handshake: the address really is connecting.
        var done = half.Select(c => Conn(c.RemoteAddress, c.RemotePort, c.LocalPort, TcpConnectionState.Established)).ToList();
        var second = detector.Analyze(done, NoHosts, Listening, NoUdp, now.AddSeconds(2));

        var rdp = Assert.Single(second, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Null(rdp.AutoBlockHoldReason);
    }

    [Fact]
    public void ForgedAdminAddressDoesNotRideOnTheAdminsRealSession()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        // The admin's real RDP session plus six forged SYNs claiming the same address.
        var snapshot = new List<NetworkConnection> { Conn("203.0.113.53", 50000, 3389, TcpConnectionState.Established) };
        snapshot.AddRange(Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.53", 40000 + i, 3389, TcpConnectionState.SynReceived)));

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var rdp = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.NotNull(rdp.AutoBlockHoldReason);
    }

    // ---- Other forgeable sources -------------------------------------------------

    [Fact]
    public void DroppedSynProbesAreNeverBlockable()
    {
        var monitor = new ProbeLogMonitor();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        monitor.ProcessLine(
            "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid",
            now);
        for (int port = 1000; port < 1010; port++)
            monitor.ProcessLine(
                $"2026-01-01 12:00:00 DROP TCP 203.0.113.60 192.0.2.10 40000 {port} 52 S 1234567 0 64240 - - - RECEIVE 4",
                now);

        var threats = monitor.DrainPending();

        Assert.NotEmpty(threats);
        Assert.All(threats, t => Assert.NotNull(t.AutoBlockHoldReason));
    }

    [Theory]
    [InlineData("UDP", "dns", true)]
    [InlineData("ICMP", "", true)]
    [InlineData("TCP", "", true)]
    [InlineData("TCP", "failed", true)]
    [InlineData("TCP", "http", false)]
    [InlineData("tcp", "tls", false)]
    public void SuricataTrustsOnlyEstablishedTcp(string proto, string appProto, bool forgeable)
        => Assert.Equal(forgeable, SuricataService.SourceMayBeForged(proto, appProto));

    // ---- The prevention gates ----------------------------------------------------

    private static PreventionService Engine()
    {
        var prevention = new PreventionService(new FirewallService(), new AllowlistService(), new AppSettings())
        {
            Enabled = true,
            // Dry run: every gate runs, but no test may write a firewall rule.
            DryRun = true,
            ResolverCheckOverride = _ => false
        };
        return prevention;
    }

    [Fact]
    public void HeldThreatIsNeverActedOnAndSaysWhy()
    {
        var prevention = Engine();
        var held = new ThreatEvent
        {
            SourceIp = "203.0.113.70",
            Level = ThreatLevel.Critical,
            Type = ThreatType.PortScan,
            Title = "Port scan",
            AutoBlockHoldReason = "the source address may be forged"
        };

        Assert.Empty(prevention.Apply(new[] { held }).Decisions);

        var status = prevention.DescribeEnforcement(held);
        Assert.NotNull(status);
        Assert.False(status!.IsBlocked);
        Assert.Contains("may be forged", status.Text);
    }

    [Fact]
    public void ConfiguredResolverIsNeverAutoBlocked()
    {
        var prevention = Engine();
        prevention.ResolverCheckOverride = ip => ip == "203.0.113.53";
        var threat = new ThreatEvent { SourceIp = "203.0.113.53", Level = ThreatLevel.Critical, Type = ThreatType.PortScan };

        Assert.Empty(prevention.Apply(new[] { threat }).Decisions);
        Assert.Contains("DNS resolver", prevention.DescribeEnforcement(threat)!.Text);
    }

    [Fact]
    public void SkippedDecisionIsDescribedByItsOwnMessage()
    {
        var prevention = Engine();
        var threat = new ThreatEvent { SourceIp = "203.0.113.71", Level = ThreatLevel.Critical, Type = ThreatType.PortScan };
        var result = new PreventionResult
        {
            Decisions = new[]
            {
                new PreventionDecision
                {
                    Ip = "203.0.113.71",
                    Action = PreventionAction.Skipped,
                    Message = "Not blocking 203.0.113.71 — it is a VPN tunnel endpoint",
                    Threat = threat
                }
            }
        };

        var status = prevention.DescribeEnforcement(threat, result);

        Assert.Equal(BlockState.NotBlocked, status!.State);
        Assert.Contains("VPN tunnel endpoint", status.Text);
        Assert.DoesNotContain("refused", status.Text);
    }

    [Fact]
    public void AdapterResolversAreNormalizedAddresses()
    {
        // Whatever this machine's adapters hold, every entry must be an address the
        // gate can compare against a threat's normalized source.
        Assert.All(PreventionService.ReadAdapterResolvers(),
            r => Assert.True(FirewallService.TryNormalizeIp(r, out var again, out _) && again == r));
    }

    [Fact]
    public void NewInstallsExpireAutoBlocks()
        => Assert.Equal(1440, new AppSettings().AutoBlockExpiryMinutes);
}
