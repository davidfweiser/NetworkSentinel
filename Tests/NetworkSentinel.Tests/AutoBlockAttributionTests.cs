using NetworkSentinel.Models;
using NetworkSentinel.Native;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Auto-block acts on the address a threat names. These tests pin down that an
/// attacker cannot choose that address: not by smuggling one into a logged username,
/// not by forging the source of packets that never complete a handshake.
/// </summary>
public class AutoBlockAttributionTests
{
    // ---- SSH / PAM log injection ------------------------------------------------

    private static IReadOnlyList<ThreatEvent> Feed(AuthLogMonitor monitor, string line, int times)
    {
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        for (int i = 0; i < times; i++)
            monitor.ProcessLine(line, now.AddSeconds(i));
        return monitor.DrainPending();
    }

    [Theory]
    // The username is attacker-chosen and may contain spaces; sshd logs it before the real address.
    [InlineData("Invalid user maximum authentication attempts exceeded for root from 8.8.8.8 port 22 from 198.51.100.7 port 40122")]
    [InlineData("Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from 198.51.100.7 port 40122 ssh2")]
    [InlineData("Connection closed by invalid user a 8.8.8.8 port 1 [preauth] 198.51.100.7 port 50110 [preauth]")]
    [InlineData("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=x rhost=8.8.8.8")]
    public void InjectedAddressInUsernameIsNeverBlamed(string line)
    {
        var monitor = new AuthLogMonitor();
        var threats = Feed(monitor, line, 12);

        Assert.NotEmpty(threats);
        Assert.All(threats, t => Assert.Equal("198.51.100.7", t.SourceIp));
    }

    [Fact]
    public void ImmediateCriticalOnlyForTheRealSender()
    {
        var monitor = new AuthLogMonitor();
        var threats = Feed(monitor,
            "Invalid user maximum authentication attempts exceeded for root from 8.8.8.8 port 22 from 198.51.100.7 port 40122",
            1);

        // One injected line must not produce an instant Critical against anybody else.
        Assert.DoesNotContain(threats, t => t.SourceIp == "8.8.8.8");
    }

    [Theory]
    [InlineData("Failed password for root from 203.0.113.7 port 51022 ssh2")]
    [InlineData("Failed password for invalid user admin from 203.0.113.7 port 51022 ssh2")]
    [InlineData("Failed publickey for invalid user admin from 203.0.113.7 port 51022 ssh2 [preauth]")]
    [InlineData("Invalid user oracle from 203.0.113.7 port 40122")]
    [InlineData("Connection closed by invalid user a 203.0.113.7 port 50110 [preauth]")]
    [InlineData("Connection reset by authenticating user root 203.0.113.7 port 50110 [preauth]")]
    [InlineData("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root")]
    [InlineData("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7")]
    // auth.log lines carry a syslog prefix in front of the message.
    [InlineData("Jan  1 12:00:00 host sshd[1234]: Failed password for root from 203.0.113.7 port 51022 ssh2")]
    public void GenuineSshdLinesStillCount(string line)
    {
        var monitor = new AuthLogMonitor();
        var threats = Feed(monitor, line, 4);

        var threat = Assert.Single(threats);
        Assert.Equal("203.0.113.7", threat.SourceIp);
        Assert.Equal(ThreatLevel.High, threat.Level);
    }

    [Fact]
    public void GenuineMaxAttemptsIsImmediate()
    {
        var monitor = new AuthLogMonitor();
        var threats = Feed(monitor,
            "error: maximum authentication attempts exceeded for root from 203.0.113.7 port 33990 ssh2 [preauth]", 1);

        var threat = Assert.Single(threats);
        Assert.Equal("203.0.113.7", threat.SourceIp);
        Assert.Equal(ThreatLevel.Critical, threat.Level);
    }

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

    private static readonly IReadOnlySet<int> Listening = new HashSet<int> { 22 };
    private static readonly IReadOnlySet<int> NoUdp = new HashSet<int>();
    private static readonly IReadOnlyDictionary<string, RemoteHost> NoHosts = new Dictionary<string, RemoteHost>();

    [Fact]
    public void ForgedSynsToSshAlertButAreNotBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var snapshot = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.50", 40000 + i, 22, TcpConnectionState.SynReceived))
            .ToList();

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var ssh = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Equal(ThreatLevel.High, ssh.Level);
        Assert.NotNull(ssh.AutoBlockHoldReason);
    }

    [Fact]
    public void CompletedHandshakesAreBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var snapshot = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.51", 40000 + i, 22, TcpConnectionState.Established))
            .ToList();

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var ssh = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Null(ssh.AutoBlockHoldReason);
    }

    [Fact]
    public void HalfOpenSessionsThatLaterCompleteBecomeBlockable()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        var half = Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.52", 40000 + i, 22, TcpConnectionState.SynReceived))
            .ToList();
        var first = detector.Analyze(half, NoHosts, Listening, NoUdp, now);
        Assert.All(first, t => Assert.NotNull(t.AutoBlockHoldReason));

        // Same sockets, a poll later, past the handshake: the address really is connecting.
        var done = half.Select(c => Conn(c.RemoteAddress, c.RemotePort, c.LocalPort, TcpConnectionState.Established)).ToList();
        var second = detector.Analyze(done, NoHosts, Listening, NoUdp, now.AddSeconds(2));

        var ssh = Assert.Single(second, t => t.Type == ThreatType.BruteForcePattern);
        Assert.Null(ssh.AutoBlockHoldReason);
    }

    [Fact]
    public void ForgedAdminAddressDoesNotRideOnTheAdminsRealSession()
    {
        var detector = new IntrusionDetector();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        // The admin's real SSH session plus six forged SYNs claiming the same address.
        var snapshot = new List<NetworkConnection> { Conn("203.0.113.53", 50000, 22, TcpConnectionState.Established) };
        snapshot.AddRange(Enumerable.Range(0, 6)
            .Select(i => Conn("203.0.113.53", 40000 + i, 22, TcpConnectionState.SynReceived)));

        var threats = detector.Analyze(snapshot, NoHosts, Listening, NoUdp, now);

        var ssh = Assert.Single(threats, t => t.Type == ThreatType.BruteForcePattern);
        Assert.NotNull(ssh.AutoBlockHoldReason);
    }

    // ---- Other forgeable sources -------------------------------------------------

    [Fact]
    public void ClosedPortProbesAreNeverBlockable()
    {
        var monitor = new ProbeLogMonitor();
        var now = new DateTime(2026, 1, 1, 12, 0, 0);
        for (int port = 1000; port < 1010; port++)
            monitor.ProcessLine($"kernel: NS-PROBE IN=eth0 OUT= SRC=203.0.113.60 DST=192.0.2.10 LEN=44 PROTO=TCP SPT=40000 DPT={port} SYN", now);

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
            // Dry run: every gate runs, but no test may write a kernel firewall rule.
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
    public void ParsesResolvConfNameservers()
    {
        var servers = PreventionService.ParseNameservers(new[]
        {
            "# Generated",
            "nameserver 1.1.1.1",
            "  nameserver   2606:4700:4700::1111  ",
            "nameserver not-an-address",
            "nameservers 9.9.9.9",
            "search example.com",
            "options edns0"
        }).ToList();

        Assert.Equal(new[] { "1.1.1.1", "2606:4700:4700::1111" }, servers);
    }

    [Fact]
    public void NewInstallsExpireAutoBlocks()
        => Assert.Equal(1440, new AppSettings().AutoBlockExpiryMinutes);
}
