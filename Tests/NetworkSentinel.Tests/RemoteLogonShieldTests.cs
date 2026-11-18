using NetworkSentinel.Models;
using NetworkSentinel.Native;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// A successful remote logon clears its address's failure count, and is remembered so
/// auto-block leaves the operator's own address alone. Only a logon that proves someone
/// authenticated from that address counts.
/// </summary>
public class RemoteLogonCountingTests
{
    private const string Ip = "203.0.113.7";
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0);

    private static string SecurityEvent(int id, string ip, string logonType = "10",
                                        string sid = "S-1-5-21-1111-2222-3333-1001", string user = "alice",
                                        string provider = "Microsoft-Windows-Security-Auditing") =>
        $"""
         <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
           <System>
             <Provider Name="{provider}" />
             <EventID>{id}</EventID>
           </System>
           <EventData>
             <Data Name="TargetUserSid">{sid}</Data>
             <Data Name="TargetUserName">{user}</Data>
             <Data Name="LogonType">{logonType}</Data>
             <Data Name="IpAddress">{ip}</Data>
           </EventData>
         </Event>
         """;

    private static void Fail(AuthLogMonitor monitor, int times, ref DateTime now)
    {
        for (var i = 0; i < times; i++)
        {
            monitor.ProcessRecord(SecurityEvent(4625, Ip, logonType: "3", sid: "S-1-0-0"), 4625, now);
            now = now.AddSeconds(5);
        }
    }

    [Fact]
    public void FourFailuresStillRaiseHigh()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Fail(monitor, 4, ref now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatLevel.High, threat.Level);
        Assert.Equal("4 failed logons in 10 min", threat.Title);
    }

    [Fact]
    public void ALogonClearsTheCount()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Fail(monitor, 3, ref now);
        monitor.ProcessRecord(SecurityEvent(4624, Ip), 4624, now);
        Fail(monitor, 1, ref now);

        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void OnlyAuthenticatedRemoteLogonsAreReported()
    {
        var seen = new List<string>();
        var monitor = new AuthLogMonitor { SuccessfulLogin = seen.Add };

        monitor.ProcessRecord(SecurityEvent(4624, "203.0.113.10", logonType: "10"), 4624, T0); // Remote Desktop
        monitor.ProcessRecord(SecurityEvent(4624, "203.0.113.11", logonType: "3"), 4624, T0);  // SMB / WinRM / NLA
        monitor.ProcessRecord(SecurityEvent(4624, "::ffff:203.0.113.12", logonType: "7"), 4624, T0); // RDP reconnect unlock

        // A null session: anyone can make one, from anywhere.
        monitor.ProcessRecord(SecurityEvent(4624, "198.51.100.1", logonType: "3", sid: "S-1-5-7", user: "ANONYMOUS LOGON"), 4624, T0);
        // An enabled Guest account takes any password.
        monitor.ProcessRecord(SecurityEvent(4624, "198.51.100.2", logonType: "3", sid: "S-1-5-21-1111-2222-3333-501", user: "Guest"), 4624, T0);
        // A service or local logon is not someone arriving over the network.
        monitor.ProcessRecord(SecurityEvent(4624, "198.51.100.3", logonType: "5"), 4624, T0);
        // Not written by LSA.
        monitor.ProcessRecord(SecurityEvent(4624, "198.51.100.4", provider: "SomethingElse"), 4624, T0);
        // No client address to shield.
        monitor.ProcessRecord(SecurityEvent(4624, "-"), 4624, T0);
        monitor.ProcessRecord(SecurityEvent(4624, "127.0.0.1"), 4624, T0);

        Assert.Equal(new[] { "203.0.113.10", "203.0.113.11", "203.0.113.12" }, seen);
    }

    [Fact]
    public void AFailedLogonIsNotReportedAsASuccess()
    {
        var seen = new List<string>();
        var monitor = new AuthLogMonitor { SuccessfulLogin = seen.Add };
        monitor.ProcessRecord(SecurityEvent(4625, Ip), 4625, T0);
        Assert.Empty(seen);
    }
}

public class RemoteLogonShieldTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), "ns-logons-" + Guid.NewGuid().ToString("N") + ".json");

    private static readonly Func<IEnumerable<string>> NoSessions = () => Array.Empty<string>();

    [Fact]
    public void RemoteDesktopClientAddressesAreReadFromIPv4Only()
    {
        var v4 = new byte[20];
        new byte[] { 203, 0, 113, 7 }.CopyTo(v4, 2);
        Assert.Equal("203.0.113.7", WtsSessions.ParseClientAddress(2, v4));

        Assert.Null(WtsSessions.ParseClientAddress(2, new byte[20]));   // 0.0.0.0
        Assert.Null(WtsSessions.ParseClientAddress(0, v4));             // console: AF_UNSPEC
        Assert.Null(WtsSessions.ParseClientAddress(23, v4));            // AF_INET6: layout undocumented
    }

    [Fact]
    public void ReadingTheLiveSessionsOnThisMachineWorks()
    {
        // Exercises the real wtsapi32 marshalling. A test run sits at the console or in a
        // build agent's service session, so the list is usually empty — but whatever it
        // holds must be addresses.
        Assert.All(WtsSessions.LoggedOnClientAddresses(), a => Assert.True(System.Net.IPAddress.TryParse(a, out _)));
    }

    [Fact]
    public void ALoggedOnClientIsShielded()
    {
        var shield = new RemoteLogonShield(TempPath(), () => new[] { "203.0.113.7" });
        Assert.True(shield.IsShielded("203.0.113.7"));
        Assert.True(shield.IsShielded("::ffff:203.0.113.7"));
        Assert.False(shield.IsShielded("203.0.113.8"));
    }

    [Fact]
    public void AnUnreadableSessionListShieldsNothing()
    {
        var shield = new RemoteLogonShield(TempPath(), () => throw new InvalidOperationException("TermService stopped"));
        Assert.False(shield.IsShielded("203.0.113.7"));
    }

    [Fact]
    public void RecentLogonsAreRememberedAcrossRestartsAndThenForgotten()
    {
        var store = TempPath();
        try
        {
            // Near the real clock: loading prunes with it, before a test clock can be set.
            var now = DateTime.UtcNow;
            var shield = new RemoteLogonShield(store, NoSessions) { UtcNow = () => now };
            shield.RecordLogin("203.0.113.7");
            shield.RecordLogin("192.168.1.20"); // private: never auto-blocked anyway, not stored

            var restarted = new RemoteLogonShield(store, NoSessions) { UtcNow = () => now.AddDays(29) };
            Assert.True(restarted.IsShielded("203.0.113.7"));
            Assert.DoesNotContain("192.168.1.20", File.ReadAllText(store));

            restarted.UtcNow = () => now.AddDays(31);
            Assert.False(restarted.IsShielded("203.0.113.7"));
        }
        finally
        {
            File.Delete(store);
        }
    }

    [Fact]
    public void TwoProcessesSharingTheFileKeepEachOthersLogons()
    {
        // The desktop app and the web service each hold a shield over the same file.
        var store = TempPath();
        try
        {
            var desktop = new RemoteLogonShield(store, NoSessions);
            var service = new RemoteLogonShield(store, NoSessions);
            desktop.RecordLogin("203.0.113.7");
            service.RecordLogin("203.0.113.8");

            var restarted = new RemoteLogonShield(store, NoSessions);
            Assert.True(restarted.IsShielded("203.0.113.7"));
            Assert.True(restarted.IsShielded("203.0.113.8"));
        }
        finally
        {
            File.Delete(store);
        }
    }

    [Fact]
    public void AutoBlockHoldsBackARemoteLogonAddressAndSaysWhy()
    {
        var prevention = new PreventionService(new FirewallService(), new AllowlistService(), new AppSettings())
        {
            Enabled = true,
            // Dry run: every gate runs, but no test may write a real firewall rule.
            DryRun = true,
            IsRemoteLogonAddress = ip => ip == "203.0.113.7"
        };

        var threats = new[] { "203.0.113.7", "203.0.113.8" }.Select(ip => new ThreatEvent
        {
            SourceIp = ip, Level = ThreatLevel.High, Type = ThreatType.FailedLogonBurst, Title = "4 failed logons in 10 min"
        }).ToList();
        var result = prevention.Apply(threats);

        var held = Assert.Single(result.Decisions, d => d.Action == PreventionAction.Skipped);
        Assert.Equal("203.0.113.7", held.Ip);
        Assert.Contains("logged on to this machine from it", held.Message);
        Assert.Contains(result.Decisions, d => d.Ip == "203.0.113.8" && d.Action == PreventionAction.Simulated);
        Assert.Contains("logs on to this machine remotely", prevention.DescribeEnforcement(threats[0])!.Text);
    }
}
