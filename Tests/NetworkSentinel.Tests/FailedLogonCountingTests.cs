using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// One failed SSH attempt is one attempt. sshd and PAM each log a failed password,
/// and sshd logs the disconnect after it; counting every line turned two typos into
/// four or five "attempts" — over the High threshold that auto-block acts on.
/// The sequences below are what OpenSSH with PAM writes on Debian and Ubuntu.
/// </summary>
public class FailedLogonCountingTests
{
    private const string Ip = "203.0.113.7";
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0);

    private static void Replay(AuthLogMonitor monitor, IEnumerable<string> lines, ref DateTime now)
    {
        foreach (var line in lines)
        {
            monitor.ProcessLine(line, now);
            now = now.AddSeconds(2);
        }
    }

    /// <summary>A valid account mistyping its password <paramref name="typos"/> times on one connection, then leaving.</summary>
    private static IEnumerable<string> ValidUserTypos(int port, int typos, string account = "alice")
    {
        for (var i = 0; i < typos; i++)
        {
            yield return $"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={Ip}  user={account}";
            yield return $"Failed password for {account} from {Ip} port {port} ssh2";
        }
        yield return $"Connection closed by authenticating user {account} {Ip} port {port} [preauth]";
    }

    /// <summary>A guess at an account that does not exist: one password, then gone.</summary>
    private static IEnumerable<string> InvalidUserGuess(int port)
    {
        yield return $"Invalid user oracle from {Ip} port {port}";
        yield return "pam_unix(sshd:auth): check pass; user unknown";
        yield return $"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={Ip}";
        yield return $"Failed password for invalid user oracle from {Ip} port {port} ssh2";
        yield return $"Disconnected from invalid user oracle {Ip} port {port} [preauth]";
    }

    [Fact]
    public void TwoMistypedPasswordsAreNotABurst()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Replay(monitor, ValidUserTypos(50000, 2), ref now);

        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void FourRealAttemptsStillRaiseHigh()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Replay(monitor, ValidUserTypos(50000, 2), ref now);
        Replay(monitor, ValidUserTypos(50001, 2), ref now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal(ThreatLevel.High, threat.Level);
        Assert.Equal("4 failed logons in 10 min", threat.Title);
    }

    [Fact]
    public void AGuessAtAnUnknownAccountCountsOnce()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        for (var port = 50000; port < 50003; port++)
            Replay(monitor, InvalidUserGuess(port), ref now);
        Assert.Empty(monitor.DrainPending());

        Replay(monitor, InvalidUserGuess(50003), ref now);
        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal("4 failed logons in 10 min", threat.Title);
        Assert.Contains("oracle", threat.Detail);
    }

    [Fact]
    public void ProbingUserNamesWithoutAPasswordStillCounts()
    {
        // Scanners often only ask whether an account exists, and hang up.
        var monitor = new AuthLogMonitor();
        var now = T0;
        for (var port = 50000; port < 50004; port++)
        {
            Replay(monitor, new[]
            {
                $"Invalid user admin{port} from {Ip} port {port}",
                $"Connection closed by invalid user admin{port} {Ip} port {port} [preauth]"
            }, ref now);
        }

        Assert.Equal(ThreatLevel.High, Assert.Single(monitor.DrainPending()).Level);
    }

    [Fact]
    public void PamOnlyFailuresCountOnceEach()
    {
        // sshd logs a valid account's failed keyboard-interactive attempts only at
        // VERBOSE; PAM's line is then all there is, and the disconnect is not another.
        var monitor = new AuthLogMonitor();
        var now = T0;
        for (var port = 50000; port < 50004; port++)
        {
            Replay(monitor, new[]
            {
                $"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={Ip}  user=alice",
                $"Connection closed by authenticating user alice {Ip} port {port} [preauth]"
            }, ref now);
        }

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal("4 failed logons in 10 min", threat.Title);
    }

    [Fact]
    public void ALoginClearsTheCount()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Replay(monitor, ValidUserTypos(50000, 3), ref now);
        Replay(monitor, new[] { $"Accepted password for alice from {Ip} port 50001 ssh2" }, ref now);
        Replay(monitor, ValidUserTypos(50002, 1), ref now);

        Assert.Empty(monitor.DrainPending());
    }

    [Fact]
    public void ALoginClearsOnlyThatAccountsFailures()
    {
        // Someone with a login here, guessing root's password from the same address: their
        // own login used to wipe the count, so they could reset it as often as they liked.
        var monitor = new AuthLogMonitor();
        var now = T0;
        Replay(monitor, ValidUserTypos(50000, 3, "root"), ref now);
        Replay(monitor, new[] { $"Accepted publickey for alice from {Ip} port 50001 ssh2: ED25519 SHA256:abc" }, ref now);
        Replay(monitor, ValidUserTypos(50002, 1, "root"), ref now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal("4 failed logons in 10 min", threat.Title);
        Assert.Equal(new[] { "root" }, threat.AccountsTried);
    }

    [Fact]
    public void ABurstNamesTheAccountsItTriedInItsWindow()
    {
        var monitor = new AuthLogMonitor();
        var now = T0;
        Replay(monitor, ValidUserTypos(50000, 1, "bob"), ref now);
        now = now.AddMinutes(11); // bob's attempt has left the window
        Replay(monitor, ValidUserTypos(50001, 3), ref now);
        Replay(monitor, InvalidUserGuess(50002), ref now);

        var threat = Assert.Single(monitor.DrainPending());
        Assert.Equal(new[] { "alice", "oracle" }, threat.AccountsTried);
        Assert.EndsWith("Accounts tried: alice, oracle.", threat.Detail);
    }

    [Fact]
    public void AnAuthLogLoginDoesNotClearTheCount()
    {
        // Any local account can write an "Accepted" line into auth.log with
        // `logger -t sshd`; trusting it would let one keep an attacker under the threshold.
        var monitor = new AuthLogMonitor();
        var now = T0;
        foreach (var line in ValidUserTypos(50000, 3)
                     .Append($"Accepted password for alice from {Ip} port 50001 ssh2")
                     .Concat(ValidUserTypos(50002, 1)))
        {
            monitor.ProcessLine($"Jan  1 12:00:00 host sshd[1]: {line}", now, fromJournal: false);
            now = now.AddSeconds(2);
        }

        Assert.Equal("4 failed logons in 10 min", Assert.Single(monitor.DrainPending()).Title);
    }

    [Fact]
    public void SuccessfulLoginsAreReportedFromJournaldOnly()
    {
        var seen = new List<(string, string)>();
        var monitor = new AuthLogMonitor { SuccessfulLogin = (ip, account) => seen.Add((ip, account)) };

        monitor.ProcessLine($"Accepted publickey for alice from {Ip} port 50000 ssh2: ED25519 SHA256:abc", T0, fromJournal: true);
        // Any local account can write this into auth.log with `logger -t sshd`.
        monitor.ProcessLine($"Jan  1 12:00:00 host sshd[1]: Accepted password for alice from 198.51.100.1 port 1 ssh2", T0, fromJournal: false);
        // Nor can a client's disconnect message pose as one.
        monitor.ProcessLine($"Received disconnect from {Ip} port 50001:11: Accepted password for root from 198.51.100.2 port 22 ssh2", T0, fromJournal: true);

        Assert.Equal(new[] { (Ip, "alice") }, seen);
    }
}

public class SshOperatorShieldTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), "ns-ssh-" + Guid.NewGuid().ToString("N"));

    /// <summary>One glibc 64-bit utmp record (384 bytes).</summary>
    private static byte[] UtmpRecord(short type, string host = "", byte[]? addr = null, string user = "alice")
    {
        var record = new byte[384];
        BitConverter.GetBytes(type).CopyTo(record, 0);
        System.Text.Encoding.ASCII.GetBytes(user).CopyTo(record, 44);
        System.Text.Encoding.ASCII.GetBytes(host).CopyTo(record, 76);
        addr?.CopyTo(record, 348);
        return record;
    }

    [Fact]
    public void LiveSessionsAreReadFromUtmp()
    {
        var data = new[]
        {
            UtmpRecord(7, "203.0.113.7", new byte[] { 203, 0, 113, 7 }),
            UtmpRecord(7, "", System.Net.IPAddress.Parse("2001:db8::7").GetAddressBytes(), "bob"),
            // Address only in ut_host: what libutempter's setgid-utmp helper writes for any
            // local user who asks, with any host they like. sshd always fills ut_addr_v6.
            UtmpRecord(7, "198.51.100.9", user: "mallory"),
            UtmpRecord(6, "198.51.100.10", new byte[] { 198, 51, 100, 10 }), // LOGIN_PROCESS: not logged in
            UtmpRecord(7, "198.51.100.11", new byte[] { 198, 51, 100, 11 }, user: ""), // no account
            UtmpRecord(7, ":0"),                                             // local X session
        }.SelectMany(r => r).ToArray();

        Assert.Equal(new[] { ("203.0.113.7", "alice"), ("2001:db8::7", "bob") }, SshOperatorShield.ParseUtmp(data));
        // Not a whole number of records: some other layout, so nothing is guessed at.
        Assert.Empty(SshOperatorShield.ParseUtmp(data[..^1]));
    }

    [Fact]
    public void ALoggedInClientIsShieldedForItsOwnAccount()
    {
        var utmp = TempPath();
        File.WriteAllBytes(utmp, UtmpRecord(7, "203.0.113.7", new byte[] { 203, 0, 113, 7 }));
        try
        {
            var shield = new SshOperatorShield(TempPath(), utmp);
            Assert.True(shield.IsShielded("203.0.113.7"));
            Assert.True(shield.IsShielded("::ffff:203.0.113.7"));
            Assert.False(shield.IsShielded("203.0.113.8"));

            // A failed-logon burst is held back only if every account it tried logged in here.
            Assert.True(shield.IsShielded("203.0.113.7", new[] { "alice" }));
            Assert.False(shield.IsShielded("203.0.113.7", new[] { "root" }));
            Assert.False(shield.IsShielded("203.0.113.7", new[] { "alice", "root" }));
            Assert.False(shield.IsShielded("203.0.113.7", new[] { "alice", "" })); // an unnamed attempt
            Assert.False(shield.IsShielded("203.0.113.7", Array.Empty<string>()));
        }
        finally
        {
            File.Delete(utmp);
        }
    }

    [Fact]
    public void AForgedUtmpHostShieldsNothing()
    {
        var utmp = TempPath();
        File.WriteAllBytes(utmp, UtmpRecord(7, "203.0.113.7", user: "mallory"));
        try
        {
            var shield = new SshOperatorShield(TempPath(), utmp);
            Assert.False(shield.IsShielded("203.0.113.7"));
            Assert.False(shield.IsShielded("203.0.113.7", new[] { "mallory" }));
        }
        finally
        {
            File.Delete(utmp);
        }
    }

    [Fact]
    public void RecentLoginsAreRememberedAcrossRestartsAndThenForgotten()
    {
        var store = TempPath();
        try
        {
            // Near the real clock: loading prunes with it, before a test clock can be set.
            var now = DateTime.UtcNow;
            var shield = new SshOperatorShield(store, "/nonexistent") { UtcNow = () => now };
            shield.RecordLogin("203.0.113.7", "alice");
            shield.RecordLogin("192.168.1.20", "alice"); // private: never auto-blocked anyway, not stored
            shield.RecordLogin("203.0.113.9", "");       // no account: vouches for nothing

            var restarted = new SshOperatorShield(store, "/nonexistent") { UtcNow = () => now.AddDays(29) };
            Assert.True(restarted.IsShielded("203.0.113.7"));
            Assert.True(restarted.IsShielded("203.0.113.7", new[] { "alice" }));
            Assert.False(restarted.IsShielded("203.0.113.7", new[] { "root" }));
            Assert.False(restarted.IsShielded("203.0.113.9"));
            Assert.DoesNotContain("192.168.1.20", File.ReadAllText(store));

            restarted.UtcNow = () => now.AddDays(31);
            Assert.False(restarted.IsShielded("203.0.113.7"));

            if (!OperatingSystem.IsWindows())
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(store));
        }
        finally
        {
            File.Delete(store);
        }
    }

    [Fact]
    public void AFileFromBeforeAccountsWereRecordedIsDropped()
    {
        var store = TempPath();
        File.WriteAllText(store, $"{{\"203.0.113.7\":\"{DateTime.UtcNow:O}\"}}");
        try
        {
            Assert.False(new SshOperatorShield(store, "/nonexistent").IsShielded("203.0.113.7"));
        }
        finally
        {
            File.Delete(store);
        }
    }

    private static PreventionService DryRunPrevention(SshOperatorShield shield) =>
        new(new FirewallService(), new AllowlistService(), new AppSettings())
        {
            Enabled = true,
            // Dry run: every gate runs, but no test may write a kernel firewall rule.
            DryRun = true,
            IsSshOperator = shield.IsShielded
        };

    private static ThreatEvent Burst(string ip, params string[] accounts) => new()
    {
        SourceIp = ip, Level = ThreatLevel.High, Type = ThreatType.FailedLogonBurst,
        Title = "4 failed logons in 10 min", AccountsTried = accounts
    };

    [Fact]
    public void AutoBlockHoldsBackAnSshOperatorAndSaysWhy()
    {
        var store = TempPath();
        try
        {
            var shield = new SshOperatorShield(store, "/nonexistent");
            shield.RecordLogin("203.0.113.7", "alice");
            var prevention = DryRunPrevention(shield);

            var threats = new[] { Burst("203.0.113.7", "alice"), Burst("203.0.113.8", "alice") };
            var result = prevention.Apply(threats);

            var held = Assert.Single(result.Decisions, d => d.Action == PreventionAction.Skipped);
            Assert.Equal("203.0.113.7", held.Ip);
            Assert.Contains("logged in over SSH", held.Message);
            Assert.Contains(result.Decisions, d => d.Ip == "203.0.113.8" && d.Action == PreventionAction.Simulated);
            Assert.Contains("SSH", prevention.DescribeEnforcement(threats[0])!.Text);
        }
        finally
        {
            File.Delete(store);
        }
    }

    [Fact]
    public void AnOperatorsAddressGuessingAnotherAccountIsStillBlocked()
    {
        // A login as alice does not excuse guesses at root from the same address — that is
        // anyone with an account here trying to become root, not the operator's typos.
        var store = TempPath();
        try
        {
            var shield = new SshOperatorShield(store, "/nonexistent");
            shield.RecordLogin("203.0.113.7", "alice");
            var prevention = DryRunPrevention(shield);

            var guessing = Burst("203.0.113.7", "alice", "root");
            var result = prevention.Apply(new[] { guessing });
            Assert.Contains(result.Decisions, d => d.Ip == "203.0.113.7" && d.Action == PreventionAction.Simulated);
            Assert.DoesNotContain("SSH", prevention.DescribeEnforcement(guessing)!.Text);

            // Any other kind of threat from the operator's address is still held back.
            var scan = new ThreatEvent
            {
                SourceIp = "203.0.113.7", Level = ThreatLevel.High, Type = ThreatType.PortScan, Title = "Port scan"
            };
            Assert.Contains("SSH", prevention.DescribeEnforcement(scan)!.Text);
        }
        finally
        {
            File.Delete(store);
        }
    }
}
